// Records how Xray-core v26.10.31's XDRIVE transport names and moves a
// session's objects: paramsFromConfig, objectName, parseEntry, announceName,
// the local storage's resolve, and step-by-step replays of its segment
// writer and reader. The writer and reader run without their goroutines'
// timers: a "tick" is one pass of flushLoop's body and a poll one call of
// walReader.poll, so every run is the same and a fresh one matches
// tests/fixtures/xdrive/wal-vectors.json byte for byte.
//
// It runs inside the package, added without touching the checkout:
//
//	go -C <pinned checkout> test -overlay overlay.json \
//	    ./transport/internet/xdrive -run TestXrayRustOracle
//
// where overlay.json maps transport/internet/xdrive/xray_rust_oracle_test.go
// to this file, and XDRIVE_ORACLE_OUT names the output file.
package xdrive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type xrayRustParams struct {
	Input  [8]uint32 `json:"input"`
	Output struct {
		SegmentBytes      int   `json:"segmentBytes"`
		FlushIntervalNs   int64 `json:"flushIntervalNs"`
		MinPollIntervalNs int64 `json:"minPollIntervalNs"`
		MaxPollIntervalNs int64 `json:"maxPollIntervalNs"`
		EagerWindowNs     int64 `json:"eagerWindowNs"`
		HoleTimeoutNs     int64 `json:"holeTimeoutNs"`
		SessionTTLNs      int64 `json:"sessionTtlNs"`
		Concurrency       int   `json:"concurrency"`
	} `json:"output"`
}

type xrayRustObjectName struct {
	Prefix string `json:"prefix"`
	Seq    int64  `json:"seq"`
	Suffix string `json:"suffix"`
	Name   string `json:"name"`
}

type xrayRustEntry struct {
	Name string `json:"name"`
	Seq  int64  `json:"seq"`
	OK   bool   `json:"ok"`
}

type xrayRustAnnounce struct {
	Session string `json:"session"`
	Nanos   int64  `json:"nanos"`
	Name    string `json:"name"`
}

type xrayRustResolve struct {
	Name string `json:"name"`
	// Path: what resolve gives, relative to the root, when it takes the name.
	Path  string `json:"path,omitempty"`
	Error string `json:"error,omitempty"`
}

type xrayRustObject struct {
	Name   string `json:"name"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

type xrayRustWriterCase struct {
	Name         string   `json:"name"`
	SegmentBytes uint32   `json:"segmentBytes"`
	Concurrency  uint32   `json:"concurrency"`
	Ops          []string `json:"ops"`
	// Refuse: names whose Put fails.
	Refuse []string `json:"refuse,omitempty"`
	// WriteErrors: the ops whose Write returned an error, with its text.
	WriteErrors map[string]string `json:"writeErrors,omitempty"`
	CloseError  string            `json:"closeError,omitempty"`
	Objects     []xrayRustObject  `json:"objects"`
}

type xrayRustListed struct {
	Name string `json:"name"`
	// Data: what Get returns; absent means errNotFound.
	Data *string `json:"data,omitempty"`
	// Inline: the bytes the listing carries.
	Inline *string `json:"inline,omitempty"`
	// Fail: Get fails with this error instead.
	Fail string `json:"fail,omitempty"`
}

type xrayRustReaderStep struct {
	Listing   []xrayRustListed `json:"listing"`
	Advanced  bool             `json:"advanced"`
	EOF       bool             `json:"eof"`
	Error     string           `json:"error,omitempty"`
	Chunks    []string         `json:"chunks"`
	Discarded []string         `json:"discarded"`
	Seq       int64            `json:"seq"`
}

type xrayRustReaderCase struct {
	Name        string `json:"name"`
	Concurrency uint32 `json:"concurrency"`
	// HoleTimeout: "zero", which fails on the second poll that sees a
	// hole, or "long", which never does.
	HoleTimeout string               `json:"holeTimeout"`
	Steps       []xrayRustReaderStep `json:"steps"`
}

type xrayRustVectors struct {
	Params   []xrayRustParams     `json:"params"`
	Objects  []xrayRustObjectName `json:"objectNames"`
	Entries  []xrayRustEntry      `json:"entries"`
	Announce []xrayRustAnnounce   `json:"announce"`
	Resolve  []xrayRustResolve    `json:"resolve"`
	Writers  []xrayRustWriterCase `json:"writers"`
	Readers  []xrayRustReaderCase `json:"readers"`
}

// xrayRustPayload is byte k of a writer case's stream.
func xrayRustPayload(from, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(((from+i)*131 + 7) % 256)
	}
	return b
}

// xrayRustStore is a storage in memory that refuses the names it is told to.
type xrayRustStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	refuse  map[string]bool
	listing []Entry
	data    map[string][]byte
	fail    map[string]string
}

func (s *xrayRustStore) Put(ctx context.Context, name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refuse[name] {
		return stderrors.New("refused")
	}
	s.objects[name] = append([]byte(nil), data...)
	return nil
}

func (s *xrayRustStore) Get(ctx context.Context, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if message, ok := s.fail[name]; ok {
		return nil, stderrors.New(message)
	}
	data, ok := s.data[name]
	if !ok {
		return nil, errNotFound
	}
	return data, nil
}

func (s *xrayRustStore) Delete(ctx context.Context, name string) error { return nil }

func (s *xrayRustStore) List(ctx context.Context, prefix string) ([]Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Entry(nil), s.listing...), nil
}

func (s *xrayRustStore) Close() error { return nil }

func xrayRustRunWriter(c xrayRustWriterCase) xrayRustWriterCase {
	store := &xrayRustStore{objects: make(map[string][]byte), refuse: make(map[string]bool)}
	for _, name := range c.Refuse {
		store.refuse[name] = true
	}
	p := paramsFromConfig(&Config{SegmentBytes: c.SegmentBytes, Concurrency: c.Concurrency})
	w := &walWriter{
		ctx:     context.Background(),
		storage: store,
		prefix:  "up",
		params:  p,
		sem:     make(chan struct{}, p.concurrency),
	}
	written := 0
	for i, op := range c.Ops {
		switch {
		case strings.HasPrefix(op, "w"):
			n, _ := strconv.Atoi(op[1:])
			if _, err := w.Write(xrayRustPayload(written, n)); err != nil {
				if c.WriteErrors == nil {
					c.WriteErrors = make(map[string]string)
				}
				c.WriteErrors[strconv.Itoa(i)] = err.Error()
			} else {
				written += n
			}
		case op == "t":
			// One pass of flushLoop's body.
			w.mu.Lock()
			if !w.closed && w.err == nil && len(w.buf) > 0 && w.readyToFlush() {
				w.flushLocked()
			}
			w.mu.Unlock()
		case op == "c":
			if err := w.Close(); err != nil {
				c.CloseError = err.Error()
			}
		default:
			panic("unknown op " + op)
		}
		w.wg.Wait()
	}
	names := make([]string, 0, len(store.objects))
	for name := range store.objects {
		names = append(names, name)
	}
	sort.Strings(names)
	c.Objects = []xrayRustObject{}
	for _, name := range names {
		sum := sha256.Sum256(store.objects[name])
		c.Objects = append(c.Objects, xrayRustObject{Name: name, Size: len(store.objects[name]), SHA256: hex.EncodeToString(sum[:])})
	}
	return c
}

func xrayRustRunReader(c xrayRustReaderCase) xrayRustReaderCase {
	store := &xrayRustStore{data: make(map[string][]byte), fail: make(map[string]string)}
	p := paramsFromConfig(&Config{Concurrency: c.Concurrency})
	switch c.HoleTimeout {
	case "zero":
		p.holeTimeout = 0
	case "long":
		p.holeTimeout = time.Hour
	default:
		panic("unknown hole timeout " + c.HoleTimeout)
	}
	r := &walReader{
		ctx:      context.Background(),
		storage:  store,
		prefix:   "down",
		params:   p,
		ch:       make(chan []byte, 1024),
		discards: make(chan string, 4*p.concurrency),
		wake:     make(chan struct{}, 1),
	}
	for i, step := range c.Steps {
		store.mu.Lock()
		store.listing = nil
		store.data = make(map[string][]byte)
		store.fail = make(map[string]string)
		for _, listed := range step.Listing {
			entry := Entry{Name: listed.Name}
			if listed.Inline != nil {
				entry.Inline = []byte(*listed.Inline)
			}
			store.listing = append(store.listing, entry)
			if listed.Data != nil {
				store.data["down/"+listed.Name] = []byte(*listed.Data)
			}
			if listed.Fail != "" {
				store.fail["down/"+listed.Name] = listed.Fail
			}
		}
		store.mu.Unlock()
		advanced, eof, err := r.poll()
		step.Advanced, step.EOF = advanced, eof
		if err != nil {
			step.Error = err.Error()
		}
		step.Chunks = []string{}
		for len(r.ch) > 0 {
			step.Chunks = append(step.Chunks, string(<-r.ch))
		}
		step.Discarded = []string{}
		for len(r.discards) > 0 {
			step.Discarded = append(step.Discarded, <-r.discards)
		}
		step.Seq = r.seq
		c.Steps[i] = step
	}
	return c
}

func xrayRustString(s string) *string { return &s }

func xrayRustListing(names ...string) []xrayRustListed {
	listing := make([]xrayRustListed, 0, len(names))
	for _, name := range names {
		listing = append(listing, xrayRustListed{Name: name, Data: xrayRustString("data of " + name)})
	}
	return listing
}

func TestXrayRustOracle(t *testing.T) {
	out := os.Getenv("XDRIVE_ORACLE_OUT")
	if out == "" {
		t.Skip("XDRIVE_ORACLE_OUT is not set")
	}
	var v xrayRustVectors

	for _, input := range [][8]uint32{
		{},
		{1, 1, 1, 1, 1, 1, 1, 1},
		{524288, 20, 50, 500, 300, 8, 2000, 30000},
		{16 << 20, 0, 0, 0, 0, 64, 0, 0},
		{16<<20 + 1, 0, 0, 0, 0, 65, 0, 0},
		{4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295, 4294967295},
		{0, 0, 300, 100, 0, 0, 0, 0},
		{0, 0, 0, 10, 0, 0, 0, 0},
		{0, 0, 60, 0, 0, 0, 0, 0},
		{0, 0, 600, 0, 0, 0, 0, 0},
		{4096, 5, 5, 50, 30, 2, 100, 200},
	} {
		c := &Config{SegmentBytes: input[0], FlushIntervalMs: input[1], PollIntervalMs: input[2],
			MaxPollIntervalMs: input[3], SessionTtlSeconds: input[4], Concurrency: input[5],
			EagerWindowMs: input[6], HoleTimeoutMs: input[7]}
		p := paramsFromConfig(c)
		var entry xrayRustParams
		entry.Input = input
		entry.Output.SegmentBytes = p.segmentBytes
		entry.Output.FlushIntervalNs = int64(p.flushInterval)
		entry.Output.MinPollIntervalNs = int64(p.minPollInterval)
		entry.Output.MaxPollIntervalNs = int64(p.maxPollInterval)
		entry.Output.EagerWindowNs = int64(p.eagerWindow)
		entry.Output.HoleTimeoutNs = int64(p.holeTimeout)
		entry.Output.SessionTTLNs = int64(p.sessionTTL)
		entry.Output.Concurrency = p.concurrency
		v.Params = append(v.Params, entry)
	}

	for _, c := range []struct {
		prefix string
		seq    int64
		suffix string
	}{
		{"streams/ab/c2s", 0, segSuffix}, {"streams/ab/c2s", 7, endSuffix}, {"p", 42, errSuffix},
		{"p", 999999999, segSuffix}, {"p", 1000000000, segSuffix}, {"p", 9223372036854775807, endSuffix},
		{"", 1, segSuffix}, {"a/b/c", 123456, errSuffix},
	} {
		v.Objects = append(v.Objects, xrayRustObjectName{c.prefix, c.seq, c.suffix, objectName(c.prefix, c.seq, c.suffix)})
	}

	for _, name := range []string{
		"000000000.seg", "000000007.end", "000000003.err", "12.seg", "+5.seg", "-0.seg", "-1.seg",
		"9223372036854775807.seg", "9223372036854775808.seg", "1.tmp", "seg", ".seg", "+.seg", "-.end",
		"1_000.seg", " 1.seg", "1 .seg", "0x1.seg", "1.seg.bak", "1.2.seg", "a.b.seg", "", ".", "..seg",
		"00000000000000000000001.seg", "1.SEG", "1.Seg", "١.seg", "1e3.seg", "+0.err", "--1.seg",
		"000000001.end.err", "999999999999999999999.end",
	} {
		seq, ok := parseEntry(name)
		v.Entries = append(v.Entries, xrayRustEntry{Name: name, Seq: seq, OK: ok})
	}

	for _, c := range []struct {
		session string
		nanos   int64
	}{
		{"0123456789abcdef0123456789abcdef", 1794200836551728000},
		{"0123456789abcdef0123456789abcdef", 0},
		{"ffffffffffffffffffffffffffffffff", 1},
		{"00000000000000000000000000000000", -5},
		{"abc", 9223372036854775807},
	} {
		v.Announce = append(v.Announce, xrayRustAnnounce{c.session, c.nanos, announceName(c.session, time.Unix(0, c.nanos))})
	}

	root := t.TempDir()
	local, err := newLocalStorage(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"sessions/1-ab", "streams/ab/c2s/000000000.seg", "a//b/./c/", "../../etc/passwd", "a/../../b",
		"", "/", ".", "a/..", "./a", "a/.xdrive-tmp-1", ".xdrive-tmp-x", "a/.xdrive-tmp", "a/.xdrive-tmp-",
		"a/x.xdrive-tmp-1", ".xdrive-tmp-1/a", "streams", "a/b/../c", "a\\b", " a / b ", "...", "a/...",
	} {
		entry := xrayRustResolve{Name: name}
		full, err := local.resolve(name)
		if err != nil {
			entry.Error = err.Error()
		} else {
			rel := strings.TrimPrefix(full, root)
			entry.Path = strings.TrimPrefix(rel, string(os.PathSeparator))
		}
		v.Resolve = append(v.Resolve, entry)
	}

	for _, c := range []xrayRustWriterCase{
		{Name: "one small write, then close", SegmentBytes: 16, Ops: []string{"w5", "c"}},
		{Name: "a write that fills segments", SegmentBytes: 16, Ops: []string{"w40", "c"}},
		{Name: "exactly one segment", SegmentBytes: 16, Ops: []string{"w16", "c"}},
		{Name: "a tick after growth holds", SegmentBytes: 64, Ops: []string{"w5", "t", "c"}},
		{Name: "a quiet tick flushes", SegmentBytes: 64, Ops: []string{"w5", "t", "t", "c"}},
		{Name: "growth is held for eight ticks", SegmentBytes: 1024, Ops: []string{
			"w1", "t", "w1", "t", "w1", "t", "w1", "t", "w1", "t", "w1", "t", "w1", "t", "w1", "t", "w1", "t", "w1", "t", "c"}},
		{Name: "held ticks reset after a flush", SegmentBytes: 1024, Ops: []string{
			"w3", "t", "t", "w4", "t", "w4", "t", "t", "c"}},
		{Name: "ticks with nothing written", SegmentBytes: 16, Ops: []string{"t", "t", "w2", "t", "t", "t", "c"}},
		{Name: "close with nothing written", SegmentBytes: 16, Ops: []string{"c"}},
		{Name: "a second close changes nothing", SegmentBytes: 16, Ops: []string{"w3", "c", "c"}},
		{Name: "a write after close", SegmentBytes: 16, Ops: []string{"w3", "c", "w3"}},
		{Name: "default segment size", Ops: []string{"w1000", "t", "t", "w600000", "c"}},
		{Name: "large write over small segments", SegmentBytes: 7, Concurrency: 2, Ops: []string{"w100", "t", "w3", "c"}},
		{Name: "a refused segment fails the writer", SegmentBytes: 16, Refuse: []string{"up/000000001.seg"},
			Ops: []string{"w16", "w16", "w16", "t", "w5", "c"}},
		{Name: "a refused tail fails the close", SegmentBytes: 16, Refuse: []string{"up/000000000.seg"},
			Ops: []string{"w5", "c"}},
		{Name: "a refused end mark", SegmentBytes: 16, Refuse: []string{"up/000000001.end"},
			Ops: []string{"w5", "c"}},
		{Name: "segment one byte", SegmentBytes: 1, Ops: []string{"w4", "t", "w1", "c"}},
	} {
		v.Writers = append(v.Writers, xrayRustRunWriter(c))
	}

	inline := xrayRustListed{Name: "000000000.seg", Inline: xrayRustString("carried by the listing")}
	missing := xrayRustListed{Name: "000000001.seg"}
	failing := xrayRustListed{Name: "000000001.seg", Fail: "storage exploded"}
	for _, c := range []xrayRustReaderCase{
		{Name: "segments in order, then the end", Concurrency: 2, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000000.seg")},
			{Listing: xrayRustListing("000000001.seg", "000000002.seg", "000000003.seg")},
			{Listing: xrayRustListing("000000004.end")},
		}},
		{Name: "an empty listing", Concurrency: 8, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: nil}, {Listing: xrayRustListing("000000000.seg", "000000001.end")},
		}},
		{Name: "an end at the head of a batch", Concurrency: 4, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000000.seg", "000000001.seg", "000000002.end", "000000003.seg")},
		}},
		{Name: "a hole fails on the next poll", Concurrency: 8, HoleTimeout: "zero", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000001.seg")}, {Listing: xrayRustListing("000000001.seg")},
		}},
		{Name: "a hole that fills in time", Concurrency: 8, HoleTimeout: "zero", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000001.seg")}, {Listing: xrayRustListing("000000000.seg", "000000001.seg")},
			{Listing: xrayRustListing("000000003.seg")}, {Listing: xrayRustListing("000000002.seg")},
		}},
		{Name: "a hole that never times out", Concurrency: 8, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000002.seg")}, {Listing: xrayRustListing("000000002.seg")},
			{Listing: xrayRustListing("000000002.seg")},
		}},
		{Name: "only an end mark ahead is a hole too", Concurrency: 8, HoleTimeout: "zero", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000003.end")}, {Listing: xrayRustListing("000000003.end")},
		}},
		{Name: "a failure marker after a segment", Concurrency: 8, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000000.seg", "000000001.err", "000000002.seg")},
		}},
		{Name: "a failure marker ahead of the head", Concurrency: 8, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000000.seg", "000000002.err")},
			{Listing: xrayRustListing("000000001.seg", "000000002.err")},
		}},
		{Name: "a listed segment not there yet", Concurrency: 8, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: append(xrayRustListing("000000000.seg"), missing)},
			{Listing: xrayRustListing("000000001.seg")},
		}},
		{Name: "a failing get", Concurrency: 8, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: append(xrayRustListing("000000000.seg"), failing)},
		}},
		{Name: "an inline payload", Concurrency: 8, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: []xrayRustListed{inline, {Name: "000000001.end"}}},
		}},
		{Name: "names that are not entries", Concurrency: 8, HoleTimeout: "zero", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("x", "1.tmp", ".xdrive-tmp-5", "000000000.seg", "-1.seg", "1.2.seg")},
			{Listing: xrayRustListing("+1.seg", "000000002.end")},
		}},
		{Name: "duplicate numbers keep the last listed", Concurrency: 8, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: []xrayRustListed{
				{Name: "000000000.seg", Data: xrayRustString("first spelling")},
				{Name: "0.seg", Data: xrayRustString("second spelling")},
			}},
			{Listing: []xrayRustListed{
				{Name: "1.end"}, {Name: "000000001.seg", Data: xrayRustString("a segment after an end")},
			}},
		}},
		{Name: "more segments than the discard queue holds", Concurrency: 1, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000000.seg", "000000001.seg", "000000002.seg", "000000003.seg",
				"000000004.seg", "000000005.seg", "000000006.seg")},
		}},
		{Name: "entries behind the head are no hole", Concurrency: 8, HoleTimeout: "zero", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000000.seg", "000000001.seg")},
			{Listing: xrayRustListing("000000000.seg", "000000001.seg")},
			{Listing: xrayRustListing("000000001.seg")},
			{Listing: xrayRustListing("000000002.seg")},
		}},
		{Name: "names that are no entries are no hole", Concurrency: 8, HoleTimeout: "zero", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("x", "1.tmp")}, {Listing: xrayRustListing("x", "1.tmp")},
			{Listing: xrayRustListing("000000000.seg")},
		}},
		{Name: "batches of concurrency", Concurrency: 3, HoleTimeout: "long", Steps: []xrayRustReaderStep{
			{Listing: xrayRustListing("000000000.seg", "000000001.seg", "000000002.seg", "000000003.seg",
				"000000004.seg", "000000006.seg")},
			{Listing: xrayRustListing("000000005.seg", "000000006.seg", "000000007.err")},
		}},
	} {
		v.Readers = append(v.Readers, xrayRustRunReader(c))
	}

	data, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintln(os.Stderr, "wrote", out)
}

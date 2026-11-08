// Records what Xray-core's sudoku mask puts on the wire: classic datagrams
// from its UDP conn and the packed bytes its TCP server writes. The encoding
// draws clue sets, orders and padding at random, so every run differs; a
// decoder with the same tables reads them all.
// Run with go -C <pinned checkout> run -mod=readonly <this file> out.json.
package main

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/transport/internet/finalmask/sudoku"
)

type recorder struct {
	mu   sync.Mutex
	sent [][]byte
}

func (r *recorder) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }
func (r *recorder) WriteTo(b []byte, _ net.Addr) (int, error) {
	r.mu.Lock()
	r.sent = append(r.sent, append([]byte(nil), b...))
	r.mu.Unlock()
	return len(b), nil
}
func (r *recorder) Close() error                     { return nil }
func (r *recorder) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (r *recorder) SetDeadline(time.Time) error      { return nil }
func (r *recorder) SetReadDeadline(time.Time) error  { return nil }
func (r *recorder) SetWriteDeadline(time.Time) error { return nil }

type exchange struct {
	Plain string `json:"plain"`
	Wire  string `json:"wire"`
}

type packed struct {
	Writes []string `json:"writes"`
	Wire   string   `json:"wire"`
}

type result struct {
	Name    string          `json:"name"`
	Config  json.RawMessage `json:"config"`
	Classic []exchange      `json:"classic"`
	Packed  packed          `json:"packed"`
}

func run(name string, raw string, config *sudoku.Config) result {
	every := make([]byte, 256)
	for i := range every {
		every[i] = byte(i)
	}
	plains := [][]byte{every, every, every, every, []byte("hello sudoku")}
	rec := &recorder{}
	udp, err := config.WrapPacketConnClient(rec, nil, nil)
	if err != nil {
		panic(err)
	}
	var classic []exchange
	for _, plain := range plains {
		if _, err := udp.WriteTo(plain, &net.UDPAddr{}); err != nil {
			panic(err)
		}
		classic = append(classic, exchange{hex.EncodeToString(plain), hex.EncodeToString(rec.sent[len(rec.sent)-1])})
	}

	// The server's writes, read off the other end of a pipe.
	server, client := net.Pipe()
	wrapped, err := config.WrapConnServer(server)
	if err != nil {
		panic(err)
	}
	writes := [][]byte{[]byte("a"), []byte("bc"), []byte("def"), every}
	done := make(chan []byte)
	go func() {
		wire, _ := io.ReadAll(client)
		done <- wire
	}()
	var hexWrites []string
	for _, write := range writes {
		if _, err := wrapped.Write(write); err != nil {
			panic(err)
		}
		hexWrites = append(hexWrites, hex.EncodeToString(write))
	}
	_ = server.Close()
	wire := <-done
	return result{name, json.RawMessage(raw), classic, packed{hexWrites, hex.EncodeToString(wire)}}
}

func main() {
	cases := []struct {
		name, raw string
		config    *sudoku.Config
	}{
		{"entropy", `{"password":"synthetic"}`, &sudoku.Config{Password: "synthetic"}},
		{"empty-password", `{}`, &sudoku.Config{}},
		{"ascii", `{"password":"p@ss","ascii":"prefer_ascii"}`, &sudoku.Config{Password: "p@ss", Ascii: "prefer_ascii"}},
		{"custom", `{"password":"x","customTable":"xppvvvvx"}`, &sudoku.Config{Password: "x", CustomTable: "xppvvvvx"}},
		{"custom-tables", `{"password":"multi","customTables":["xppvvvvx","vvxpvxpv",""]}`, &sudoku.Config{Password: "multi", CustomTables: []string{"xppvvvvx", "vvxpvxpv", ""}}},
		{"padding", `{"password":"synthetic","paddingMin":20,"paddingMax":80}`, &sudoku.Config{Password: "synthetic", PaddingMin: 20, PaddingMax: 80}},
	}
	var results []result
	for _, c := range cases {
		results = append(results, run(c.name, c.raw, c.config))
	}
	encoded, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[1], append(encoded, '\n'), 0600); err != nil {
		panic(err)
	}
}

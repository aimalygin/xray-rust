// Records how Xray-core's xdns mask reads its domains, encodes a client's
// queries, answers them as its server does and how its client reads an
// answer back, mutated answers included. Randomness is seeded, so a fresh
// run matches tests/fixtures/xdns/vectors.json byte for byte.
// Run with go -C <pinned checkout> run -mod=readonly <this file> out.json
// [full]; full writes the larger corpus scripts/check-xdns-interop.sh reads.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"slices"
	"strings"

	"github.com/xtls/xray-core/transport/internet/finalmask/xdns"
	"golang.org/x/net/dns/dnsmessage"
)

type domainCase struct {
	Name       string `json:"name"`
	LenLimit   int    `json:"lenLimit"`
	LabelLimit int    `json:"labelLimit"`
	Edns0      int    `json:"edns0"`
	Error      string `json:"error,omitempty"`
	// What fmt.Sprint prints for the domain: its name and capacity.
	Show string `json:"show,omitempty"`
	// Whether a query for it packs; Xray's client panics when it does not.
	Packs bool `json:"packs"`
}

type nameCase struct {
	Name    string `json:"name"`
	Decoded string `json:"decoded"`
}

type encodeCase struct {
	Domain     string `json:"domain"`
	LenLimit   int    `json:"lenLimit"`
	LabelLimit int    `json:"labelLimit"`
	Data       string `json:"data"`
	Name       string `json:"name"`
}

type queryCase struct {
	Domain     string `json:"domain"`
	LenLimit   int    `json:"lenLimit"`
	LabelLimit int    `json:"labelLimit"`
	Type       uint16 `json:"type"`
	Edns0      uint16 `json:"edns0"`
	ID         uint16 `json:"id"`
	// The bytes the name carries: the client's id, the padding length and
	// padding, and the packet.
	Data string `json:"data"`
	// The query, base64.
	Query string `json:"query"`
}

type domainSpec struct {
	Name       string `json:"name"`
	LenLimit   int    `json:"lenLimit"`
	LabelLimit int    `json:"labelLimit"`
	Edns0      uint16 `json:"edns0"`
}

type responseCase struct {
	// Which of the result's domains answered.
	Domain int `json:"domain"`
	// The query, base64.
	Query string `json:"query"`
	// The packets the server framed into its answer, which the client
	// reads back.
	Packets []string `json:"packets"`
	// The answer, base64.
	Response string `json:"response"`
}

type readCase struct {
	// The response, base64.
	Response string `json:"response"`
	// Where the client stopped: unpack, header, domain, or empty when it
	// decoded the answer.
	Stage   string   `json:"stage,omitempty"`
	Decoded string   `json:"decoded,omitempty"`
	Packets []string `json:"packets"`
}

type result struct {
	Domains   []domainCase `json:"domains"`
	Names     []nameCase   `json:"names"`
	Encodings []encodeCase `json:"encodings"`
	Queries   []queryCase  `json:"queries"`
	// The client's domains, all four types each, for responses and reads;
	// the first whose name matches an answer decodes it.
	Answering []domainSpec   `json:"answering"`
	Responses []responseCase `json:"responses"`
	Reads     []readCase     `json:"reads"`
}

var allTypes = []uint16{1, 5, 16, 28}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// packs reports whether a query whose name fills the domain's capacity
// packs, recovering from the panic Encode raises for an overlong name.
func packs(domain *xdns.Domain, capacity int) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  domain.Encode(make([]byte, capacity)),
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
		}},
	}
	_, err := msg.AppendPack(nil)
	return err == nil
}

// capacity is the domain's per-query capacity, which Show prints after the
// name.
func capacity(domain *xdns.Domain) int {
	show := domain.Show()
	var cap int
	must(fmt.Sscan(show[strings.LastIndexByte(show, ' ')+1:], &cap))
	return cap
}

func domains() []domainCase {
	type input struct {
		name                       string
		lenLimit, labelLimit, edns int
	}
	long := func(n int) string { return strings.Repeat("a", n) }
	inputs := []input{
		{"t.example.com", 255, 63, 0},
		{"t.example.com", 255, 63, 512},
		{"t.example.com", 255, 63, 4096},
		{"t.example.com", 255, 63, 511},
		{"t.example.com", 255, 63, 4097},
		{"t.example.com", 255, 1, 0},
		{"t.example.com", 255, 10, 0},
		{"t.example.com", 255, 64, 0},
		{"t.example.com", 255, 0, 0},
		{"t.example.com", 256, 63, 0},
		{"t.example.com", -1, 63, 0},
		{"t.example.com", 100, 63, 0},
		{"t.example.com", 50, 63, 0},
		{"t.example.com", 45, 63, 0},
		{"t.example.com", 44, 63, 0},
		{"t.example.com", 43, 63, 0},
		{"t.example.com", 42, 20, 0},
		{"t.example.com", 15, 63, 0},
		{"t.example.com", 14, 63, 0},
		{"A.Example.COM", 255, 63, 0},
		{"a", 255, 63, 0},
		{"", 255, 63, 0},
		{".", 255, 63, 0},
		{"a.", 255, 63, 0},
		{".a", 255, 63, 0},
		{"a..b", 255, 63, 0},
		{"тест.рф", 255, 63, 0},
		{"a b.example", 255, 63, 0},
		{"_xdns.example.com", 255, 63, 0},
		{long(63) + ".com", 255, 63, 0},
		{long(64) + ".com", 255, 63, 0},
		{long(200) + ".com", 255, 63, 0},
		{long(250) + ".com", 255, 63, 0},
		{long(254), 255, 63, 0},
		{long(255), 255, 63, 0},
		{"xn--e1aybc.xn--p1ai", 255, 63, 0},
		{"xn--.example", 255, 63, 0},
		{"xn--zz9.example", 255, 63, 0},
		{"😀.example", 255, 63, 0},
		{"a\x00b.example", 255, 63, 0},
		{"ﬀ.example", 255, 63, 0},
		{"Тест.РФ", 255, 63, 0},
		{strings.Repeat("я", 40) + ".example", 255, 63, 0},
		{"-a-.example", 255, 63, 0},
		{"a\\.example", 255, 63, 0},
		{"a\uFFFDb.example", 255, 63, 0},
		{"xn--abc-.example", 255, 63, 0},
		{"xn---.example", 255, 63, 0},
		{"XN--zz9.example", 255, 63, 0},
		{"a.xn--zz9", 255, 63, 0},
		{"xn--80ak6aa92e.example", 255, 63, 0},
		{"xn--ls8h.example", 255, 63, 0},
		{"xn--a-ecp.example", 255, 63, 0},
		{"t.example.com", 255, 63, 65535},
	}
	var out []domainCase
	for _, in := range inputs {
		c := domainCase{Name: in.name, LenLimit: in.lenLimit, LabelLimit: in.labelLimit, Edns0: in.edns}
		domain, err := xdns.NewDomain(in.name, in.lenLimit, in.labelLimit, allTypes, uint16(in.edns))
		if err != nil {
			c.Error = err.Error()
		} else {
			c.Show = domain.Show()
			c.Packs = packs(domain, capacity(domain))
		}
		out = append(out, c)
	}
	return out
}

func newDomain(name string, lenLimit, labelLimit int, types []uint16, edns0 uint16) *xdns.Domain {
	return must(xdns.NewDomain(name, lenLimit, labelLimit, types, edns0))
}

// names decodes names under t.example.com.
func names() []nameCase {
	var out []nameCase
	domain := newDomain("t.example.com", 255, 63, allTypes, 0)
	inputs := []string{
		"t.example.com.",
		"x.t.example.com.",
		"xt.example.com.",
		"me.t.example.com.",
		"ME.T.EXAMPLE.COM.",
		"m.e.t.example.com.",
		"mfrg.t.example.com.",
		"mfrgg.t.example.com.",
		"mfrggz.t.example.com.",
		"mfrggzd.t.example.com.",
		"mfrggzdf.t.example.com.",
		"mfrggzdfm.t.example.com.",
		"mfrggzdfmz.t.example.com.",
		"mfrggzdfmzt.t.example.com.",
		"mfrggzdfmztw.t.example.com.",
		"m1.t.example.com.",
		"m8.t.example.com.",
		"m=.t.example.com.",
		"m-.t.example.com.",
		"m\n.e.t.example.com.",
		"m\re.t.example.com.",
		"mf.example.com.",
		"me.t.example.org.",
		"me.T.Example.Com.",
		"me.u.example.com.",
		"me7.t.example.com.",
		"me7a.t.example.com.",
		"mb.t.example.com.",
		"my.t.example.com.",
	}
	for _, input := range inputs {
		var decoded [255]byte
		n := domain.Decode(&decoded, must(dnsmessage.NewName(input)))
		out = append(out, nameCase{input, hex.EncodeToString(decoded[:n])})
	}
	return out
}

func encodings(rng *rand.Rand) []encodeCase {
	var out []encodeCase
	for _, d := range []struct {
		name                 string
		lenLimit, labelLimit int
	}{
		{"t.example.com", 255, 63},
		{"t.example.com", 255, 1},
		{"t.example.com", 100, 7},
		{"A.Example.COM", 120, 30},
		{"тест.рф", 255, 63},
	} {
		domain := newDomain(d.name, d.lenLimit, d.labelLimit, allTypes, 0)
		capacity := capacity(domain)
		for _, size := range []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 17, capacity - 1, capacity} {
			data := make([]byte, size)
			for i := range data {
				data[i] = byte(rng.IntN(256))
			}
			name := domain.Encode(data)
			out = append(out, encodeCase{d.name, d.lenLimit, d.labelLimit, hex.EncodeToString(data), name.String()})
		}
	}
	return out
}

// query packs a query as Xray's client sends it, the id written over the
// packed one as the client writes random bytes there.
func query(domain *xdns.Domain, qtype uint16, edns0 uint16, id uint16, data []byte) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  domain.Encode(data),
			Type:  dnsmessage.Type(qtype),
			Class: dnsmessage.ClassINET,
		}},
	}
	if edns0 > 0 {
		msg.Additionals = []dnsmessage.Resource{{
			Header: dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName("."),
				Type:  dnsmessage.TypeOPT,
				Class: dnsmessage.Class(edns0),
			},
			Body: &dnsmessage.OPTResource{},
		}}
	}
	pack := must(msg.AppendPack(nil))
	pack[0], pack[1] = byte(id>>8), byte(id)
	return pack
}

var typeBits = map[uint16]byte{1: 0, 5: 1, 16: 2, 28: 3}

func queries(rng *rand.Rand) []queryCase {
	var out []queryCase
	clientID := [8]byte{0xa4, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	for _, d := range []domainSpec{
		{"t.example.com", 255, 63, 0},
		{"t.example.com", 255, 63, 1232},
		{"t.example.com", 101, 20, 4096},
	} {
		domain := newDomain(d.Name, d.LenLimit, d.LabelLimit, allTypes, d.Edns0)
		capacity := capacity(domain)
		for _, qtype := range allTypes {
			id := uint16(rng.IntN(65536))
			// A poll: the id, eight bytes of padding.
			poll := append([]byte{}, clientID[:]...)
			poll[0] |= typeBits[qtype]
			poll = append(poll, 8)
			for range 8 {
				poll = append(poll, byte(rng.IntN(256)))
			}
			out = append(out, queryCase{d.Name, d.LenLimit, d.LabelLimit, qtype, d.Edns0, id, hex.EncodeToString(poll), b64(query(domain, qtype, d.Edns0, id, poll))})
			// Whole packets: three bytes of padding, then the packet.
			for _, size := range []int{1, capacity - 12} {
				data := append([]byte{}, clientID[:]...)
				data[0] |= typeBits[qtype]
				data = append(data, 3, byte(rng.IntN(256)), byte(rng.IntN(256)), byte(rng.IntN(256)))
				for range size {
					data = append(data, byte(rng.IntN(256)))
				}
				out = append(out, queryCase{d.Name, d.LenLimit, d.LabelLimit, qtype, d.Edns0, id, hex.EncodeToString(data), b64(query(domain, qtype, d.Edns0, id, data))})
			}
		}
	}
	return out
}

// responseCapacity is NewResp's capacity for a query, which Xray keeps in an
// unexported field.
func responseCapacity(domainEdns0 uint16, msg dnsmessage.Message, edns0 uint16, lenMax int, domainCap int) int {
	size := min(max(int(edns0), 512), max(int(domainEdns0), 512))
	left := size - 12 - int(msg.Questions[0].Name.Length) - 1 - 2 - 2
	if edns0 > 0 {
		left -= 1 + 2 + 2 + 4 + 2 + 0
	}
	cap := 0
	switch msg.Questions[0].Type {
	case dnsmessage.TypeA:
		n := min(left/(2+2+2+4+2+4), 255)
		cap = 4*n - n - 1
	case dnsmessage.TypeCNAME:
		n := min(left/(2+2+2+4+2+lenMax), 255)
		cap = domainCap*n - n - 1
	case dnsmessage.TypeTXT:
		left -= 2 + 2 + 2 + 4 + 2
		n := left / 255
		m := left % 255
		cap = 255*n - n
		if m > 1 {
			cap += m - 1
		}
	case dnsmessage.TypeAAAA:
		n := min(left/(2+2+2+4+2+16), 255)
		cap = 16*n - n - 1
	}
	return cap
}

// lenMax is the longest name an answer's CNAME takes, as NewDomain computes
// it; Xray keeps it unexported too.
func lenMax(name dnsmessage.Name, labelLimit, cap int) int {
	total := (cap*8 + 4) / 5
	lenMax := int(name.Length) + 1 + total + total/labelLimit
	if total%labelLimit > 0 {
		lenMax++
	}
	return lenMax
}

func frame(packets [][]byte) []byte {
	var d []byte
	for i, p := range packets {
		l := len(p)
		if i == len(packets)-1 {
			l |= 0xC000
		}
		d = append(d, byte(l>>8), byte(l))
		d = append(d, p...)
	}
	return d
}

func answeringDomains(full bool) []domainSpec {
	specs := []domainSpec{
		{"t.example.com", 255, 63, 0},
		{"t.example.com", 101, 20, 1232},
	}
	if full {
		specs = append(specs, domainSpec{"t.example.com", 255, 63, 4096})
	}
	return specs
}

func responses(rng *rand.Rand, specs []domainSpec, full bool) []responseCase {
	var out []responseCase
	clientID := [8]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80}
	queryEdns0s := []uint16{0, 1232}
	if full {
		queryEdns0s = append(queryEdns0s, 600, 4096)
	}
	for index, d := range specs {
		domain := newDomain(d.Name, d.LenLimit, d.LabelLimit, allTypes, d.Edns0)
		dcap := capacity(domain)
		name := must(dnsmessage.NewName(d.Name + "."))
		lm := lenMax(name, d.LabelLimit, dcap)
		for _, qtype := range allTypes {
			for _, queryEdns0 := range queryEdns0s {
				data := append([]byte{}, clientID[:]...)
				data[0] |= typeBits[qtype]
				data = append(data, 8, 1, 2, 3, 4, 5, 6, 7, 8)
				packed := query(domain, qtype, queryEdns0, uint16(rng.IntN(65536)), data)
				msg := dnsmessage.Message{}
				if err := msg.Unpack(packed); err != nil {
					panic(err)
				}
				// The server clamps the query's size to 512..4096.
				edns0 := queryEdns0
				if edns0 > 0 && edns0 < 512 {
					edns0 = 512
				}
				resp := xdns.NewResp(msg, domain, edns0)
				capacity := responseCapacity(d.Edns0, msg, edns0, lm, dcap)
				for _, sizes := range [][]int{{}, {1}, {5, 7}, {3, 3, 3}, {capacity - 2}, {capacity/2 - 2, capacity - capacity/2 - 2}} {
					var packets [][]byte
					fits := true
					for _, size := range sizes {
						if size <= 0 {
							fits = false
							break
						}
						p := make([]byte, size)
						for i := range p {
							p[i] = byte(rng.IntN(256))
						}
						packets = append(packets, p)
					}
					if !fits || len(frame(packets)) > capacity {
						continue
					}
					response := resp.Encode(nil, frame(packets))
					c := responseCase{Domain: index, Query: b64(packed), Response: b64(response), Packets: []string{}}
					for _, p := range packets {
						c.Packets = append(c.Packets, hex.EncodeToString(p))
					}
					// The client reads back what the server framed.
					got := read(response, specs)
					if got.Stage != "" || !slices.Equal(got.Packets, c.Packets) {
						panic(fmt.Sprintf("the client misreads %v", c))
					}
					out = append(out, c)
				}
			}
		}
	}
	return out
}

// read is Xray's xdnsClient.read without its channels: whether a response
// unpacks, passes the header and domain checks, and which packets its
// answer carries.
func read(buf []byte, specs []domainSpec) readCase {
	var domains []*xdns.Domain
	for _, d := range specs {
		domains = append(domains, newDomain(d.Name, d.LenLimit, d.LabelLimit, allTypes, d.Edns0))
	}
	c := readCase{Response: b64(buf), Packets: []string{}}
	msg := dnsmessage.Message{}
	if err := msg.Unpack(buf); err != nil {
		c.Stage = "unpack"
		return c
	}
	if !msg.Header.Response || msg.Header.Truncated || msg.Header.RCode != dnsmessage.RCodeSuccess || len(msg.Questions) != 1 {
		c.Stage = "header"
		return c
	}
	var domain *xdns.Domain
	for i := range domains {
		if domains[i].IsDomain(msg.Questions[0].Name) {
			domain = domains[i]
			break
		}
	}
	if domain == nil || !domain.HasType(uint16(msg.Questions[0].Type)) {
		c.Stage = "domain"
		return c
	}
	p := make([]byte, 4096)
	n := xdns.NewResp(msg, domain, 0).Decode(p)
	p = p[:n]
	c.Decoded = hex.EncodeToString(p)
	b := p
	var bs [][]byte
	for len(b) > 1 {
		last := b[0]&0xC0 == 0xC0
		length := int(b[0]&0x3F)<<8 | int(b[1])
		b = b[2:]
		if length > len(b) {
			bs = nil
			break
		}
		bs = append(bs, append([]byte{}, b[:length]...))
		if last {
			break
		}
		b = b[length:]
		if len(b) < 2 {
			bs = nil
		}
	}
	for _, packet := range bs {
		c.Packets = append(c.Packets, hex.EncodeToString(packet))
	}
	return c
}

// mutate changes a response the ways a path or a broken resolver might.
func mutate(rng *rand.Rand, response []byte) []byte {
	out := append([]byte{}, response...)
	switch rng.IntN(9) {
	case 0: // flip a byte
		if len(out) > 0 {
			out[rng.IntN(len(out))] ^= byte(1 + rng.IntN(255))
		}
	case 1: // truncate
		out = out[:rng.IntN(len(out)+1)]
	case 2: // overwrite a 16-bit field
		if len(out) > 1 {
			i := rng.IntN(len(out) - 1)
			v := rng.IntN(65536)
			out[i], out[i+1] = byte(v>>8), byte(v)
		}
	case 3: // append garbage
		for range 1 + rng.IntN(16) {
			out = append(out, byte(rng.IntN(256)))
		}
	case 4: // a compression pointer anywhere
		if len(out) > 1 {
			i := rng.IntN(len(out) - 1)
			v := 0xC000 | rng.IntN(len(out))
			out[i], out[i+1] = byte(v>>8), byte(v)
		}
	case 5: // the answer count
		if len(out) >= 12 {
			out[6], out[7] = 0, byte(rng.IntN(8))
		}
	case 6: // header flags
		if len(out) >= 4 {
			out[2] = byte(rng.IntN(256))
			out[3] = byte(rng.IntN(256))
		}
	case 7: // the question count
		if len(out) >= 12 {
			out[4], out[5] = 0, byte(rng.IntN(3))
		}
	case 8: // one bit past the header
		if len(out) > 12 {
			i := 12 + rng.IntN(len(out)-12)
			out[i] ^= byte(1 << rng.IntN(8))
		}
	}
	return out
}

// handmade are answers Xray's server never writes but a resolver might
// pass on.
func handmade() []dnsmessage.Message {
	question := dnsmessage.Question{Name: must(dnsmessage.NewName("me.t.example.com.")), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	txtQuestion := dnsmessage.Question{Name: question.Name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}
	header := dnsmessage.Header{Response: true}
	answerA := func(a [4]byte) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: a}}
	}
	txt := func(name dnsmessage.Name, strings ...string) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeTXT, Class: dnsmessage.ClassINET}, Body: &dnsmessage.TXTResource{TXT: strings}}
	}
	cname := func(target string) dnsmessage.Resource {
		return dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}, Body: &dnsmessage.CNAMEResource{CNAME: must(dnsmessage.NewName(target))}}
	}
	one := func(answers ...dnsmessage.Resource) dnsmessage.Message {
		return dnsmessage.Message{Header: header, Questions: []dnsmessage.Question{question}, Answers: answers}
	}
	return []dnsmessage.Message{
		// Out of order, a duplicate, a fragment count larger or smaller than
		// given, a first fragment that is not the first.
		one(answerA([4]byte{1, 0xC0, 0, 0}), answerA([4]byte{0, 2, 0xC0, 0x01})),
		one(answerA([4]byte{0, 2, 0xC0, 0x01}), answerA([4]byte{0, 2, 0xC0, 0x01})),
		one(answerA([4]byte{0, 3, 0xC0, 0x01})),
		one(answerA([4]byte{0, 1, 0xC0, 0x01}), answerA([4]byte{1, 9, 9, 9})),
		one(answerA([4]byte{2, 1, 0xC0, 0x01}), answerA([4]byte{5, 9, 9, 9})),
		// Two packets, the first not marked last.
		one(answerA([4]byte{0, 3, 0x00, 0x01}), answerA([4]byte{1, 0xAA, 0xC0, 0x01}), answerA([4]byte{2, 0xBB, 0, 0})),
		// A packet that is not marked last and nothing after it.
		one(answerA([4]byte{0, 2, 0x00, 0x01}), answerA([4]byte{1, 0xAA, 0, 0})),
		// Only one of the top bits: not the last.
		one(answerA([4]byte{0, 2, 0x80, 0x01}), answerA([4]byte{1, 0xAA, 0xC0, 0x00})),
		one(answerA([4]byte{0, 2, 0x40, 0x01}), answerA([4]byte{1, 0xAA, 0xC0, 0x00})),
		// An empty packet, marked last.
		one(answerA([4]byte{0, 1, 0xC0, 0x00})),
		// An answer for another name and of another type.
		one(
			dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName("other.example.")), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{0, 1, 0xC0, 0}}},
			dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeAAAA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AAAAResource{}},
			answerA([4]byte{0, 1, 0xC0, 0x01}),
		),
		// Truncated, an error code, no question, two questions, a query.
		{Header: dnsmessage.Header{Response: true, Truncated: true}, Questions: []dnsmessage.Question{question}, Answers: []dnsmessage.Resource{answerA([4]byte{0, 1, 0xC0, 0x01})}},
		{Header: dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeNameError}, Questions: []dnsmessage.Question{question}},
		{Header: header, Answers: []dnsmessage.Resource{answerA([4]byte{0, 1, 0xC0, 0x01})}},
		{Header: header, Questions: []dnsmessage.Question{question, question}, Answers: []dnsmessage.Resource{answerA([4]byte{0, 1, 0xC0, 0x01})}},
		{Questions: []dnsmessage.Question{question}, Answers: []dnsmessage.Resource{answerA([4]byte{0, 1, 0xC0, 0x01})}},
		// TXT: two answers, several strings with empty ones, another name.
		{Header: header, Questions: []dnsmessage.Question{txtQuestion}, Answers: []dnsmessage.Resource{txt(question.Name, "\xC0\x01x"), txt(question.Name, "\xC0\x01y")}},
		{Header: header, Questions: []dnsmessage.Question{txtQuestion}, Answers: []dnsmessage.Resource{txt(question.Name, "", "\x00", "\x01a", "\xC0", "\x01", "z")}},
		{Header: header, Questions: []dnsmessage.Question{txtQuestion}, Answers: []dnsmessage.Resource{txt(must(dnsmessage.NewName("t.example.com.")), "\xC0\x01x")}},
		{Header: header, Questions: []dnsmessage.Question{txtQuestion}, Answers: []dnsmessage.Resource{txt(question.Name)}},
		// CNAME answers pointing elsewhere, and ones that do not decode.
		{Header: header, Questions: []dnsmessage.Question{{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{
			cname("aaaq.elsewhere.example."), cname("a.t.example.com."), cname("aaaqeaib.t.example.com."),
		}},
		{Header: header, Questions: []dnsmessage.Question{{Name: question.Name, Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET}}, Answers: []dnsmessage.Resource{
			cname("aa.t.example.com."), cname("aaaqeaib.t.example.com."),
		}},
		// A question of a type the domain does not take, or outside it.
		{Header: header, Questions: []dnsmessage.Question{{Name: question.Name, Type: dnsmessage.TypeMX, Class: dnsmessage.ClassINET}}},
		{Header: header, Questions: []dnsmessage.Question{{Name: must(dnsmessage.NewName("me.example.org.")), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}},
		// Extra sections: an OPT, an authority, an unknown type, SVCB.
		{Header: header, Questions: []dnsmessage.Question{question}, Answers: []dnsmessage.Resource{answerA([4]byte{0, 1, 0xC0, 0x01})},
			Authorities: []dnsmessage.Resource{
				{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName("example.com.")), Type: dnsmessage.TypeNS, Class: dnsmessage.ClassINET}, Body: &dnsmessage.NSResource{NS: must(dnsmessage.NewName("ns.example.com."))}},
				{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName("example.com.")), Type: dnsmessage.TypeSOA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.SOAResource{NS: must(dnsmessage.NewName("ns.example.com.")), MBox: must(dnsmessage.NewName("h.example.com.")), Serial: 1, Refresh: 2, Retry: 3, Expire: 4, MinTTL: 5}},
			},
			Additionals: []dnsmessage.Resource{
				{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName(".")), Type: dnsmessage.TypeOPT, Class: 1232}, Body: &dnsmessage.OPTResource{Options: []dnsmessage.Option{{Code: 10, Data: []byte{1, 2, 3, 4, 5, 6, 7, 8}}}}},
				{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName("x.example.com.")), Type: 99, Class: dnsmessage.ClassINET}, Body: &dnsmessage.UnknownResource{Type: 99, Data: []byte{1, 2, 3}}},
				{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName("x.example.com.")), Type: dnsmessage.TypeMX, Class: dnsmessage.ClassINET}, Body: &dnsmessage.MXResource{Pref: 5, MX: must(dnsmessage.NewName("mx.example.com."))}},
				{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName("x.example.com.")), Type: dnsmessage.TypeSRV, Class: dnsmessage.ClassINET}, Body: &dnsmessage.SRVResource{Priority: 1, Weight: 2, Port: 3, Target: must(dnsmessage.NewName("srv.example.com."))}},
				{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName("x.example.com.")), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}, Body: &dnsmessage.PTRResource{PTR: must(dnsmessage.NewName("ptr.example.com."))}},
				{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName("x.example.com.")), Type: dnsmessage.TypeSVCB, Class: dnsmessage.ClassINET}, Body: &dnsmessage.SVCBResource{Priority: 1, Target: must(dnsmessage.NewName("svc.example.com.")), Params: []dnsmessage.SVCParam{{Key: 1, Value: []byte{2, 'h', '3'}}, {Key: 3, Value: []byte{1, 187}}}}},
				{Header: dnsmessage.ResourceHeader{Name: must(dnsmessage.NewName("x.example.com.")), Type: dnsmessage.TypeHTTPS, Class: dnsmessage.ClassINET}, Body: &dnsmessage.HTTPSResource{SVCBResource: dnsmessage.SVCBResource{Priority: 0, Target: must(dnsmessage.NewName("."))}}},
			}},
	}
}

// rawReads are hand-written byte strings the Go encoder would not produce.
func rawReads() [][]byte {
	base := query(newDomain("t.example.com", 255, 63, allTypes, 0), 1, 0, 0x1234, []byte{1, 2})
	answer := func(rdlength uint16, rdata ...byte) []byte {
		msg := append([]byte{}, base...)
		msg[2] |= 0x80 // response
		msg[7] = 1     // one answer
		msg = append(msg, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, byte(rdlength>>8), byte(rdlength))
		return append(msg, rdata...)
	}
	return [][]byte{
		// An A record whose length runs past the end, last in the message.
		answer(100, 0, 1, 0xC0, 0x01),
		// One whose length is shorter than four bytes.
		answer(2, 0, 1, 0xC0, 0x01),
		// A name with a dot inside a label.
		append(append([]byte{}, base[:12]...), 3, 'a', '.', 'b', 0, 0, 1, 0, 1),
		// A pointer loop.
		append(append([]byte{}, base[:12]...), 0xC0, 12, 0, 1, 0, 1),
		// A reserved label prefix.
		append(append([]byte{}, base[:12]...), 0x40, 0, 1, 0, 1),
		// TXT whose strings run past its length.
		func() []byte {
			msg := answer(3, 5, 'a', 'b', 'c', 'd', 'e')
			msg[len(base)-3] = 16 // question type TXT
			msg[len(base)+3] = 16 // answer type TXT
			return msg
		}(),
		// An OPT whose option runs past the end.
		func() []byte {
			msg := append([]byte{}, base...)
			msg[2] |= 0x80
			msg[11] = 1
			return append(msg, 0, 0, 41, 2, 0, 0, 0, 0, 0, 0, 8, 0, 10, 0, 9, 1, 2)
		}(),
		// One whose last option runs past its length into the bytes after
		// it, which Go reads.
		func() []byte {
			msg := append([]byte{}, base...)
			msg[2] |= 0x80
			msg[11] = 1
			return append(msg, 0, 0, 41, 4, 0xD0, 0, 0, 0, 0, 0, 4, 0, 10, 0, 2, 0xAA, 0xBB)
		}(),
	}
}

func reads(rng *rand.Rand, specs []domainSpec, cases []responseCase, mutations int) []readCase {
	var out []readCase
	for _, c := range cases {
		response := must(base64.StdEncoding.DecodeString(c.Response))
		for range mutations {
			mutated := mutate(rng, response)
			for range rng.IntN(3) {
				mutated = mutate(rng, mutated)
			}
			out = append(out, read(mutated, specs))
		}
	}
	for _, msg := range handmade() {
		packed := must(msg.Pack())
		out = append(out, read(packed, specs))
		for range 3 * mutations {
			out = append(out, read(mutate(rng, packed), specs))
		}
	}
	for _, raw := range rawReads() {
		out = append(out, read(raw, specs))
	}
	return out
}

func main() {
	full := len(os.Args) > 2 && os.Args[2] == "full"
	rng := rand.New(rand.NewPCG(0x78646e73, 0x6f7261636c65))
	var out result
	out.Domains = domains()
	out.Names = names()
	out.Encodings = encodings(rng)
	out.Queries = queries(rng)
	out.Answering = answeringDomains(full)
	out.Responses = responses(rng, out.Answering, full)
	mutations := 1
	if full {
		mutations = 12
	}
	out.Reads = reads(rng, out.Answering, out.Responses, mutations)
	encoded, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[1], append(encoded, '\n'), 0600); err != nil {
		panic(err)
	}
}

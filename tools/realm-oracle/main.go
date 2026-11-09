// Records what Xray-core's realm mask does with its settings and on the
// wire: Realm.Build's verdicts on URLs, STUN servers and port mappings, how
// its client reads STUN Binding responses with pion/stun, how it encodes and
// decodes punch packets, which addresses it punches, and the rendezvous
// request its HTTP client writes with the answer it takes from each
// response. Randomness is seeded and the rendezvous port is written as
// {port}, so a fresh run matches tests/fixtures/realm/vectors.json byte for
// byte.
// Run with go -C <pinned checkout> run -mod=readonly <this file> out.json
package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
	_ "unsafe"

	"github.com/pion/stun/v3"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask/realm"
)

//go:linkname candidatePunchAddrs github.com/xtls/xray-core/transport/internet/finalmask/realm.candidatePunchAddrs
func candidatePunchAddrs(locals, peers []netip.AddrPort, family realm.Family) ([]netip.AddrPort, map[netip.AddrPort]struct{})

//go:linkname expandSymmetricNATCandidates github.com/xtls/xray-core/transport/internet/finalmask/realm.expandSymmetricNATCandidates
func expandSymmetricNATCandidates(candidates []netip.AddrPort, seen map[netip.AddrPort]struct{}) []netip.AddrPort

//go:linkname parseSTUNBindingResponse github.com/xtls/xray-core/transport/internet/finalmask/realm.parseSTUNBindingResponse
func parseSTUNBindingResponse(packet []byte) (*stun.Message, netip.AddrPort, error)

//go:linkname parseAddrPorts github.com/xtls/xray-core/transport/internet/finalmask/realm.parseAddrPorts
func parseAddrPorts(addrs []string) ([]netip.AddrPort, error)

//go:linkname xorPunchPacket github.com/xtls/xray-core/transport/internet/finalmask/realm.xorPunchPacket
func xorPunchPacket(packet, obfsKey, salt []byte)

type urlCase struct {
	URL    string `json:"url"`
	Error  string `json:"error,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	Host   string `json:"host,omitempty"`
	Port   string `json:"port,omitempty"`
	Token  string `json:"token,omitempty"`
	ID     string `json:"id,omitempty"`
}

type stunServerCase struct {
	Server string `json:"server"`
	// Realm.Build's verdict.
	Error string `json:"error,omitempty"`
	// The port the client reads with strconv.Atoi, when it reads.
	Port *int `json:"port,omitempty"`
}

type settingsCase struct {
	Settings json.RawMessage `json:"settings"`
	Error    string          `json:"error,omitempty"`
	IPMode   string          `json:"ipMode,omitempty"`
	Mapping  *mapping        `json:"portMapping,omitempty"`
}

type mapping struct {
	Enabled  bool  `json:"enabled"`
	Timeout  int64 `json:"timeout"`
	Lifetime int64 `json:"lifetime"`
}

type stunCase struct {
	Name   string `json:"name"`
	Packet string `json:"packet"`
	// The transaction and the address the client takes, or neither: its
	// bytes in hex, a slash and the port, since a mutated answer reports
	// any address.
	Transaction string `json:"transaction,omitempty"`
	Mapped      string `json:"mapped,omitempty"`
}

type punchCase struct {
	Nonce  string `json:"nonce"`
	Obfs   string `json:"obfs"`
	Packet string `json:"packet"`
	// The type and padding length DecodePunchPacket reads, or 0.
	Type    int `json:"type"`
	Padding int `json:"padding"`
}

type candidateCase struct {
	Locals []string `json:"locals"`
	Peers  []string `json:"peers"`
	Family int      `json:"family"`
	// expandSymmetricNATCandidates(candidatePunchAddrs(...)), in Go's
	// order; IPv4-mapped addresses are written in hex groups.
	Punched []string `json:"punched"`
}

type addrPortsCase struct {
	Addresses []string `json:"addresses"`
	// What parseAddrPorts keeps: all of them, or none.
	Parsed []string `json:"parsed"`
}

type httpCase struct {
	Name     string `json:"name"`
	Token    string `json:"token"`
	ID       string `json:"id"`
	PortText string `json:"portText"`
	Request  string `json:"request"`
	// The response's bytes, hex.
	Response string   `json:"response"`
	Result   []string `json:"result"`
	Status   int      `json:"status,omitempty"`
	Error    bool     `json:"error,omitempty"`
}

type result struct {
	URLs        []urlCase        `json:"urls"`
	StunServers []stunServerCase `json:"stunServers"`
	Settings    []settingsCase   `json:"settings"`
	Stun        []stunCase       `json:"stun"`
	Punch       []punchCase      `json:"punch"`
	Candidates  []candidateCase  `json:"candidates"`
	AddrPorts   []addrPortsCase  `json:"addrPorts"`
	HTTP        []httpCase       `json:"http"`
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	if text := err.Error(); text != "" {
		return text
	}
	return "error"
}

func build(settings []byte) (*realm.Config, error) {
	var c conf.Realm
	if err := json.Unmarshal(settings, &c); err != nil {
		return nil, err
	}
	built, err := c.Build()
	if err != nil {
		return nil, err
	}
	return built.(*realm.Config), nil
}

func urls() []urlCase {
	corpus := []string{
		"realm://public@realm.hy2.io/my-server",
		"realm+http://tok@127.0.0.1:8080/name",
		"REALM://Tok@Host.Example/Name",
		"Realm+HTTP://tok@host/name",
		"realm://tok@host",
		"realm://tok@host/",
		"realm://tok@host//x",
		"realm://tok@host/a/b",
		"realm://tok@host/a%2Fb",
		"realm://tok@host/a%2fb%20c",
		"realm://tok@host/%zz",
		"realm://tok@host/a b",
		"realm://tok@host/a?b",
		"realm://tok@host/%E2%82%AC",
		"realm://tok@host/%FF",
		"realm://t%40k@host/x",
		"realm://user:pass@host/x",
		"realm://user:@host/x",
		"realm://:pass@host/x",
		"realm://@host/x",
		"realm://a@b@host/x",
		"realm://a%3Ab@host/x",
		"realm://t%2Fk%3F@host/x",
		"realm://t+k@host/x",
		"realm://t!$&'()*,;=~k@host/x",
		"realm://t k@host/x",
		"realm://t%zz@host/x",
		"realm://t%0A@host/x",
		"realm://t%7F@host/x",
		"realm://t%09@host/x",
		"realm://t%FF@host/x",
		"realm://t%C3%A9@host/x",
		"realm://tok@[2001:db8::1]:8443/x",
		"realm://tok@[2001:db8::1]/x",
		"realm://tok@[fe80::1%25en0]/x",
		"realm://tok@[fe80::1%25]/x",
		"realm://tok@[192.0.2.4]/x",
		"realm://tok@[::ffff:c000:204]/x",
		"realm://tok@[2001:db8::1/x",
		"realm://tok@[2001:db8::1]x/x",
		"realm://tok@x[::1]/x",
		"realm://tok@[not-ip]/x",
		"realm://tok@2001:db8::1:443/x",
		"realm://tok@::1/x",
		"realm://tok@a:b:443/x",
		"realm://tok@host:/x",
		"realm://tok@host:0/x",
		"realm://tok@host:1/x",
		"realm://tok@host:65535/x",
		"realm://tok@host:65536/x",
		"realm://tok@host:0443/x",
		"realm://tok@host:99999999999999999999/x",
		"realm://tok@host:abc/x",
		"realm://tok@host:-1/x",
		"realm://tok@:443/x",
		"realm://tok@/x",
		"realm://tok@ho st/x",
		"realm://tok@ho%41st/x",
		"realm://tok@h%C3%BCst/x",
		"realm://tok@ho_st/x",
		"realm://tok@host<x>/x",
		"realm://tok@host/x?query#frag",
		"realm://tok@host/x#%zz",
		"realm://tok@host/x?%zz",
		"realm://tok@host/x?",
		"realm:tok@host/x",
		"realm:///x",
		"realm",
		"",
		"://tok@host/x",
		"1realm://tok@host/x",
		"https://tok@host/x",
		"realm+https://tok@host/x",
		"realm://tok@host/x\t",
		"realm://tok@host/x\x7f",
		"realm://tok@host/*",
		"realm://tok@host*",
	}
	cases := make([]urlCase, 0, len(corpus))
	for _, u := range corpus {
		settings, _ := json.Marshal(map[string]any{"url": u, "stunServers": []string{"stun.example:3478"}})
		c, err := build(settings)
		if err != nil {
			cases = append(cases, urlCase{URL: u, Error: errText(err)})
			continue
		}
		cases = append(cases, urlCase{URL: u, Scheme: c.Scheme, Host: c.Host, Port: c.Port, Token: c.Token, ID: c.ID})
	}
	return cases
}

func stunServers() []stunServerCase {
	corpus := []string{
		"stun.example.com:3478",
		"192.0.2.1:3478",
		"[2001:db8::1]:3478",
		"stun.example.com",
		"stun.example.com:",
		":3478",
		"[2001:db8::1]",
		"2001:db8::1:3478",
		"a:b:c",
		"[a:b]:1:2",
		"h:0",
		"h:1",
		"h:65535",
		"h:65536",
		"h:+3478",
		"h:-1",
		"h:03478",
		"h:x",
		"h: 1",
		"h:99999999999999999999",
		"[::1]x:1",
		"]h[:1",
		"",
	}
	cases := make([]stunServerCase, 0, len(corpus))
	for _, server := range corpus {
		settings, _ := json.Marshal(map[string]any{"url": "realm://t@host/x", "stunServers": []string{server}})
		_, err := build(settings)
		c := stunServerCase{Server: server, Error: errText(err)}
		if err == nil {
			_, p, _ := net.SplitHostPort(server)
			if port, err := strconv.Atoi(p); err == nil {
				c.Port = &port
			}
		}
		cases = append(cases, c)
	}
	return cases
}

func settings() []settingsCase {
	corpus := []string{
		`{"url":"realm://t@host/x","stunServers":["s:1"],"ipMode":"V4"}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"ipMode":"v6"}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"ipMode":"DUAL"}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"ipMode":"ipv4"}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"ipMode":null}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"ipMode":4}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":{"enabled":true,"timeout":5,"lifetime":600}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":{}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":null}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":{"timeout":-5,"lifetime":-1}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":{"timeout":1.5}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":{"timeout":"5"}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":{"enabled":"true"}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":{"lifetime":9223372036854775807}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":{"lifetime":9223372036854775808}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"portMapping":true}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"tlsConfig":{"serverName":"rendezvous.example"}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"tlsConfig":{"fingerprint":"nope"}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"tlsConfig":{"allowInsecure":true}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"tlsConfig":{"pinnedPeerCertSha256":"zz"}}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"tlsConfig":null}`,
		`{"url":"realm://t@host/x","stunServers":["s:1"],"tlsConfig":5}`,
		`{"url":"realm://t@host/x","stunServers":[]}`,
		`{"url":"realm://t@host/x","stunServers":null}`,
		`{"url":"realm://t@host/x","stunServers":[null]}`,
		`{"url":"realm://t@host/x","stunServers":"s:1"}`,
		`{"url":null,"stunServers":["s:1"]}`,
		`{"url":5,"stunServers":["s:1"]}`,
		`{}`,
	}
	cases := make([]settingsCase, 0, len(corpus))
	for _, raw := range corpus {
		c := settingsCase{Settings: json.RawMessage(raw)}
		built, err := build([]byte(raw))
		if err != nil {
			c.Error = errText(err)
		} else {
			c.IPMode = built.IPMode
			if built.PortMapping != nil {
				c.Mapping = &mapping{built.PortMapping.Enabled, built.PortMapping.Timeout, built.PortMapping.Lifetime}
			}
		}
		cases = append(cases, c)
	}
	return cases
}

func stunCases(rng *rand.Rand) []stunCase {
	transaction := func() [stun.TransactionIDSize]byte {
		var id [stun.TransactionIDSize]byte
		for i := range id {
			id[i] = byte(rng.UintN(256))
		}
		return id
	}
	attribute := func(kind uint16, value []byte) []byte {
		out := []byte{byte(kind >> 8), byte(kind), byte(len(value) >> 8), byte(len(value))}
		out = append(out, value...)
		for len(out)%4 != 0 {
			out = append(out, 0)
		}
		return out
	}
	message := func(kind uint16, id [stun.TransactionIDSize]byte, attributes ...[]byte) []byte {
		var body []byte
		for _, a := range attributes {
			body = append(body, a...)
		}
		out := []byte{byte(kind >> 8), byte(kind), byte(len(body) >> 8), byte(len(body)), 0x21, 0x12, 0xA4, 0x42}
		out = append(out, id[:]...)
		return append(out, body...)
	}
	xorValue := func(family uint16, ip []byte, port uint16, id [stun.TransactionIDSize]byte) []byte {
		mask := append([]byte{0x21, 0x12, 0xA4, 0x42}, id[:]...)
		value := []byte{0, byte(family), byte((port ^ 0x2112) >> 8), byte(port ^ 0x2112)}
		for i, b := range ip {
			value = append(value, b^mask[i])
		}
		return value
	}
	plainValue := func(family uint16, ip []byte, port uint16) []byte {
		return append([]byte{0, byte(family), byte(port >> 8), byte(port)}, ip...)
	}
	v4 := []byte{203, 0, 113, 7}
	v6 := netip.MustParseAddr("2001:db8::7").AsSlice()
	mapped := netip.MustParseAddr("::ffff:203.0.113.9").AsSlice()
	var cases []stunCase
	add := func(name string, packet []byte) {
		c := stunCase{Name: name, Packet: hex.EncodeToString(packet)}
		if msg, addr, err := parseSTUNBindingResponse(packet); err == nil {
			c.Transaction = hex.EncodeToString(msg.TransactionID[:])
			c.Mapped = hexAddrPort(addr)
		}
		cases = append(cases, c)
	}
	// pion's own encoders first.
	{
		id := transaction()
		m := stun.MustBuild(stun.NewTransactionIDSetter(id), stun.BindingSuccess,
			&stun.XORMappedAddress{IP: net.IP(v4), Port: 40000})
		add("pion xor-mapped IPv4", m.Raw)
		id = transaction()
		m = stun.MustBuild(stun.NewTransactionIDSetter(id), stun.BindingSuccess,
			&stun.XORMappedAddress{IP: net.IP(v6), Port: 5000}, stun.Fingerprint)
		add("pion xor-mapped IPv6 with fingerprint", m.Raw)
		id = transaction()
		m = stun.MustBuild(stun.NewTransactionIDSetter(id), stun.BindingSuccess,
			&stun.MappedAddress{IP: net.IP(v4), Port: 3478})
		add("pion mapped IPv4", m.Raw)
		id = transaction()
		m = stun.MustBuild(stun.NewTransactionIDSetter(id), stun.BindingSuccess,
			&stun.MappedAddress{IP: net.IP(v6), Port: 1})
		add("pion mapped IPv6", m.Raw)
		id = transaction()
		m = stun.MustBuild(stun.NewTransactionIDSetter(id), stun.BindingRequest)
		add("pion binding request", m.Raw)
		id = transaction()
		m = stun.MustBuild(stun.NewTransactionIDSetter(id), stun.BindingError,
			&stun.XORMappedAddress{IP: net.IP(v4), Port: 40000})
		add("pion binding error", m.Raw)
	}
	type base struct {
		name   string
		packet func(id [stun.TransactionIDSize]byte) []byte
	}
	bases := []base{
		{"xor IPv4", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x0020, xorValue(1, v4, 40000, id))) }},
		{"xor IPv6", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x0020, xorValue(2, v6, 5000, id))) }},
		{"xor IPv6 holding IPv4-mapped", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x0020, xorValue(2, mapped, 6000, id))) }},
		{"old xor type", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x8020, xorValue(1, v4, 40001, id))) }},
		{"mapped IPv4", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x0001, plainValue(1, v4, 3478))) }},
		{"mapped IPv6", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x0001, plainValue(2, v6, 3478))) }},
		{"mapped then xor", func(id [12]byte) []byte {
			return message(0x0101, id, attribute(0x0001, plainValue(1, v4, 1)), attribute(0x0020, xorValue(1, v4, 2, id)))
		}},
		{"two xor", func(id [12]byte) []byte {
			return message(0x0101, id, attribute(0x0020, xorValue(1, v4, 1, id)), attribute(0x0020, xorValue(1, v4, 2, id)))
		}},
		{"bad xor family then mapped", func(id [12]byte) []byte {
			return message(0x0101, id, attribute(0x0020, xorValue(3, v4, 1, id)), attribute(0x0001, plainValue(1, v4, 9)))
		}},
		{"long xor then mapped", func(id [12]byte) []byte {
			return message(0x0101, id, attribute(0x0020, xorValue(1, append(v4, 1), 1, id)), attribute(0x0001, plainValue(1, v4, 9)))
		}},
		{"short xor", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x0020, xorValue(1, v4[:2], 7, id))) }},
		{"long mapped", func(id [12]byte) []byte {
			return message(0x0101, id, attribute(0x0001, plainValue(1, append(v4, 9, 9), 7)))
		}},
		{"header-only mapped", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x0001, plainValue(1, nil, 7))) }},
		{"xor port zero", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x0020, xorValue(1, v4, 0, id))) }},
		{"high type bits", func(id [12]byte) []byte { return message(0xC101, id, attribute(0x0020, xorValue(1, v4, 1, id))) }},
		{"other method", func(id [12]byte) []byte { return message(0x0103, id, attribute(0x0020, xorValue(1, v4, 1, id))) }},
		{"no address", func(id [12]byte) []byte { return message(0x0101, id, attribute(0x8022, []byte("software"))) }},
		{"integrity then xor", func(id [12]byte) []byte {
			return message(0x0101, id, attribute(0x0008, make([]byte, 20)), attribute(0x0020, xorValue(1, v4, 3, id)))
		}},
	}
	for _, b := range bases {
		id := transaction()
		packet := b.packet(id)
		add(b.name, packet)
		add(b.name+", trailing bytes", append(append([]byte{}, packet...), 1, 2, 3))
		for cut := 0; cut < len(packet); cut += 1 + int(rng.UintN(5)) {
			add(fmt.Sprintf("%s, cut to %d", b.name, cut), packet[:cut])
		}
		for i := 0; i < 24; i++ {
			mutated := append([]byte{}, packet...)
			at := int(rng.UintN(uint(len(mutated))))
			mutated[at] ^= byte(1 + rng.UintN(255))
			add(fmt.Sprintf("%s, byte %d changed", b.name, at), mutated)
		}
		lengthened := append([]byte{}, packet...)
		lengthened[3] += 4
		add(b.name+", length past the buffer", lengthened)
	}
	return cases
}

// hexAddrPort writes an address as its bytes in hex, a slash and the port.
func hexAddrPort(addr netip.AddrPort) string {
	return hex.EncodeToString(addr.Addr().AsSlice()) + "/" + strconv.Itoa(int(addr.Port()))
}

// plainString is AddrPort.String with an IPv4-mapped address in hex
// groups, which the fixture scanner reads as one address.
func plainString(addr netip.AddrPort) string {
	if addr.Addr().Is4In6() {
		b := addr.Addr().As16()
		return fmt.Sprintf("[::ffff:%x:%x]:%d", uint16(b[12])<<8|uint16(b[13]), uint16(b[14])<<8|uint16(b[15]), addr.Port())
	}
	return addr.String()
}

var magic = [8]byte{'H', 'Y', 'R', 'L', 'M', 'v', '1', 0}

// encodeWith builds a punch packet as EncodePunchPacket does, with the
// salt and padding given.
func encodeWith(kind byte, nonce, obfs, salt, padding []byte) []byte {
	plain := make([]byte, 25+len(padding))
	copy(plain, magic[:])
	plain[8] = kind
	copy(plain[9:25], nonce)
	copy(plain[25:], padding)
	packet := append(append([]byte{}, salt...), plain...)
	xorPunchPacket(packet[8:], obfs, salt)
	return packet
}

func punchCases(rng *rand.Rand) []punchCase {
	bytesOf := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rng.UintN(256))
		}
		return b
	}
	// The construction matches Xray-core's encoder: rebuild its own
	// packets from their salt and padding.
	for i := 0; i < 64; i++ {
		meta, err := realm.NewPunchMetadata()
		if err != nil {
			panic(err)
		}
		nonce, _ := hex.DecodeString(meta.Nonce)
		obfs, _ := hex.DecodeString(meta.Obfs)
		kind := realm.PunchPacketType(1 + i%2)
		packet, err := realm.EncodePunchPacket(kind, meta)
		if err != nil {
			panic(err)
		}
		plain := append([]byte{}, packet[8:]...)
		xorPunchPacket(plain, obfs, packet[:8])
		if !bytes.Equal(encodeWith(byte(kind), nonce, obfs, packet[:8], plain[25:]), packet) {
			panic("the oracle's punch encoding differs from Xray-core's")
		}
	}
	var cases []punchCase
	add := func(nonce, obfs, packet []byte) {
		meta := realm.PunchMetadata{Nonce: hex.EncodeToString(nonce), Obfs: hex.EncodeToString(obfs)}
		c := punchCase{Nonce: meta.Nonce, Obfs: meta.Obfs, Packet: hex.EncodeToString(packet)}
		if p, err := realm.DecodePunchPacket(packet, meta); err == nil {
			c.Type = int(p.Type)
			c.Padding = p.PaddingLength
		}
		cases = append(cases, c)
	}
	for i := 0; i < 12; i++ {
		nonce, obfs, salt := bytesOf(16), bytesOf(32), bytesOf(8)
		padding := bytesOf([]int{0, 1, 31, 32, 33, 64, 500, 1023, 1024, 1025, 7, 100}[i])
		kind := byte(1 + i%2)
		packet := encodeWith(kind, nonce, obfs, salt, padding)
		add(nonce, obfs, packet)
		other := append([]byte{}, nonce...)
		other[i] ^= 1
		add(other, obfs, packet)
		otherKey := append([]byte{}, obfs...)
		otherKey[i] ^= 1
		add(nonce, otherKey, packet)
		for j := 0; j < 6; j++ {
			mutated := append([]byte{}, packet...)
			mutated[rng.UintN(uint(len(mutated)))] ^= byte(1 + rng.UintN(255))
			add(nonce, obfs, mutated)
		}
		add(nonce, obfs, packet[:len(packet)-1])
		add(nonce, obfs, append(append([]byte{}, packet...), 0))
	}
	nonce, obfs, salt := bytesOf(16), bytesOf(32), bytesOf(8)
	for _, kind := range []byte{0, 3, 0x81, 0xFF} {
		add(nonce, obfs, encodeWith(kind, nonce, obfs, salt, nil))
	}
	add(nonce, obfs, nil)
	add(nonce, obfs, bytesOf(32))
	return cases
}

func candidateCases() []candidateCase {
	type spec struct {
		locals, peers []string
		family        realm.Family
	}
	specs := []spec{
		{[]string{"203.0.113.1:5"}, []string{"198.51.100.1:1000", "[2001:db8::1]:1000"}, realm.Family_Dual},
		{[]string{"[2001:db8::9]:5"}, []string{"198.51.100.1:1000", "[2001:db8::1]:1000"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5", "[2001:db8::9]:5"}, []string{"198.51.100.1:1000", "[2001:db8::1]:1000"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5", "[2001:db8::9]:5"}, []string{"198.51.100.1:1000", "[2001:db8::1]:1000"}, realm.Family_V4},
		{[]string{"203.0.113.1:5", "[2001:db8::9]:5"}, []string{"198.51.100.1:1000", "[2001:db8::1]:1000"}, realm.Family_V6},
		{[]string{"203.0.113.1:5"}, []string{"[::ffff:c633:6401]:1000"}, realm.Family_Dual},
		{[]string{"[2001:db8::9]:5"}, []string{"[::ffff:c633:6401]:1000"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{"198.51.100.1:1000", "198.51.100.1:1000"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{"198.51.100.1:1000", "198.51.100.1:1003"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{"198.51.100.1:1000", "198.51.100.1:1004"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{"198.51.100.1:1000", "198.51.100.1:1005"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{"198.51.100.1:1000", "198.51.100.1:1002", "198.51.100.1:1006"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{"198.51.100.1:65530", "198.51.100.1:65533"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{"198.51.100.1:9", "198.51.100.1:10"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{
			"198.51.100.1:100", "198.51.100.1:104", "198.51.100.1:108", "198.51.100.1:112", "198.51.100.1:116",
			"198.51.100.1:120", "198.51.100.1:124", "198.51.100.1:128", "198.51.100.1:132"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{
			"198.51.100.1:100", "198.51.100.1:104", "198.51.100.1:108", "198.51.100.1:112", "198.51.100.1:116",
			"198.51.100.1:120", "198.51.100.1:124", "198.51.100.1:128", "198.51.100.1:132", "198.51.100.1:136",
			"198.51.100.1:140"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, []string{"198.51.100.1:1000", "198.51.100.2:1001", "198.51.100.2:1002", "198.51.100.1:1001"}, realm.Family_Dual},
		{[]string{"[2001:db8::9]:5"}, []string{"[2001:db8::1]:1000", "[2001:db8::1]:1001"}, realm.Family_Dual},
		{nil, []string{"198.51.100.1:1000"}, realm.Family_Dual},
		{[]string{"203.0.113.1:5"}, nil, realm.Family_Dual},
	}
	cases := make([]candidateCase, 0, len(specs))
	for _, s := range specs {
		parse := func(list []string) []netip.AddrPort {
			out := make([]netip.AddrPort, 0, len(list))
			for _, a := range list {
				out = append(out, netip.MustParseAddrPort(a))
			}
			return out
		}
		filtered, seen := candidatePunchAddrs(parse(s.locals), parse(s.peers), s.family)
		expanded := expandSymmetricNATCandidates(filtered, seen)
		punched := make([]string, 0, len(expanded))
		for _, a := range expanded {
			punched = append(punched, plainString(a))
		}
		cases = append(cases, candidateCase{Locals: s.locals, Peers: s.peers, Family: int(s.family), Punched: punched})
	}
	return cases
}

func addrPortsCases() []addrPortsCase {
	corpus := [][]string{
		{"198.51.100.1:1", "[2001:db8::1]:2"},
		{"198.51.100.1:0"},
		{"198.51.100.1:00080"},
		{"198.51.100.1:65536"},
		{"198.51.100.1"},
		{"[::ffff:c633:6401]:3"},
		{"[2001:db8::1%eth0]:4"},
		{"[2001:db8::1%7]:4"},
		{"01.0.2.4:5"},
		{"198.51.100.1:1", "nope"},
		{"2001:db8::1:2"},
		{"[2001:db8::1]"},
		{""},
		{},
	}
	cases := make([]addrPortsCase, 0, len(corpus))
	for _, list := range corpus {
		parsed, _ := parseAddrPorts(list)
		out := make([]string, 0, len(parsed))
		for _, a := range parsed {
			out = append(out, plainString(a))
		}
		cases = append(cases, addrPortsCase{Addresses: list, Parsed: out})
	}
	return cases
}

type httpSpec struct {
	name, token, id, portText, response string
}

func gzipped(body string) string {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	w.Write([]byte(body))
	w.Close()
	return buf.String()
}

func httpCases() []httpCase {
	addrs := `{"addresses":["198.51.100.1:1000","[2001:db8::1]:2000"],"nonce":"aa","obfs":"bb"}`
	reply := func(status string, headers string, body string) string {
		return "HTTP/1.1 " + status + "\r\n" + headers + "Connection: close\r\n\r\n" + body
	}
	fixed := func(status, body string) string {
		return reply(status, "Content-Type: application/json\r\nContent-Length: "+strconv.Itoa(len(body))+"\r\n", body)
	}
	chunked := "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" +
		"10\r\n" + addrs[:16] + "\r\n" + strconv.FormatInt(int64(len(addrs)-16), 16) + "\r\n" + addrs[16:] + "\r\n0\r\n\r\n"
	zipped := gzipped(addrs)
	specs := []httpSpec{
		{"answer", "synthetic-token", "synthetic-realm", "", fixed("200 OK", addrs)},
		{"escaped name", "synthetic-token", "a/b c?d;e", "", fixed("200 OK", addrs)},
		{"non-ASCII name", "synthetic-token", "naïve-realm", "", fixed("200 OK", addrs)},
		{"percent in name", "synthetic-token", "%41", "", fixed("200 OK", addrs)},
		{"token with colons", "user:pass", "synthetic-realm", "", fixed("200 OK", addrs)},
		{"port with a leading zero", "synthetic-token", "synthetic-realm", "0", fixed("200 OK", addrs)},
		{"chunked", "t", "r", "", chunked},
		{"gzip", "t", "r", "", reply("200 OK", "Content-Encoding: gzip\r\nContent-Length: "+strconv.Itoa(len(zipped))+"\r\n", zipped)},
		{"gzip in capitals", "t", "r", "", reply("200 OK", "Content-Encoding: GZIP\r\nContent-Length: "+strconv.Itoa(len(zipped))+"\r\n", zipped)},
		{"close-delimited", "t", "r", "", reply("200 OK", "", addrs)},
		{"keys in another case", "t", "r", "", fixed("200 OK", `{"ADDRESSES":["198.51.100.1:1"]}`)},
		{"duplicate keys", "t", "r", "", fixed("200 OK", `{"addresses":["198.51.100.1:1"],"addresses":["198.51.100.2:2"]}`)},
		{"trailing bytes", "t", "r", "", fixed("200 OK", addrs+"garbage{")},
		{"second value", "t", "r", "", fixed("200 OK", addrs+`{"addresses":["198.51.100.9:9"]}`)},
		{"null", "t", "r", "", fixed("200 OK", "null")},
		{"null addresses", "t", "r", "", fixed("200 OK", `{"addresses":null}`)},
		{"null element", "t", "r", "", fixed("200 OK", `{"addresses":["198.51.100.1:1",null]}`)},
		{"number element", "t", "r", "", fixed("200 OK", `{"addresses":[1]}`)},
		{"string addresses", "t", "r", "", fixed("200 OK", `{"addresses":"198.51.100.1:1"}`)},
		{"number nonce", "t", "r", "", fixed("200 OK", `{"addresses":["198.51.100.1:1"],"nonce":1}`)},
		{"unknown fields", "t", "r", "", fixed("200 OK", `{"addresses":["198.51.100.1:1"],"extra":{"a":[1,2]}}`)},
		{"array", "t", "r", "", fixed("200 OK", `[]`)},
		{"empty body", "t", "r", "", fixed("200 OK", "")},
		{"whitespace body", "t", "r", "", fixed("200 OK", " \n ")},
		{"truncated JSON", "t", "r", "", fixed("200 OK", `{"addresses":["198.51`)},
		{"not found", "t", "r", "", fixed("404 Not Found", `{"error":"realm_not_found","message":"realm not registered"}`+"\n")},
		{"unauthorized", "t", "r", "", fixed("401 Unauthorized", `{"error":"invalid_token","message":"invalid realm token"}`+"\n")},
		{"server error without body", "t", "r", "", fixed("500 Internal Server Error", "")},
		{"no content", "t", "r", "", reply("204 No Content", "", "")},
		{"created", "t", "r", "", fixed("201 Created", addrs)},
		{"continue then answer", "t", "r", "", "HTTP/1.1 100 Continue\r\n\r\n" + fixed("200 OK", addrs)},
	}
	var cases []httpCase
	for _, s := range specs {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
		requests := make(chan string, 1)
		go func(response string) {
			conn, err := listener.Accept()
			if err != nil {
				requests <- ""
				return
			}
			defer conn.Close()
			reader := bufio.NewReader(conn)
			var head bytes.Buffer
			length := 0
			for {
				line, err := reader.ReadString('\n')
				if err != nil {
					break
				}
				head.WriteString(line)
				if strings.HasPrefix(line, "Content-Length: ") {
					length, _ = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "Content-Length: ")))
				}
				if line == "\r\n" {
					break
				}
			}
			body := make([]byte, length)
			io.ReadFull(reader, body)
			requests <- head.String() + string(body)
			conn.Write([]byte(response))
		}(s.response)
		client := realm.NewClient("http", "127.0.0.1", s.portText+port, s.token, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := client.Connect(ctx, s.id, realm.ConnectRequest{
			Addresses: []string{"203.0.113.5:4000", "[2001:db8::5]:4000"},
			PunchMetadata: realm.PunchMetadata{
				Nonce: strings.Repeat("ab", 16),
				Obfs:  strings.Repeat("01", 32),
			},
		})
		cancel()
		listener.Close()
		request := <-requests
		c := httpCase{
			Name:     s.name,
			Token:    s.token,
			ID:       s.id,
			PortText: s.portText,
			Request:  strings.ReplaceAll(request, "127.0.0.1:"+s.portText+port, "127.0.0.1:"+s.portText+"{port}"),
			Response: hex.EncodeToString([]byte(s.response)),
		}
		if err != nil {
			c.Error = true
			var status *realm.StatusError
			if errors.As(err, &status) {
				c.Status = status.StatusCode
			}
		} else {
			c.Result = resp.Addresses
			if c.Result == nil {
				c.Result = []string{}
			}
		}
		cases = append(cases, c)
	}
	return cases
}

func main() {
	rng := rand.New(rand.NewPCG(0x7265616c6d, 0x6f7261636c65))
	var out result
	out.URLs = urls()
	out.StunServers = stunServers()
	out.Settings = settings()
	out.Stun = stunCases(rng)
	out.Punch = punchCases(rng)
	out.Candidates = candidateCases()
	out.AddrPorts = addrPortsCases()
	out.HTTP = httpCases()
	encoded, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[1], append(encoded, '\n'), 0600); err != nil {
		panic(err)
	}
}

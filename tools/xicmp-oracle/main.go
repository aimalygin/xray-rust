// Records what Xray-core's xicmp mask does with its settings and on the
// wire: Xicmp.Build's verdicts on addresses and settings, the echo
// messages its marshal writes for the client's requests and the server's
// replies, x/net/icmp's checksum, and how ParseMessage reads the messages
// its readers take. Randomness is seeded, so a fresh run matches
// tests/fixtures/xicmp/vectors.json byte for byte.
// Run with go -C <pinned checkout> run -mod=readonly <this file> out.json
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	_ "unsafe"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask/xicmp"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

//go:linkname marshal github.com/xtls/xray-core/transport/internet/finalmask/xicmp.marshal
func marshal(b []byte, typ icmp.Type, id, seq int, dataLen int) []byte

//go:linkname checksum golang.org/x/net/icmp.checksum
func checksum(b []byte) uint16

type ipCase struct {
	IP    string `json:"ip"`
	Error string `json:"error,omitempty"`
}

type settingsCase struct {
	Settings json.RawMessage `json:"settings"`
	Error    string          `json:"error,omitempty"`
	Dgram    bool            `json:"dgram"`
	IPs      []string        `json:"ips"`
}

type echoCase struct {
	// "request" from the client, after its id; "reply" from the server.
	Side     string `json:"side"`
	V6       bool   `json:"v6"`
	ID       int    `json:"id"`
	Seq      int    `json:"seq"`
	ClientID string `json:"clientId,omitempty"`
	Payload  string `json:"payload"`
	Message  string `json:"message"`
}

type checksumCase struct {
	Bytes    string `json:"bytes"`
	Checksum uint16 `json:"checksum"`
}

type parseCase struct {
	V6      bool   `json:"v6"`
	Message string `json:"message"`
	// ParseMessage's reading: an error, or the type, and for an echo its
	// identifier, sequence and data.
	Error bool   `json:"error,omitempty"`
	Type  int    `json:"type"`
	Echo  bool   `json:"echo,omitempty"`
	ID    int    `json:"id,omitempty"`
	Seq   int    `json:"seq,omitempty"`
	Data  string `json:"data,omitempty"`
}

type result struct {
	IPs       []ipCase       `json:"ips"`
	Settings  []settingsCase `json:"settings"`
	Echoes    []echoCase     `json:"echoes"`
	Checksums []checksumCase `json:"checksums"`
	Parses    []parseCase    `json:"parses"`
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

func build(settings []byte) (*xicmp.Config, error) {
	var c conf.Xicmp
	if err := json.Unmarshal(settings, &c); err != nil {
		return nil, err
	}
	built, err := c.Build()
	if err != nil {
		return nil, err
	}
	return built.(*xicmp.Config), nil
}

func ips() []ipCase {
	corpus := []string{
		"192.0.2.1", "198.51.100.255", "0.0.0.0", "255.255.255.255",
		"2001:db8::1", "::", "::1", "fe80::1", "2001:db8::1%eth0", "fe80::1%25",
		"fe80::1%", "2001:db8::192.0.2.1", "::ffff:c000:201", "2001:db8::c000:201",
		"192.0.2.1%eth0", "01.0.2.1", "192.0.2.01", "192.0.2", "192.0.2.1.5",
		"192.0.2.256", " 192.0.2.1", "192.0.2.1 ", "[2001:db8::1]", "2001:db8::1/64",
		"192.0.2.0/24", "host.example", "", "2001:db8:::1", "2001:db8::1::2",
		"2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::00001", "2001:db8:3:4:5:6:7:8",
		"2001:db8:3:4:5:6:7:8:9", "2001:db8::192.0.2.256", "2001:db8::01.0.2.1", "2001:DB8::A",
	}
	cases := make([]ipCase, 0, len(corpus))
	for _, ip := range corpus {
		settings, _ := json.Marshal(map[string]any{"ips": []string{ip}})
		_, err := build(settings)
		cases = append(cases, ipCase{IP: ip, Error: errText(err)})
	}
	return cases
}

func settings() []settingsCase {
	corpus := []string{
		`{}`,
		`{"dgram":true}`,
		`{"dgram":false,"ips":["192.0.2.1","2001:db8::1"]}`,
		`{"dgram":null,"ips":null}`,
		`{"dgram":"true"}`,
		`{"dgram":1}`,
		`{"ips":"192.0.2.1"}`,
		`{"ips":[1]}`,
		`{"ips":[null]}`,
		`{"ips":["192.0.2.1",null]}`,
		`{"ips":[]}`,
		`null`,
		`5`,
	}
	cases := make([]settingsCase, 0, len(corpus))
	for _, raw := range corpus {
		c := settingsCase{Settings: json.RawMessage(raw)}
		built, err := build([]byte(raw))
		if err != nil {
			c.Error = errText(err)
		} else {
			c.Dgram = built.DGRAM
			c.IPs = built.IPs
			if c.IPs == nil {
				c.IPs = []string{}
			}
		}
		cases = append(cases, c)
	}
	return cases
}

func bytesOf(rng *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.UintN(256))
	}
	return b
}

func echoes(rng *rand.Rand) []echoCase {
	var cases []echoCase
	for _, length := range []int{0, 1, 2, 7, 8, 9, 31, 64, 1200, 1350, 4080} {
		for _, v6 := range []bool{false, true} {
			id, seq := int(rng.UintN(65536)), int(rng.UintN(65536))
			clientID := bytesOf(rng, 8)
			payload := bytesOf(rng, length)
			// The client: its id after the header, then the packet.
			b := make([]byte, 4096)
			copy(b[8:], clientID)
			copy(b[16:], payload)
			var typ icmp.Type = ipv4.ICMPTypeEcho
			if v6 {
				typ = ipv6.ICMPTypeEchoRequest
			}
			message := marshal(b, typ, id, seq, 8+len(payload))
			cases = append(cases, echoCase{Side: "request", V6: v6, ID: id, Seq: seq,
				ClientID: hex.EncodeToString(clientID), Payload: hex.EncodeToString(payload),
				Message: hex.EncodeToString(message)})
			// The server: the packet after the header.
			if length > 4088 {
				continue
			}
			b = make([]byte, 4096)
			copy(b[8:], payload)
			typ = ipv4.ICMPTypeEchoReply
			if v6 {
				typ = ipv6.ICMPTypeEchoReply
			}
			message = marshal(b, typ, id, seq, len(payload))
			cases = append(cases, echoCase{Side: "reply", V6: v6, ID: id, Seq: seq,
				Payload: hex.EncodeToString(payload), Message: hex.EncodeToString(message)})
		}
	}
	return cases
}

func checksums(rng *rand.Rand) []checksumCase {
	var cases []checksumCase
	for _, length := range []int{0, 1, 2, 3, 8, 9, 63, 64, 1201, 4096} {
		for i := 0; i < 3; i++ {
			b := bytesOf(rng, length)
			cases = append(cases, checksumCase{Bytes: hex.EncodeToString(b), Checksum: checksum(b)})
		}
	}
	cases = append(cases, checksumCase{Bytes: hex.EncodeToString(make([]byte, 64)), Checksum: checksum(make([]byte, 64))})
	ones := make([]byte, 64)
	for i := range ones {
		ones[i] = 0xff
	}
	cases = append(cases, checksumCase{Bytes: hex.EncodeToString(ones), Checksum: checksum(ones)})
	return cases
}

func parses(rng *rand.Rand) []parseCase {
	var cases []parseCase
	add := func(v6 bool, message []byte) {
		proto := 1
		if v6 {
			proto = 58
		}
		c := parseCase{V6: v6, Message: hex.EncodeToString(message)}
		m, err := icmp.ParseMessage(proto, message)
		if err != nil {
			c.Error = true
		} else {
			switch t := m.Type.(type) {
			case ipv4.ICMPType:
				c.Type = int(t)
			case ipv6.ICMPType:
				c.Type = int(t)
			default:
				panic(fmt.Sprintf("%T", m.Type))
			}
			if echo, ok := m.Body.(*icmp.Echo); ok {
				c.Echo = true
				c.ID = echo.ID
				c.Seq = echo.Seq
				c.Data = hex.EncodeToString(echo.Data)
			}
		}
		cases = append(cases, c)
	}
	for _, v6 := range []bool{false, true} {
		for _, typ := range []byte{0, 3, 8, 11, 128, 129, 133, 255} {
			for _, length := range []int{0, 3, 4, 7, 8, 9, 40} {
				message := bytesOf(rng, length)
				if length > 0 {
					message[0] = typ
				}
				add(v6, message)
			}
		}
		for i := 0; i < 24; i++ {
			message := bytesOf(rng, 8+int(rng.UintN(32)))
			if v6 {
				message[0] = 128 + byte(rng.UintN(2))
			} else {
				message[0] = byte(rng.UintN(2)) * 8
			}
			add(v6, message)
		}
	}
	return cases
}

func main() {
	rng := rand.New(rand.NewPCG(0x7869636d70, 0x6f7261636c65))
	var out result
	out.IPs = ips()
	out.Settings = settings()
	out.Echoes = echoes(rng)
	out.Checksums = checksums(rng)
	out.Parses = parses(rng)
	encoded, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[1], append(encoded, '\n'), 0600); err != nil {
		panic(err)
	}
}

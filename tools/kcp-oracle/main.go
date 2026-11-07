// Command kcp-oracle writes the vectors xray-rust's mKCP mask tests compare
// against: what Xray-core's own finalmask code puts on the wire for each
// mkcp-legacy mask, how mask groups order around noise, which datagrams the
// 4096-byte limit drops, what the DNS header packs for awkward names, and what
// a received datagram unwraps to. Run it inside a pinned Xray-core checkout:
//
//	go -C Xray-core run -mod=readonly ../tools/kcp-oracle/main.go out.json
//
// AES-128-GCM draws a random nonce, so its writes record only lengths and its
// reads use a packet sealed here with a fixed nonce.
package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/aes128gcm"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/header"
	"github.com/xtls/xray-core/transport/internet/finalmask/mkcp/original"
	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
)

type capture struct {
	sent     [][]byte
	incoming [][]byte
}

func (c *capture) ReadFrom(p []byte) (int, net.Addr, error) {
	if len(c.incoming) == 0 {
		return 0, nil, fmt.Errorf("eof")
	}
	n := copy(p, c.incoming[0])
	c.incoming = c.incoming[1:]
	return n, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}, nil
}
func (c *capture) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.sent = append(c.sent, append([]byte(nil), p...))
	return len(p), nil
}
func (c *capture) Close() error                       { return nil }
func (c *capture) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *capture) SetDeadline(t time.Time) error      { return nil }
func (c *capture) SetReadDeadline(t time.Time) error  { return nil }
func (c *capture) SetWriteDeadline(t time.Time) error { return nil }

func dial(masks []finalmask.UDPMask, c *capture) net.Conn {
	fm := finalmask.NewFinalMask(nil, masks, nil, nil,
		func(ctx context.Context, dest xnet.Destination) (net.PacketConn, net.Addr, error) {
			return c, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}, nil
		}, nil)
	conn, err := fm.DialUDP(context.Background(), xnet.UDPDestination(xnet.ParseAddress("192.0.2.1"), 1))
	if err != nil {
		panic(err)
	}
	return conn
}

type write struct {
	// Writes with the same connection share one dialed conn, and so the
	// counters of its headers.
	Connection int      `json:"connection"`
	Masks      []string `json:"masks"`
	Payload    string   `json:"payload"`
	Sent       []string `json:"sent"`
}

type read struct {
	Masks    []string `json:"masks"`
	Incoming string   `json:"incoming"`
	Payload  *string  `json:"payload"`
}

type dnsCase struct {
	Domain string  `json:"domain"`
	Header *string `json:"header"`
	Error  string  `json:"error"`
}

func mask(name string) finalmask.UDPMask {
	switch {
	case name == "original":
		return &original.Config{}
	case strings.HasPrefix(name, "aes:"):
		return &aes128gcm.Config{Password: name[4:]}
	case name == "noise":
		return &noise.Config{Items: []*noise.Item{{Packet: []byte("NZ")}}}
	case strings.HasPrefix(name, "dns:"):
		return &header.Config{ID: 0, Domain: name[4:]}
	}
	ids := map[string]int32{"dtls": 1, "srtp": 2, "utp": 3, "wechat": 4, "wireguard": 5}
	return &header.Config{ID: ids[name]}
}

func main() {
	out := map[string]interface{}{}
	var writes []write
	connection := 0
	addWrite := func(names []string, payloads ...[]byte) {
		connection++
		var masks []finalmask.UDPMask
		for _, name := range names {
			masks = append(masks, mask(name))
		}
		c := &capture{}
		conn := dial(masks, c)
		for _, payload := range payloads {
			c.sent = nil
			conn.Write(payload)
			w := write{Connection: connection, Masks: names, Payload: hex.EncodeToString(payload)}
			random := strings.HasPrefix(names[0], "aes:")
			for _, s := range c.sent {
				if random {
					w.Sent = append(w.Sent, fmt.Sprintf("len:%d", len(s)))
				} else {
					w.Sent = append(w.Sent, hex.EncodeToString(s))
				}
			}
			writes = append(writes, w)
		}
	}
	for _, p := range []string{"", "a", "abc", "abcd", "hello, mKCP", "0123456789abcdef0123456789abcdef"} {
		addWrite([]string{"original"}, []byte(p))
	}
	for _, h := range []string{"dtls", "srtp", "utp", "wechat", "wireguard"} {
		// Three in a row show each header's counters.
		addWrite([]string{h}, []byte("x"), []byte("yy"), []byte("zzz"))
	}
	// Eight on one conn take DTLS's length past 100, where it wraps back.
	addWrite([]string{"dtls"}, []byte{0}, []byte{1}, []byte{2}, []byte{3},
		[]byte{4}, []byte{5}, []byte{6}, []byte{7})
	addWrite([]string{"original", "wechat"}, []byte("data"))
	addWrite([]string{"wechat", "original"}, []byte("data"))
	addWrite([]string{"srtp", "dtls", "utp", "original"}, []byte("stacked"))
	addWrite([]string{"original", "noise", "wechat"}, []byte("data"), []byte("more"))
	addWrite([]string{"noise", "original"}, []byte("data"))
	addWrite([]string{"original"}, make([]byte, 4090), make([]byte, 4091))
	addWrite([]string{"wechat", "noise", "srtp"}, make([]byte, 4083), make([]byte, 4084))
	addWrite([]string{"aes:seed"}, make([]byte, 4068), make([]byte, 4069))
	out["writes"] = writes

	// DNS headers, with the random transaction ID cleared.
	var dns []dnsCase
	for _, domain := range []string{"www.baidu.com", "a.example", "a\\.b.example", "x..y", "", ".", "example.com.",
		strings.Repeat("a", 63) + ".b", strings.Repeat("a", 64) + ".b", "trail\\",
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61),
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 62),
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 63)} {
		d := dnsCase{Domain: domain}
		func() {
			defer func() {
				if r := recover(); r != nil {
					d.Error = "panic"
				}
			}()
			c := &capture{}
			var masks []finalmask.UDPMask
			masks = append(masks, &header.Config{ID: 0, Domain: domain})
			fm := finalmask.NewFinalMask(nil, masks, nil, nil,
				func(ctx context.Context, dest xnet.Destination) (net.PacketConn, net.Addr, error) {
					return c, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}, nil
				}, nil)
			conn, err := fm.DialUDP(context.Background(), xnet.UDPDestination(xnet.ParseAddress("192.0.2.1"), 1))
			if err != nil {
				d.Error = err.Error()
				return
			}
			conn.Write([]byte{})
			h := c.sent[0]
			h[0], h[1] = 0, 0
			s := hex.EncodeToString(h)
			d.Header = &s
		}()
		dns = append(dns, d)
	}
	out["dns"] = dns

	// Reads: what each mask group hands KCP, or null for a drop.
	var reads []read
	addRead := func(names []string, incoming []byte) {
		var masks []finalmask.UDPMask
		for _, name := range names {
			masks = append(masks, mask(name))
		}
		c := &capture{incoming: [][]byte{incoming}}
		conn := dial(masks, c)
		buf := make([]byte, 8192)
		r := read{Masks: names, Incoming: hex.EncodeToString(incoming)}
		n, err := conn.Read(buf)
		if err == nil {
			s := hex.EncodeToString(buf[:n])
			r.Payload = &s
		}
		reads = append(reads, r)
	}
	sealed := func(names []string, payload []byte) []byte {
		var masks []finalmask.UDPMask
		for _, name := range names {
			masks = append(masks, mask(name))
		}
		c := &capture{}
		dial(masks, c).Write(payload)
		return c.sent[len(c.sent)-1]
	}
	good := sealed([]string{"original"}, []byte("hello"))
	addRead([]string{"original"}, good)
	bad := append([]byte(nil), good...)
	bad[len(bad)-1] ^= 1
	addRead([]string{"original"}, bad)
	addRead([]string{"original"}, good[:5])
	addRead([]string{"wechat"}, []byte("0123456789abcPAYLOAD"))
	addRead([]string{"wechat"}, []byte("012345678901"))
	addRead([]string{"original", "wechat"}, sealed([]string{"original", "wechat"}, []byte("both")))
	addRead([]string{"wechat", "original"}, sealed([]string{"original", "wechat"}, []byte("swapped")))
	// AES-128-GCM with a fixed nonce, sealed by Go's own AEAD.
	key := sha256.Sum256([]byte("seed"))
	block, _ := aes.NewCipher(key[:16])
	aead, _ := cipher.NewGCM(block)
	nonce := []byte("fixed-nonce!")
	aesPacket := aead.Seal(append([]byte(nil), nonce...), nonce, []byte("secret"), nil)
	addRead([]string{"aes:seed"}, aesPacket)
	addRead([]string{"aes:other"}, aesPacket)
	addRead([]string{"aes:seed"}, aesPacket[:27])
	out["reads"] = reads
	out["aesFixedNonce"] = hex.EncodeToString(aesPacket)

	// Xray logs every drop to stdout, so the vectors go to a file.
	file, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}

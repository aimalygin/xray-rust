package main

import (
	"bytes"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"time"

	ss "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/chacha20poly1305"
)

type wireConn struct {
	net.Conn
	bytes.Buffer
}

func (c *wireConn) Write(p []byte) (int, error) { return c.Buffer.Write(p) }
func (c *wireConn) Read(p []byte) (int, error)  { return c.Buffer.Read(p) }
func (c *wireConn) Close() error                { return nil }
func ss2022Fixtures() []map[string]any {
	saved := crand.Reader
	defer func() { crand.Reader = saved }()
	cases := []map[string]any{}
	for _, method := range ss.List {
		for _, chains := range []int{1, 3} {
			if chains > 1 && strings.Contains(method, "chacha") {
				continue
			}
			size := 32
			if strings.Contains(method, "128") {
				size = 16
			}
			// Include oversized-key normalization in the identity-chain vectors.
			keys := []string{}
			for i := 0; i < chains; i++ {
				n := size
				if chains > 1 && i == 1 {
					n += 7
				}
				keys = append(keys, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, n)))
			}
			password := strings.Join(keys, ":")
			m, err := ss.NewWithPassword(method, password, func() time.Time { return time.Unix(1700000000, 0) })
			must(err)
			salt := bytes.Repeat([]byte{0x11}, size)
			crand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x11}, 4096))
			tcp := &wireConn{}
			destination := M.ParseSocksaddr("example.test:443")
			conn := m.DialEarlyConn(tcp, destination)
			payload := bytes.Repeat([]byte{0x42}, 900)
			_, err = conn.Write(payload)
			must(err)
			request := append([]byte(nil), tcp.Bytes()...)
			tcp.Reset()
			_, err = conn.Write([]byte("after-header"))
			must(err)
			crand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x22}, 4096))
			udp := &wireConn{}
			packetConn := m.DialPacketConn(udp)
			udpPayload := []byte("udp-payload")
			_, err = packetConn.WriteTo(udpPayload, destination)
			must(err)
			wire := udp.Bytes()
			id := uint64(0x2222222222222222)
			nonce := ""
			if strings.Contains(method, "chacha") {
				key, _ := base64.StdEncoding.DecodeString(password)
				cipher, err := chacha20poly1305.NewX(key)
				must(err)
				plain, err := cipher.Open(nil, wire[:24], wire[24:], nil)
				must(err)
				id = binary.BigEndian.Uint64(plain[:8])
				nonce = hex.EncodeToString(wire[:24])
			}
			cases = append(cases, map[string]any{"method": method, "password": password, "timestamp": 1700000000, "address": "example.test", "port": 443,
				"salt": hex.EncodeToString(salt), "payload": hex.EncodeToString(payload), "request": hex.EncodeToString(request), "nextRecord": hex.EncodeToString(tcp.Bytes()),
				"udpSessionId": id, "udpNonce": nonce, "udpPayload": hex.EncodeToString(udpPayload), "udpWire": hex.EncodeToString(wire)})
		}
	}
	return cases
}

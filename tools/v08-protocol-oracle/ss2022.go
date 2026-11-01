package main

import (
	"bytes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	ss "github.com/xtls/xray-core/proxy/shadowsocks_2022"
)

// The reference now reads time.Now internally. Authenticate its emitted bytes,
// change only the timestamp, then reseal to make a reproducible fixture. All
// framing, KDF, identity headers and stream nonce transitions come from Xray.
func fixedTimestamp(aead cipher.AEAD, nonce, sealed []byte, offset int) []byte {
	plain, err := aead.Open(nil, nonce, sealed, nil)
	must(err)
	binary.BigEndian.PutUint64(plain[offset:offset+8], 1700000000)
	return aead.Seal(nil, nonce, plain, nil)
}

func ss2022Fixtures() []map[string]any {
	saved := crand.Reader
	defer func() { crand.Reader = saved }()
	cases := []map[string]any{}
	for _, method := range []string{ss.MethodAES128GCM, ss.MethodAES256GCM, ss.MethodChaCha20Poly1305} {
		m, err := ss.GetCipherMethod(method)
		must(err)
		for _, chains := range []int{1, 3} {
			if chains > 1 && m.IsChaCha {
				continue
			}
			keys := []string{}
			for i := 0; i < chains; i++ {
				keys = append(keys, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byte(i + 1)}, m.KeySaltLength)))
			}
			password := strings.Join(keys, ":")
			psks, err := ss.ParsePSKList(password, m.KeySaltLength)
			must(err)
			// v26.10.21 requires exact PSK lengths; it no longer normalizes
			// oversized keys using the removed sing-shadowsocks dependency.
			if _, err := ss.ParseKey(base64.StdEncoding.EncodeToString(make([]byte, m.KeySaltLength+7)), m.KeySaltLength); err == nil {
				panic("oversized SS2022 key accepted")
			}
			salt := bytes.Repeat([]byte{0x11}, m.KeySaltLength)
			destination := net.TCPDestination(net.DomainAddress("example.test"), 443)
			var tcp bytes.Buffer
			payload := bytes.Repeat([]byte{0x42}, 900) // disables random padding
			writer, err := ss.WriteTCPRequest(&tcp, m, psks, destination, salt, payload)
			must(err)
			request := append([]byte(nil), tcp.Bytes()...)
			aead, err := m.NewAEAD(ss.DeriveSessionSubKey(psks[len(psks)-1], salt, m.KeySaltLength))
			must(err)
			offset := m.KeySaltLength + (chains-1)*16
			fixedLen := ss.RequestHeaderFixedChunkLength + aead.Overhead()
			copy(request[offset:offset+fixedLen], fixedTimestamp(aead, make([]byte, aead.NonceSize()), request[offset:offset+fixedLen], 1))
			tcp.Reset()
			next := buf.New()
			next.Write([]byte("after-header"))
			must(writer.WriteMultiBuffer(buf.MultiBuffer{next}))

			crand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x22}, 4096))
			codec, err := ss.NewUDPPacketCodec(m, psks)
			must(err)
			session, err := codec.NewClientSession()
			must(err)
			udpPayload := []byte("udp-payload")
			packet, err := session.EncodePacket(destination, udpPayload)
			must(err)
			wire := append([]byte(nil), packet.Bytes()...)
			packet.Release()
			nonce := ""
			if m.IsChaCha {
				cipher, err := m.NewUDPCipher(psks[0])
				must(err)
				nonce = hex.EncodeToString(wire[:24])
				copy(wire[24:], fixedTimestamp(cipher, wire[:24], wire[24:], 17))
			} else {
				var rawHeader [16]byte
				binary.BigEndian.PutUint64(rawHeader[:8], session.ClientSessionID())
				cipher, err := m.NewAEAD(ss.DeriveSessionSubKey(psks[len(psks)-1], rawHeader[:8], m.KeySaltLength))
				must(err)
				offset := chains * 16
				copy(wire[offset:], fixedTimestamp(cipher, rawHeader[4:16], wire[offset:], 1))
			}

			// The server reply to that client session, encoded by Xray's own
			// server codec. A distinct random stream keeps the server session id
			// apart from the client's, which a client rejects as reflected.
			crand.Reader = bytes.NewReader(bytes.Repeat([]byte{0x33}, 4096))
			userPSK := psks[len(psks)-1]
			server, err := ss.NewUDPServerCodec(m, userPSK, time.Minute)
			must(err)
			responsePayload := []byte("udp-response")
			response, err := server.EncodeServerPacket(session.ClientSessionID(), net.UDPDestination(net.ParseAddress("2001:db8::8"), 53), responsePayload)
			must(err)
			if m.IsChaCha {
				cipher, err := m.NewUDPCipher(userPSK)
				must(err)
				copy(response[24:], fixedTimestamp(cipher, response[:24], response[24:], 17))
			} else {
				var rawHeader [16]byte
				binary.BigEndian.PutUint64(rawHeader[:8], server.GetSession(session.ClientSessionID()).ServerSessionID)
				cipher, err := m.NewAEAD(ss.DeriveSessionSubKey(userPSK, rawHeader[:8], m.KeySaltLength))
				must(err)
				copy(response[16:], fixedTimestamp(cipher, rawHeader[4:16], response[16:], 1))
			}
			cases = append(cases, map[string]any{"method": method, "password": password, "timestamp": 1700000000, "address": "example.test", "port": 443,
				"salt": hex.EncodeToString(salt), "payload": hex.EncodeToString(payload), "request": hex.EncodeToString(request), "nextRecord": hex.EncodeToString(tcp.Bytes()),
				"udpSessionId": session.ClientSessionID(), "udpNonce": nonce, "udpPayload": hex.EncodeToString(udpPayload), "udpWire": hex.EncodeToString(wire),
				"udpResponsePayload": hex.EncodeToString(responsePayload), "udpResponseWire": hex.EncodeToString(response)})
		}
	}
	return cases
}

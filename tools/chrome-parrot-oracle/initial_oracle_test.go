package hysteria

// The first datagrams Xray-core's own Hysteria dialer sends with its default
// ChromeParrot QUIC stack, and every crypto/rand read behind them.
//
// scripts/check-chrome-parrot-interop.sh adds this file to the pinned
// checkout's transport/internet/hysteria package with `go test -overlay`,
// without touching the checkout, so the dial below is Xray's own
// `client.dial`: its quic.Config, its Transport with the zero-length
// connection ID generator and its TLS config. testing/cryptotest makes every
// source of cryptographic randomness deterministic, so the run reproduces
// the fixture exactly; a wrapper around crypto/rand.Reader records each read
// that goes through it, with the quic-go or uTLS function that asked, so the
// Rust side can replay the same draws.
//
// The dial goes to a UDP socket that never answers. Each Initial is decrypted
// with the keys its destination connection ID derives (RFC 9001 section 5.2)
// and taken apart: header, frames in order, the ClientHello the CRYPTO frames
// reassemble, its extensions and the QUIC transport parameters.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	gonet "net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/cryptotest"
	"time"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/tls"
)

const (
	oracleServerName = "chrome-parrot.example"
	// The first flight and the first retransmission of it.
	oracleDatagrams = 4
)

type oracleRandomRead struct {
	Source string `json:"source"`
	Hex    string `json:"hex"`
}

type oracleFrame struct {
	Type   string `json:"type"`
	Offset uint64 `json:"offset,omitempty"`
	Length int    `json:"length,omitempty"`
}

type oracleDatagram struct {
	Hex             string        `json:"hex"`
	FirstByte       byte          `json:"first_byte"`
	Version         string        `json:"version"`
	DCID            string        `json:"dcid"`
	SCID            string        `json:"scid"`
	TokenLength     int           `json:"token_length"`
	Length          int           `json:"length"`
	PacketNumberLen int           `json:"packet_number_length"`
	PacketNumber    uint64        `json:"packet_number"`
	Payload         string        `json:"payload"`
	Frames          []oracleFrame `json:"frames"`
}

type oracleExtension struct {
	Type uint16 `json:"type"`
	Data string `json:"data"`
}

type oracleTransportParameter struct {
	ID    uint64 `json:"id"`
	Value string `json:"value"`
}

type oracleCase struct {
	Seed                uint64                     `json:"seed"`
	RandomReads         []oracleRandomRead         `json:"random_reads"`
	Datagrams           []oracleDatagram           `json:"datagrams"`
	ClientHello         string                     `json:"client_hello"`
	ClientHelloRandom   string                     `json:"client_hello_random"`
	SessionID           string                     `json:"session_id"`
	CipherSuites        []uint16                   `json:"cipher_suites"`
	Extensions          []oracleExtension          `json:"extensions"`
	TransportParameters []oracleTransportParameter `json:"transport_parameters"`
}

type oracleFixture struct {
	XrayCore   string       `json:"xray_core"`
	QuicGo     string       `json:"quic_go"`
	ServerName string       `json:"server_name"`
	Cases      []oracleCase `json:"cases"`
}

// recordingReader passes crypto/rand reads through to the deterministic
// reader cryptotest installed and remembers them.
type recordingReader struct {
	mu    sync.Mutex
	inner io.Reader
	reads []oracleRandomRead
}

func (r *recordingReader) Read(b []byte) (int, error) {
	n, err := r.inner.Read(b)
	r.mu.Lock()
	r.reads = append(r.reads, oracleRandomRead{Source: randomSource(), Hex: hex.EncodeToString(b[:n])})
	r.mu.Unlock()
	return n, err
}

// randomSource names the innermost quic-go or uTLS function behind a read.
func randomSource() string {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(3, pcs)])
	for {
		frame, more := frames.Next()
		name := frame.Function
		for _, module := range []string{"github.com/apernet/quic-go", "github.com/refraction-networking/utls"} {
			if strings.HasPrefix(name, module) {
				return name
			}
		}
		if !more {
			return "unknown"
		}
	}
}

func TestXrayRustChromeParrotOracle(t *testing.T) {
	out := os.Getenv("CHROME_PARROT_ORACLE_OUT")
	if out == "" {
		t.Skip("CHROME_PARROT_ORACLE_OUT is not set")
	}
	fixture := oracleFixture{
		XrayCore:   "a4a3dff5b20c2faae567b742c172c7b95e75c083",
		QuicGo:     "github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e",
		ServerName: oracleServerName,
	}
	for _, seed := range []uint64{1, 2, 3, 4, 5, 6, 7, 8} {
		fixture.Cases = append(fixture.Cases, oracleRun(t, seed))
	}
	encoded, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(encoded, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func oracleRun(t *testing.T, seed uint64) oracleCase {
	cryptotest.SetGlobalRandom(t, seed)
	recorder := &recordingReader{inner: cryptorand.Reader}
	cryptorand.Reader = recorder

	listener, err := gonet.ListenUDP("udp", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	received := make(chan []byte, oracleDatagrams)
	go func() {
		buf := make([]byte, 65536)
		for {
			n, _, err := listener.ReadFromUDP(buf)
			if err != nil {
				return
			}
			select {
			case received <- append([]byte(nil), buf[:n]...):
			default:
			}
		}
	}()

	port := listener.LocalAddr().(*gonet.UDPAddr).Port
	dest := net.UDPDestination(net.LocalHostIP, net.Port(port))
	c := &client{
		lock:      make(chan struct{}, 1),
		dest:      dest,
		config:    &Config{Auth: "chrome-parrot-oracle"},
		tlsConfig: (&tls.Config{ServerName: oracleServerName}).GetTLSConfig(tls.WithDestination(dest)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	dialed := make(chan error, 1)
	go func() { dialed <- c.dial(ctx) }()

	var datagrams [][]byte
	deadline := time.After(5 * time.Second)
	for len(datagrams) < oracleDatagrams {
		select {
		case d := <-received:
			datagrams = append(datagrams, d)
		case <-deadline:
			t.Fatalf("seed %d: only %d datagrams arrived", seed, len(datagrams))
		}
	}
	cancel()
	<-dialed

	recorder.mu.Lock()
	reads := append([]oracleRandomRead(nil), recorder.reads...)
	recorder.mu.Unlock()

	result := oracleCase{Seed: seed, RandomReads: reads}
	crypto := map[uint64][]byte{}
	for i, d := range datagrams {
		parsed, frames, err := parseInitial(d)
		if err != nil {
			t.Fatalf("seed %d datagram %d: %v", seed, i, err)
		}
		result.Datagrams = append(result.Datagrams, parsed)
		for _, f := range frames {
			if prev, ok := crypto[f.offset]; !ok || len(prev) < len(f.data) {
				crypto[f.offset] = f.data
			}
		}
	}
	hello, err := reassemble(crypto)
	if err != nil {
		t.Fatalf("seed %d: %v", seed, err)
	}
	result.ClientHello = hex.EncodeToString(hello)
	if err := describeClientHello(hello, &result); err != nil {
		t.Fatalf("seed %d: %v", seed, err)
	}
	return result
}

type cryptoData struct {
	offset uint64
	data   []byte
}

func hkdfExpandLabel(secret []byte, label string, length int) []byte {
	info := make([]byte, 0, 4+len(label)+6)
	info = binary.BigEndian.AppendUint16(info, uint16(length))
	info = append(info, byte(len("tls13 "+label)))
	info = append(info, "tls13 "+label...)
	info = append(info, 0)
	out, err := hkdf.Expand(sha256.New, secret, string(info), length)
	if err != nil {
		panic(err)
	}
	return out
}

// QUIC v1's initial salt, RFC 9001 section 5.2.
var initialSaltV1 = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
}

func readVarint(b []byte) (uint64, int, error) {
	if len(b) == 0 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	n := 1 << (b[0] >> 6)
	if len(b) < n {
		return 0, 0, io.ErrUnexpectedEOF
	}
	v := uint64(b[0] & 0x3f)
	for i := 1; i < n; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v, n, nil
}

func parseInitial(d []byte) (oracleDatagram, []cryptoData, error) {
	out := oracleDatagram{Hex: hex.EncodeToString(d)}
	if len(d) < 7 || d[0]&0xc0 != 0xc0 {
		return out, nil, errors.New("not a long header")
	}
	pos := 1
	version := d[pos : pos+4]
	out.Version = hex.EncodeToString(version)
	pos += 4
	dcidLen := int(d[pos])
	pos++
	dcid := d[pos : pos+dcidLen]
	out.DCID = hex.EncodeToString(dcid)
	pos += dcidLen
	scidLen := int(d[pos])
	pos++
	out.SCID = hex.EncodeToString(d[pos : pos+scidLen])
	pos += scidLen
	tokenLen, n, err := readVarint(d[pos:])
	if err != nil {
		return out, nil, err
	}
	out.TokenLength = int(tokenLen)
	pos += n + int(tokenLen)
	length, n, err := readVarint(d[pos:])
	if err != nil {
		return out, nil, err
	}
	out.Length = int(length)
	pos += n
	pnOffset := pos
	if pnOffset+int(length) != len(d) {
		return out, nil, fmt.Errorf("one packet per datagram expected: %d+%d != %d", pnOffset, length, len(d))
	}

	initialSecret, err := hkdf.Extract(sha256.New, dcid, initialSaltV1)
	if err != nil {
		return out, nil, err
	}
	clientSecret := hkdfExpandLabel(initialSecret, "client in", 32)
	key := hkdfExpandLabel(clientSecret, "quic key", 16)
	iv := hkdfExpandLabel(clientSecret, "quic iv", 12)
	hp := hkdfExpandLabel(clientSecret, "quic hp", 16)

	block, err := aes.NewCipher(hp)
	if err != nil {
		return out, nil, err
	}
	mask := make([]byte, 16)
	block.Encrypt(mask, d[pnOffset+4:pnOffset+20])
	header := append([]byte(nil), d[:pnOffset+4]...)
	header[0] ^= mask[0] & 0x0f
	pnLen := int(header[0]&0x03) + 1
	var pn uint64
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[1+i]
		pn = pn<<8 | uint64(header[pnOffset+i])
	}
	header = header[:pnOffset+pnLen]
	out.FirstByte = header[0]
	out.PacketNumberLen = pnLen
	out.PacketNumber = pn

	aeadBlock, err := aes.NewCipher(key)
	if err != nil {
		return out, nil, err
	}
	aead, err := cipher.NewGCM(aeadBlock)
	if err != nil {
		return out, nil, err
	}
	nonce := append([]byte(nil), iv...)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(pn >> (8 * i))
	}
	payload, err := aead.Open(nil, nonce, d[pnOffset+pnLen:], header)
	if err != nil {
		return out, nil, err
	}
	out.Payload = hex.EncodeToString(payload)

	var crypto []cryptoData
	for p := 0; p < len(payload); {
		switch payload[p] {
		case 0x00:
			start := p
			for p < len(payload) && payload[p] == 0 {
				p++
			}
			out.Frames = append(out.Frames, oracleFrame{Type: "padding", Length: p - start})
		case 0x01:
			out.Frames = append(out.Frames, oracleFrame{Type: "ping"})
			p++
		case 0x06:
			p++
			offset, n, err := readVarint(payload[p:])
			if err != nil {
				return out, nil, err
			}
			p += n
			dataLen, n, err := readVarint(payload[p:])
			if err != nil {
				return out, nil, err
			}
			p += n
			if p+int(dataLen) > len(payload) {
				return out, nil, io.ErrUnexpectedEOF
			}
			crypto = append(crypto, cryptoData{offset: offset, data: payload[p : p+int(dataLen)]})
			out.Frames = append(out.Frames, oracleFrame{Type: "crypto", Offset: offset, Length: int(dataLen)})
			p += int(dataLen)
		default:
			return out, nil, fmt.Errorf("unexpected frame type 0x%02x", payload[p])
		}
	}
	return out, crypto, nil
}

func reassemble(pieces map[uint64][]byte) ([]byte, error) {
	offsets := make([]uint64, 0, len(pieces))
	for offset := range pieces {
		offsets = append(offsets, offset)
	}
	sort.Slice(offsets, func(i, j int) bool { return offsets[i] < offsets[j] })
	var out []byte
	for _, offset := range offsets {
		data := pieces[offset]
		end := offset + uint64(len(data))
		if offset > uint64(len(out)) {
			return nil, fmt.Errorf("gap in CRYPTO data at %d", len(out))
		}
		if end > uint64(len(out)) {
			out = append(out, data[uint64(len(out))-offset:]...)
		}
	}
	if len(out) < 4 || out[0] != 1 {
		return nil, errors.New("CRYPTO data is not a ClientHello")
	}
	total := 4 + (int(out[1])<<16 | int(out[2])<<8 | int(out[3]))
	if len(out) != total {
		return nil, fmt.Errorf("ClientHello is %d bytes, CRYPTO data %d", total, len(out))
	}
	return out, nil
}

func describeClientHello(hello []byte, out *oracleCase) error {
	b := hello[4:]
	if len(b) < 35 {
		return io.ErrUnexpectedEOF
	}
	out.ClientHelloRandom = hex.EncodeToString(b[2:34])
	b = b[34:]
	sidLen := int(b[0])
	out.SessionID = hex.EncodeToString(b[1 : 1+sidLen])
	b = b[1+sidLen:]
	suitesLen := int(binary.BigEndian.Uint16(b))
	for i := 0; i < suitesLen; i += 2 {
		out.CipherSuites = append(out.CipherSuites, binary.BigEndian.Uint16(b[2+i:]))
	}
	b = b[2+suitesLen:]
	b = b[1+int(b[0]):]
	extLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) != extLen {
		return fmt.Errorf("extensions are %d bytes, %d remain", extLen, len(b))
	}
	for len(b) > 0 {
		typ := binary.BigEndian.Uint16(b)
		l := int(binary.BigEndian.Uint16(b[2:]))
		data := b[4 : 4+l]
		out.Extensions = append(out.Extensions, oracleExtension{Type: typ, Data: hex.EncodeToString(data)})
		if typ == 0x39 {
			for p := 0; p < len(data); {
				id, n, err := readVarint(data[p:])
				if err != nil {
					return err
				}
				p += n
				vl, n, err := readVarint(data[p:])
				if err != nil {
					return err
				}
				p += n
				out.TransportParameters = append(out.TransportParameters, oracleTransportParameter{
					ID:    id,
					Value: hex.EncodeToString(data[p : p+int(vl)]),
				})
				p += int(vl)
			}
		}
		b = b[4+l:]
	}
	return nil
}

//go:build reality_oracle_clienthello

// This oracle is intentionally invoked with `go run ./tools/reality-oracle/clienthello_fixture.go`.
// The build tag keeps default package tooling from compiling multiple standalone
// main files in tools/reality-oracle while still letting go mod tidy see uTLS.

package main

import (
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"

	utls "github.com/refraction-networking/utls"
)

const (
	fingerprintChrome = "chrome"
	serverName        = "example.com"

	clientHelloHandshakeType = byte(0x01)
	realitySessionIDOffset   = 39
	realitySessionIDLen      = 32

	extensionKeyShare   = uint16(0x0033)
	groupX25519         = uint16(0x001d)
	groupX25519MLKEM768 = uint16(0x11ec)

	x25519PublicKeyLen             = 32
	x25519MLKEM768KeyExchangeLen   = 1216
	mlkem768EncapsulationKeyLength = 1184
)

type deterministicReader struct{}

func (r *deterministicReader) Read(out []byte) (int, error) {
	for i := range out {
		out[i] = byte(i)
	}
	return len(out), nil
}

type zeroReader struct{}

func (zeroReader) Read(out []byte) (int, error) {
	clear(out)
	return len(out), nil
}

type clientHelloFixture struct {
	Fingerprint                   string `json:"fingerprint"`
	ServerName                    string `json:"server_name"`
	RawClientHelloHex             string `json:"raw_client_hello_hex"`
	HelloRandomHex                string `json:"hello_random_hex"`
	SessionIDOffset               int    `json:"session_id_offset"`
	LocalX25519PrivateKeyHex      string `json:"local_x25519_private_key_hex"`
	KeyShareGroup                 string `json:"key_share_group"`
	KeyShareX25519PublicKeyOffset int    `json:"key_share_x25519_public_key_offset"`
	KeyShareX25519PublicKeyHex    string `json:"key_share_x25519_public_key_hex"`
}

func main() {
	checkPath := flag.String("check", "", "compare generated fixture with a committed JSON file")
	flag.Parse()

	fixture, err := buildFixture()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build fixture: %v\n", err)
		os.Exit(1)
	}

	generated, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal fixture: %v\n", err)
		os.Exit(1)
	}
	generated = append(generated, '\n')

	if *checkPath == "" {
		_, _ = os.Stdout.Write(generated)
		return
	}

	expected, err := os.ReadFile(*checkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read fixture: %v\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(expected, generated) {
		fmt.Fprintf(os.Stderr, "fixture mismatch: %s\n", *checkPath)
		os.Exit(1)
	}
}

func buildFixture() (clientHelloFixture, error) {
	previousRand := cryptoRand.Reader
	cryptoRand.Reader = zeroReader{}
	defer func() { cryptoRand.Reader = previousRand }()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	config := &utls.Config{
		ServerName: serverName,
		Rand:       &deterministicReader{},
	}
	uConn := utls.UClient(clientConn, config, utls.HelloChrome_Auto)
	if err := uConn.BuildHandshakeState(); err != nil {
		return clientHelloFixture{}, err
	}

	hello := uConn.HandshakeState.Hello
	if hello == nil {
		return clientHelloFixture{}, errors.New("uTLS did not build a ClientHello")
	}
	if len(hello.Raw) < realitySessionIDOffset+realitySessionIDLen {
		return clientHelloFixture{}, fmt.Errorf("raw ClientHello too short: %d", len(hello.Raw))
	}
	if hello.Raw[0] != clientHelloHandshakeType {
		return clientHelloFixture{}, fmt.Errorf("unexpected handshake type: 0x%02x", hello.Raw[0])
	}
	if len(hello.Random) != 32 {
		return clientHelloFixture{}, fmt.Errorf("unexpected ClientHello random length: %d", len(hello.Random))
	}

	hello.SessionId = make([]byte, realitySessionIDLen)
	copy(hello.Raw[realitySessionIDOffset:], hello.SessionId)

	keys := uConn.HandshakeState.State13.KeyShareKeys
	if keys == nil {
		return clientHelloFixture{}, errors.New("uTLS did not expose TLS 1.3 key-share keys")
	}
	ecdhe := keys.Ecdhe
	if ecdhe == nil {
		ecdhe = keys.MlkemEcdhe
	}
	if ecdhe == nil {
		return clientHelloFixture{}, errors.New("uTLS emitted neither Ecdhe nor MlkemEcdhe key material")
	}

	localPrivateKey := ecdhe.Bytes()
	localPublicKey := ecdhe.PublicKey().Bytes()
	group, publicOffset, err := locateX25519KeyShare(hello.Raw, localPublicKey)
	if err != nil {
		return clientHelloFixture{}, err
	}

	return clientHelloFixture{
		Fingerprint:                   fingerprintChrome,
		ServerName:                    serverName,
		RawClientHelloHex:             hex.EncodeToString(hello.Raw),
		HelloRandomHex:                hex.EncodeToString(hello.Random),
		SessionIDOffset:               realitySessionIDOffset,
		LocalX25519PrivateKeyHex:      hex.EncodeToString(localPrivateKey),
		KeyShareGroup:                 group,
		KeyShareX25519PublicKeyOffset: publicOffset,
		KeyShareX25519PublicKeyHex:    hex.EncodeToString(localPublicKey),
	}, nil
}

func locateX25519KeyShare(raw []byte, x25519PublicKey []byte) (string, int, error) {
	var matchedGroup string
	var matchedOffset int
	foundMatch := false

	cursor := byteCursor{raw: raw}
	handshakeType, err := cursor.readU8("missing handshake type")
	if err != nil {
		return "", 0, err
	}
	if handshakeType != int(clientHelloHandshakeType) {
		return "", 0, fmt.Errorf("not a ClientHello handshake: 0x%02x", handshakeType)
	}
	handshakeLen, err := cursor.readU24("missing handshake length")
	if err != nil {
		return "", 0, err
	}
	if handshakeLen != len(raw)-4 {
		return "", 0, fmt.Errorf("handshake length mismatch: header=%d raw=%d", handshakeLen, len(raw)-4)
	}
	if _, err := cursor.take(2, "missing legacy version"); err != nil {
		return "", 0, err
	}
	if _, err := cursor.take(32, "missing ClientHello random"); err != nil {
		return "", 0, err
	}
	sessionIDLen, err := cursor.readU8("missing legacy session id length")
	if err != nil {
		return "", 0, err
	}
	if _, err := cursor.take(sessionIDLen, "truncated legacy session id"); err != nil {
		return "", 0, err
	}
	cipherSuitesLen, err := cursor.readU16("missing cipher suites length")
	if err != nil {
		return "", 0, err
	}
	if _, err := cursor.take(cipherSuitesLen, "truncated cipher suites"); err != nil {
		return "", 0, err
	}
	compressionMethodsLen, err := cursor.readU8("missing compression methods length")
	if err != nil {
		return "", 0, err
	}
	if _, err := cursor.take(compressionMethodsLen, "truncated compression methods"); err != nil {
		return "", 0, err
	}
	extensionsLen, err := cursor.readU16("missing extensions length")
	if err != nil {
		return "", 0, err
	}
	extensionsEnd, err := cursor.checkedEnd(extensionsLen, "truncated extensions")
	if err != nil {
		return "", 0, err
	}
	if extensionsEnd != len(raw) {
		return "", 0, fmt.Errorf("extensions length mismatch: ended at %d expected raw length %d", extensionsEnd, len(raw))
	}

	for cursor.offset < extensionsEnd {
		extensionType, err := cursor.readU16("missing extension type")
		if err != nil {
			return "", 0, err
		}
		extensionLen, err := cursor.readU16("missing extension length")
		if err != nil {
			return "", 0, err
		}
		if cursor.offset+extensionLen > extensionsEnd {
			return "", 0, fmt.Errorf("extension overruns declared extensions: type=0x%04x offset=%d length=%d end=%d", extensionType, cursor.absoluteOffset(), extensionLen, cursor.base+extensionsEnd)
		}
		extensionDataOffset := cursor.absoluteOffset()
		extensionData, err := cursor.take(extensionLen, "truncated extension data")
		if err != nil {
			return "", 0, err
		}
		if extensionType == int(extensionKeyShare) {
			group, offset, err := locateX25519InKeyShareExtension(extensionData, extensionDataOffset, x25519PublicKey)
			if err != nil {
				return "", 0, err
			}
			if !foundMatch {
				matchedGroup = group
				matchedOffset = offset
				foundMatch = true
			}
		}
	}
	if cursor.offset != extensionsEnd {
		return "", 0, fmt.Errorf("extensions length mismatch: ended at %d expected %d", cursor.offset, extensionsEnd)
	}
	if foundMatch {
		return matchedGroup, matchedOffset, nil
	}

	return "", 0, errors.New("key_share extension not found")
}

func locateX25519InKeyShareExtension(extensionData []byte, extensionOffset int, x25519PublicKey []byte) (string, int, error) {
	var matchedGroup string
	var matchedOffset int
	foundMatch := false

	cursor := byteCursor{raw: extensionData, base: extensionOffset}
	sharesLen, err := cursor.readU16("missing key_share client_shares length")
	if err != nil {
		return "", 0, err
	}
	sharesEnd, err := cursor.checkedEnd(sharesLen, "truncated key_share client_shares")
	if err != nil {
		return "", 0, err
	}
	if sharesEnd != len(extensionData) {
		return "", 0, fmt.Errorf("key_share client_shares length mismatch: shares end at %d, extension length is %d", cursor.base+sharesEnd, len(extensionData))
	}

	for cursor.offset < sharesEnd {
		group, err := cursor.readU16("missing key_share group")
		if err != nil {
			return "", 0, err
		}
		keyExchangeLen, err := cursor.readU16("missing key_exchange length")
		if err != nil {
			return "", 0, err
		}
		keyExchangeOffset := cursor.absoluteOffset()
		keyExchange, err := cursor.take(keyExchangeLen, "truncated key_exchange")
		if err != nil {
			return "", 0, err
		}

		switch group {
		case int(groupX25519):
			if len(keyExchange) != x25519PublicKeyLen {
				return "", 0, fmt.Errorf("X25519 key_exchange length mismatch: got %d want %d", len(keyExchange), x25519PublicKeyLen)
			}
			if bytes.Equal(keyExchange, x25519PublicKey) {
				if !foundMatch {
					matchedGroup = "x25519"
					matchedOffset = keyExchangeOffset
					foundMatch = true
				}
			}
		case int(groupX25519MLKEM768):
			if len(keyExchange) != x25519MLKEM768KeyExchangeLen {
				return "", 0, fmt.Errorf("X25519MLKEM768 key_exchange length mismatch: got %d want %d", len(keyExchange), x25519MLKEM768KeyExchangeLen)
			}
			publicOffset := keyExchangeOffset + mlkem768EncapsulationKeyLength
			publicKey := keyExchange[mlkem768EncapsulationKeyLength:]
			if bytes.Equal(publicKey, x25519PublicKey) {
				if !foundMatch {
					matchedGroup = "x25519mlkem768"
					matchedOffset = publicOffset
					foundMatch = true
				}
			}
		}
	}
	if cursor.offset != sharesEnd {
		return "", 0, fmt.Errorf("key_share length mismatch: ended at %d expected %d", cursor.offset, sharesEnd)
	}
	if foundMatch {
		return matchedGroup, matchedOffset, nil
	}

	return "", 0, errors.New("matching X25519 key_share not found")
}

type byteCursor struct {
	raw    []byte
	offset int
	base   int
}

func (c byteCursor) absoluteOffset() int {
	return c.base + c.offset
}

func (c byteCursor) checkedEnd(length int, message string) (int, error) {
	if length < 0 || c.offset+length > len(c.raw) {
		return 0, fmt.Errorf("%s: need %d bytes at offset %d, have %d", message, length, c.absoluteOffset(), len(c.raw)-c.offset)
	}
	return c.offset + length, nil
}

func (c *byteCursor) take(length int, message string) ([]byte, error) {
	end, err := c.checkedEnd(length, message)
	if err != nil {
		return nil, err
	}
	out := c.raw[c.offset:end]
	c.offset = end
	return out, nil
}

func (c *byteCursor) readU8(message string) (int, error) {
	bytes, err := c.take(1, message)
	if err != nil {
		return 0, err
	}
	return int(bytes[0]), nil
}

func (c *byteCursor) readU16(message string) (int, error) {
	bytes, err := c.take(2, message)
	if err != nil {
		return 0, err
	}
	return int(bytes[0])<<8 | int(bytes[1]), nil
}

func (c *byteCursor) readU24(message string) (int, error) {
	bytes, err := c.take(3, message)
	if err != nil {
		return 0, err
	}
	return int(bytes[0])<<16 | int(bytes[1])<<8 | int(bytes[2]), nil
}

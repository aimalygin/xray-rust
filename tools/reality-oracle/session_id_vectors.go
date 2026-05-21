package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type vector struct {
	Name                        string `json:"name"`
	VersionHex                  string `json:"version_hex"`
	UnixTime                    uint32 `json:"unix_time"`
	ShortIDHex                  string `json:"short_id_hex"`
	SharedSecretHex             string `json:"shared_secret_hex"`
	HelloRandomHex              string `json:"hello_random_hex"`
	SessionIDOffset             int    `json:"session_id_offset"`
	RawClientHelloBeforeHex     string `json:"raw_client_hello_before_hex"`
	ExpectedSessionIDHex        string `json:"expected_session_id_hex"`
	ExpectedClientHelloAfterHex string `json:"expected_client_hello_after_hex"`
}

type input struct {
	name            string
	version         []byte
	unixTime        uint32
	shortID         []byte
	sharedSecret    []byte
	helloRandom     []byte
	sessionIDOffset int
	rawClientHello  []byte
}

func main() {
	checkPath := flag.String("check", "", "compare generated vectors with a committed JSON fixture")
	flag.Parse()

	generated, err := json.MarshalIndent(buildVectors(), "", "  ")
	if err != nil {
		panic(err)
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

func buildVectors() []vector {
	xrayHelloRandom := append(repeat(0x09, 20), repeat(0x0b, 12)...)

	return []vector{
		buildVector(input{
			name:            "xray_offset_39_short_id_4",
			version:         []byte{26, 5, 9},
			unixTime:        1700000000,
			shortID:         []byte{2, 3, 4, 5},
			sharedSecret:    repeat(0x07, 32),
			helloRandom:     xrayHelloRandom,
			sessionIDOffset: 39,
			rawClientHello:  xrayOffset39ClientHello(xrayHelloRandom),
		}),
		buildVector(input{
			name:            "explicit_offset_13_short_id_8",
			version:         []byte{1, 2, 3},
			unixTime:        42,
			shortID:         []byte{0, 1, 2, 3, 4, 5, 6, 7},
			sharedSecret:    sequence(0x00, 32),
			helloRandom:     sequence(0x20, 32),
			sessionIDOffset: 13,
			rawClientHello:  offset13ClientHello(),
		}),
	}
}

func buildVector(in input) vector {
	sessionID := sealSessionID(in.version, in.unixTime, in.shortID, in.sharedSecret, in.helloRandom, in.rawClientHello)
	patched := append([]byte(nil), in.rawClientHello...)
	copy(patched[in.sessionIDOffset:in.sessionIDOffset+32], sessionID)

	return vector{
		Name:                        in.name,
		VersionHex:                  hex.EncodeToString(in.version),
		UnixTime:                    in.unixTime,
		ShortIDHex:                  hex.EncodeToString(in.shortID),
		SharedSecretHex:             hex.EncodeToString(in.sharedSecret),
		HelloRandomHex:              hex.EncodeToString(in.helloRandom),
		SessionIDOffset:             in.sessionIDOffset,
		RawClientHelloBeforeHex:     hex.EncodeToString(in.rawClientHello),
		ExpectedSessionIDHex:        hex.EncodeToString(sessionID),
		ExpectedClientHelloAfterHex: hex.EncodeToString(patched),
	}
}

func sealSessionID(version []byte, unixTime uint32, shortID []byte, sharedSecret []byte, helloRandom []byte, rawClientHello []byte) []byte {
	prefix := make([]byte, 16)
	copy(prefix[0:3], version)
	binary.BigEndian.PutUint32(prefix[4:8], unixTime)
	copy(prefix[8:16], shortID)

	authKey := hkdfSha256(sharedSecret, helloRandom[:20], []byte("REALITY"), 32)
	block, err := aes.NewCipher(authKey)
	if err != nil {
		panic(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	return aead.Seal(nil, helloRandom[20:32], prefix, rawClientHello)
}

func hkdfSha256(secret []byte, salt []byte, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	prk := extract.Sum(nil)

	var okm []byte
	var previous []byte
	counter := byte(1)
	for len(okm) < length {
		expand := hmac.New(sha256.New, prk)
		expand.Write(previous)
		expand.Write(info)
		expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		okm = append(okm, previous...)
		counter++
	}

	return okm[:length]
}

func xrayOffset39ClientHello(helloRandom []byte) []byte {
	if len(helloRandom) != 32 {
		panic("xray ClientHello random must be 32 bytes")
	}

	// Xray-core seals utls `hello.Raw`, which starts at the TLS handshake
	// ClientHello message, not at the outer TLS record header.
	raw := []byte{0x01, 0x00, 0x00, 0x4f, 0x03, 0x03}
	raw = append(raw, helloRandom...)
	raw = append(raw, 0x20)
	raw = append(raw, repeat(0x00, 32)...)
	raw = append(raw, sequence(0xe0, 12)...)
	return raw
}

func offset13ClientHello() []byte {
	raw := sequence(0x30, 13)
	raw = append(raw, repeat(0x00, 32)...)
	raw = append(raw, sequence(0x70, 19)...)
	return raw
}

func repeat(value byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}

func sequence(start byte, length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = start + byte(i)
	}
	return out
}

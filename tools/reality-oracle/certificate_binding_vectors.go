//go:build reality_oracle_certificate_binding

// This oracle is invoked with
// `go run -tags reality_oracle_certificate_binding ./tools/reality-oracle/certificate_binding_vectors.go`.
// The build tag keeps default package tooling from compiling multiple standalone
// main files in tools/reality-oracle.
//
// It rebuilds the REALITY server leaf exactly as the pinned xtls/reality
// handshake_server_tls13.go does (an Ed25519 self-signed x509 certificate with
// serial 0 whose signature bytes are replaced by HMAC-SHA512(auth_key,
// ed25519_public_key)), using only the Go standard library. Xray-core
// v26.10.21 (commit 1b1647cd9ddf0abc34b981d4611fc03bcac1ca74) accepts the
// same binding in transport/internet/reality/reality.go. The Ed25519 key comes
// from a fixed seed so the vectors are reproducible.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
)

type vector struct {
	Name                    string `json:"name"`
	AuthKeyHex              string `json:"auth_key_hex"`
	Ed25519PublicHex        string `json:"ed25519_public_hex"`
	CertificateSignatureHex string `json:"certificate_signature_hex"`
	LeafDerHex              string `json:"leaf_der_hex"`
}

type input struct {
	name        string
	authKey     []byte
	ed25519Seed []byte
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
	return []vector{
		buildVector(input{
			name:        "sequence_auth_key_seed_42",
			authKey:     sequence(0x00, 32),
			ed25519Seed: repeat(0x42, 32),
		}),
		buildVector(input{
			name:        "repeat_auth_key_seed_sequence",
			authKey:     repeat(0xa5, 32),
			ed25519Seed: sequence(0x80, 32),
		}),
	}
}

func buildVector(in input) vector {
	private := ed25519.NewKeyFromSeed(in.ed25519Seed)
	public := private.Public().(ed25519.PublicKey)

	// Mirrors xtls/reality's init(): an empty template with a zero serial.
	certificate := x509.Certificate{SerialNumber: &big.Int{}}
	// Ed25519 signing is deterministic; a failing reader proves no randomness
	// enters the certificate.
	leaf, err := x509.CreateCertificate(failingReader{}, &certificate, &certificate, public, private)
	if err != nil {
		panic(err)
	}

	// Mirrors handshake_server_tls13.go: the HMAC overwrites the trailing
	// 64-byte Ed25519 signature inside the certificate DER.
	h := hmac.New(sha512.New, in.authKey)
	h.Write(public)
	h.Sum(leaf[:len(leaf)-64])

	return vector{
		Name:                    in.name,
		AuthKeyHex:              hex.EncodeToString(in.authKey),
		Ed25519PublicHex:        hex.EncodeToString(public),
		CertificateSignatureHex: hex.EncodeToString(leaf[len(leaf)-64:]),
		LeafDerHex:              hex.EncodeToString(leaf),
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) {
	return 0, errors.New("certificate generation must not read randomness")
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

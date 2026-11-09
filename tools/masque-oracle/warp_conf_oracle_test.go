// Records how Xray-core v26.10.31 reads masqueSettings.warp: its private
// key, public key and addresses, through infra/conf's parseWarpPrivateKey,
// parseWarpPublicKey and parseWarpAddress. Keys come from a seeded
// generator, so a fresh run matches tests/fixtures/masque/warp-config-vectors.json
// byte for byte. The keys are synthetic and worthless, but they are PEM
// private keys, so each input is stored XORed with 0x5a, in hex: secret
// scanners decode hex and base64, and these are test vectors, not secrets.
//
// It runs inside the package, added without touching the checkout:
//
//	go -C <pinned checkout> test -overlay overlay.json \
//	    ./infra/conf -run TestXrayRustWarpOracle
//
// where overlay.json maps infra/conf/xray_rust_warp_oracle_test.go to this
// file, and MASQUE_WARP_ORACLE_OUT names the output file.
package conf

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"math/rand/v2"
	"os"
	"strings"
	"testing"
)

type xrayRustWarpPrivate struct {
	Input string `json:"input"`
	// Scalar: the P-256 private scalar Xray keeps, when it takes the key.
	Scalar string `json:"scalar,omitempty"`
}

type xrayRustWarpPublic struct {
	Input string `json:"input"`
	OK    bool   `json:"ok"`
}

type xrayRustWarpAddress struct {
	Input  []string `json:"input"`
	Output []string `json:"output,omitempty"`
	OK     bool     `json:"ok"`
}

type xrayRustWarpVectors struct {
	Private   []xrayRustWarpPrivate `json:"private"`
	Public    []xrayRustWarpPublic  `json:"public"`
	Addresses []xrayRustWarpAddress `json:"addresses"`
}

type xrayRustWarpGen struct{ r *rand.Rand }

// xrayRustMask is an input as the fixture stores it: XOR 0x5a, in hex.
func xrayRustMask(input string) string {
	b := []byte(input)
	for i := range b {
		b[i] ^= 0x5a
	}
	return hex.EncodeToString(b)
}

func (g xrayRustWarpGen) bytes(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(g.r.Uint32())
	}
	return b
}

// scalar draws a valid scalar of the curve, of its full width.
func (g xrayRustWarpGen) scalar(c elliptic.Curve) []byte {
	n := c.Params().N
	for {
		b := g.bytes((n.BitLen() + 7) / 8)
		if k := new(big.Int).SetBytes(b); k.Sign() > 0 && k.Cmp(n) < 0 {
			return b
		}
	}
}

func (g xrayRustWarpGen) key(c elliptic.Curve) *ecdsa.PrivateKey {
	key, err := ecdsa.ParseRawPrivateKey(c, g.scalar(c))
	if err != nil {
		panic(err)
	}
	return key
}

func xrayRustMust[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// pemText armors der as encoding/pem does, with CRLF line ends on request.
func xrayRustPEM(kind string, der []byte, headers map[string]string, crlf bool) string {
	text := string(pem.EncodeToMemory(&pem.Block{Type: kind, Headers: headers, Bytes: der}))
	if crlf {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	return text
}

func xrayRustWrapped(s string, width int, sep string) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width])
		b.WriteString(sep)
		s = s[width:]
	}
	b.WriteString(s)
	return b.String()
}

// The EC private key structures, to build mutated ones.
type xrayRustECPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

type xrayRustAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type xrayRustPKCS8 struct {
	Version    int
	Algo       xrayRustAlgorithm
	PrivateKey []byte
}

var (
	xrayRustOIDEC   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	xrayRustOIDP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	xrayRustOIDP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
)

func xrayRustCurveOID(oid asn1.ObjectIdentifier) asn1.RawValue {
	return asn1.RawValue{FullBytes: xrayRustMust(asn1.Marshal(oid))}
}

// pkcs8EC wraps a SEC 1 structure as PKCS #8 with the given parameters.
func xrayRustPKCS8EC(version int, params *asn1.ObjectIdentifier, inner xrayRustECPrivateKey) []byte {
	algo := xrayRustAlgorithm{Algorithm: xrayRustOIDEC}
	if params != nil {
		algo.Parameters = xrayRustCurveOID(*params)
	}
	return xrayRustMust(asn1.Marshal(xrayRustPKCS8{
		Version: version, Algo: algo,
		PrivateKey: xrayRustMust(asn1.Marshal(inner)),
	}))
}

func (g xrayRustWarpGen) private(v *xrayRustWarpVectors) {
	add := func(input string) {
		result := xrayRustWarpPrivate{Input: xrayRustMask(input)}
		if der, err := parseWarpPrivateKey(input); err == nil {
			key := xrayRustMust(x509.ParsePKCS8PrivateKey(der)).(*ecdsa.PrivateKey)
			result.Scalar = hex.EncodeToString(xrayRustMust(key.Bytes()))
		}
		v.Private = append(v.Private, result)
	}
	b64 := base64.StdEncoding.EncodeToString
	p256 := xrayRustOIDP256
	p384 := xrayRustOIDP384

	// Well-formed keys in every form the parser reads.
	for i := range 6 {
		key := g.key(elliptic.P256())
		pkcs8 := xrayRustMust(x509.MarshalPKCS8PrivateKey(key))
		sec1 := xrayRustMust(x509.MarshalECPrivateKey(key))
		switch i {
		case 0:
			add(xrayRustPEM("PRIVATE KEY", pkcs8, nil, false))
			add(xrayRustPEM("EC PRIVATE KEY", sec1, nil, false))
			add(b64(pkcs8))
			add(b64(sec1))
		case 1:
			add(xrayRustWrapped(b64(pkcs8), 64, "\r\n"))
			add(xrayRustWrapped(b64(sec1), 76, "\n"))
			add(xrayRustPEM("WARP KEY", pkcs8, nil, true))
			add(" \t\n" + b64(pkcs8) + "\n\n")
		case 2:
			add(xrayRustPEM("EC PRIVATE KEY", sec1, map[string]string{"Comment": "a header"}, false))
			add("text before\n" + xrayRustPEM("PRIVATE KEY", pkcs8, nil, false) + "text after")
			add(strings.Replace(xrayRustPEM("PRIVATE KEY", pkcs8, nil, false), "END PRIVATE KEY", "END EC PRIVATE KEY", 1))
			add(strings.TrimSuffix(xrayRustPEM("PRIVATE KEY", pkcs8, nil, false), "-----END PRIVATE KEY-----\n"))
		case 3:
			s := b64(pkcs8)
			add(s[:len(s)/2] + " " + s[len(s)/2:])
			add(strings.TrimRight(s, "="))
			add(strings.NewReplacer("+", "-", "/", "_").Replace(s))
			add(base64.RawStdEncoding.EncodeToString(sec1))
		case 4:
			// A lenient final symbol: Go ignores the unused bits. SEC 1 keys
			// of P-256 are padded; PKCS #8 ones are not.
			s := b64(sec1)
			if i := strings.IndexByte(s, '='); i > 0 {
				c := s[i-1]
				const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
				s = s[:i-1] + string(alphabet[(strings.IndexByte(alphabet, c)+1)%64]) + s[i:]
			}
			add(s)
			add(xrayRustPEM("PRIVATE KEY", append(pkcs8, 0x05, 0x00), nil, false))
			add(b64(append(sec1, 0x00)))
		case 5:
			add("")
			add("   \n\t ")
			add("not a key at all")
			add(xrayRustPEM("PRIVATE KEY", nil, nil, false))
		}
	}

	// Structures around the scalar: versions, parameters, lengths and range.
	n := elliptic.P256().Params().N
	nBytes := n.FillBytes(make([]byte, 32))
	nMinus1 := new(big.Int).Sub(n, big.NewInt(1)).FillBytes(make([]byte, 32))
	for range 4 {
		key := g.key(elliptic.P256())
		scalar := xrayRustMust(key.Bytes())
		point := xrayRustMust(key.PublicKey.Bytes())
		pub := asn1.BitString{Bytes: point, BitLength: len(point) * 8}
		inner := func(version int, d []byte, oid asn1.ObjectIdentifier, pub asn1.BitString) xrayRustECPrivateKey {
			return xrayRustECPrivateKey{Version: version, PrivateKey: d, NamedCurveOID: oid, PublicKey: pub}
		}
		cases := [][]byte{
			xrayRustPKCS8EC(0, &p256, inner(1, scalar, nil, pub)),
			xrayRustPKCS8EC(1, &p256, inner(1, scalar, nil, pub)),
			xrayRustPKCS8EC(7, &p256, inner(1, scalar, nil, asn1.BitString{})),
			xrayRustPKCS8EC(0, nil, inner(1, scalar, p256, pub)),
			xrayRustPKCS8EC(0, nil, inner(1, scalar, nil, pub)),
			xrayRustPKCS8EC(0, &p384, inner(1, scalar, nil, pub)),
			xrayRustPKCS8EC(0, &p256, inner(2, scalar, nil, pub)),
			xrayRustPKCS8EC(0, &p256, inner(1, append([]byte{0}, scalar...), nil, pub)),
			xrayRustPKCS8EC(0, &p256, inner(1, append([]byte{1}, scalar...), nil, pub)),
			xrayRustPKCS8EC(0, &p256, inner(1, make([]byte, 32), nil, pub)),
			xrayRustPKCS8EC(0, &p256, inner(1, nBytes, nil, pub)),
			xrayRustPKCS8EC(0, &p256, inner(1, nMinus1, nil, pub)),
			xrayRustPKCS8EC(0, &p256, inner(1, scalar[1:], nil, pub)),
			xrayRustPKCS8EC(0, &p256, inner(1, scalar, p384, pub)),
			xrayRustPKCS8EC(0, &p256, inner(1, scalar, nil, asn1.BitString{Bytes: []byte{1, 2, 3}, BitLength: 24})),
			xrayRustMust(asn1.Marshal(inner(1, scalar, p256, pub))),
			xrayRustMust(asn1.Marshal(inner(1, scalar, p256, asn1.BitString{}))),
			xrayRustMust(asn1.Marshal(inner(1, scalar, nil, pub))),
			xrayRustMust(asn1.Marshal(inner(1, scalar, p384, pub))),
			xrayRustMust(asn1.Marshal(inner(0, scalar, p256, pub))),
		}
		for _, der := range cases {
			add(b64(der))
		}
		// A public key whose padding bits are set, which encoding/asn1
		// refuses inside the structure.
		bad := xrayRustMust(x509.MarshalPKCS8PrivateKey(key))
		if i := len(bad) - 66; i > 0 && bad[i] == 0 {
			bad[i] = 1
			add(b64(bad))
		}
	}

	// Other algorithms and curves, which Xray refuses.
	for _, c := range []elliptic.Curve{elliptic.P224(), elliptic.P384(), elliptic.P521()} {
		key := g.key(c)
		add(b64(xrayRustMust(x509.MarshalPKCS8PrivateKey(key))))
		add(xrayRustPEM("EC PRIVATE KEY", xrayRustMust(x509.MarshalECPrivateKey(key)), nil, false))
	}
	add(b64(xrayRustMust(x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(g.bytes(32))))))
	add(b64(xrayRustMust(x509.MarshalPKCS8PrivateKey(xrayRustMust(ecdh.X25519().NewPrivateKey(g.bytes(32)))))))
	add(b64(xrayRustMust(x509.MarshalPKIXPublicKey(&g.key(elliptic.P256()).PublicKey))))

	// Damaged encodings: truncated, flipped, re-encoded lengths.
	for range 40 {
		key := g.key(elliptic.P256())
		der := xrayRustMust(x509.MarshalPKCS8PrivateKey(key))
		if g.r.IntN(2) == 0 {
			der = xrayRustMust(x509.MarshalECPrivateKey(key))
		}
		switch g.r.IntN(4) {
		case 0:
			der = der[:g.r.IntN(len(der))]
		case 1:
			der[g.r.IntN(len(der))] ^= byte(1 + g.r.IntN(255))
		case 2:
			// The outer length in long form, which DER forbids.
			if der[1] < 0x80 {
				der = append([]byte{der[0], 0x81, der[1]}, der[2:]...)
			} else {
				der[1] = 0x80
			}
		case 3:
			der = append(der, g.bytes(1+g.r.IntN(8))...)
		}
		add(b64(der))
	}
}

func (g xrayRustWarpGen) public(v *xrayRustWarpVectors) {
	add := func(input string) {
		_, err := parseWarpPublicKey(input)
		v.Public = append(v.Public, xrayRustWarpPublic{Input: xrayRustMask(input), OK: err == nil})
	}
	b64 := base64.StdEncoding.EncodeToString
	spki := func(pub any) []byte { return xrayRustMust(x509.MarshalPKIXPublicKey(pub)) }

	for i := range 4 {
		key := g.key(elliptic.P256())
		der := spki(&key.PublicKey)
		add(xrayRustPEM("PUBLIC KEY", der, nil, i == 1))
		add(b64(der))
	}
	for _, c := range []elliptic.Curve{elliptic.P224(), elliptic.P384(), elliptic.P521()} {
		add(b64(spki(&g.key(c).PublicKey)))
	}
	add(b64(spki(ed25519.NewKeyFromSeed(g.bytes(32)).Public())))
	add(b64(spki(xrayRustMust(ecdh.X25519().NewPrivateKey(g.bytes(32))).PublicKey())))
	modulus := new(big.Int).SetBytes(append([]byte{0xc0}, g.bytes(255)...))
	modulus.SetBit(modulus, 0, 1)
	add(b64(spki(&rsa.PublicKey{N: modulus, E: 65537})))

	type algorithm struct {
		Algorithm  asn1.ObjectIdentifier
		Parameters asn1.RawValue `asn1:"optional"`
	}
	type info struct {
		Algorithm algorithm
		PublicKey asn1.BitString
	}
	raw := func(oid asn1.ObjectIdentifier, params []byte, key []byte, padding int) []byte {
		a := algorithm{Algorithm: oid}
		if params != nil {
			a.Parameters = asn1.RawValue{FullBytes: params}
		}
		return xrayRustMust(asn1.Marshal(info{Algorithm: a, PublicKey: asn1.BitString{Bytes: key, BitLength: len(key)*8 - padding}}))
	}
	null := []byte{5, 0}
	ecOID, p256 := xrayRustOIDEC, xrayRustMust(asn1.Marshal(xrayRustOIDP256))
	ed25519OID := asn1.ObjectIdentifier{1, 3, 101, 112}
	rsaOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	dsaOID := asn1.ObjectIdentifier{1, 2, 840, 10040, 4, 1}
	mldsa44OID := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}
	for range 3 {
		key := g.key(elliptic.P256())
		point := xrayRustMust(key.PublicKey.Bytes())
		x := point[1:33]
		compressed := append([]byte{2 + point[64]&1}, x...)
		offCurve := append([]byte(nil), point...)
		offCurve[64] ^= 1
		p := elliptic.P256().Params().P.FillBytes(make([]byte, 32))
		unreduced := append(append([]byte{4}, p...), point[33:]...)
		rsaKey := func(n, e *big.Int) []byte {
			return xrayRustMust(asn1.Marshal(struct{ N, E *big.Int }{n, e}))
		}
		dsaParams := func(p, q, g int64) []byte {
			return xrayRustMust(asn1.Marshal(struct{ P, Q, G *big.Int }{big.NewInt(p), big.NewInt(q), big.NewInt(g)}))
		}
		for _, der := range [][]byte{
			raw(ecOID, p256, point, 0),
			raw(ecOID, p256, compressed, 0),
			raw(ecOID, p256, offCurve, 0),
			raw(ecOID, p256, unreduced, 0),
			raw(ecOID, p256, point[:64], 0),
			raw(ecOID, null, point, 0),
			raw(ecOID, nil, point, 0),
			raw(ecOID, xrayRustMust(asn1.Marshal(asn1.ObjectIdentifier{1, 2, 3})), point, 0),
			raw(ecOID, p256, append([]byte{0}, point...), 4),
			append(raw(ecOID, p256, point, 0), 0),
			raw(ed25519OID, nil, g.bytes(32), 0),
			raw(ed25519OID, null, g.bytes(32), 0),
			raw(ed25519OID, nil, g.bytes(31), 0),
			raw(rsaOID, null, rsaKey(modulus, big.NewInt(3)), 0),
			raw(rsaOID, nil, rsaKey(modulus, big.NewInt(3)), 0),
			raw(rsaOID, null, rsaKey(new(big.Int).Neg(modulus), big.NewInt(3)), 0),
			raw(rsaOID, null, rsaKey(modulus, big.NewInt(0)), 0),
			raw(rsaOID, null, rsaKey(modulus, new(big.Int).Lsh(big.NewInt(1), 70)), 0),
			raw(rsaOID, null, append(rsaKey(modulus, big.NewInt(65537)), 1, 2), 0),
			raw(dsaOID, dsaParams(23, 11, 4), xrayRustMust(asn1.Marshal(big.NewInt(8))), 0),
			raw(dsaOID, dsaParams(23, 11, 0), xrayRustMust(asn1.Marshal(big.NewInt(8))), 0),
			raw(mldsa44OID, nil, g.bytes(1312), 0),
			raw(mldsa44OID, nil, g.bytes(1311), 0),
			raw(asn1.ObjectIdentifier{1, 2, 3, 4}, nil, g.bytes(32), 0),
		} {
			add(b64(der))
		}
	}
	add("")
	add(b64(xrayRustMust(x509.MarshalPKCS8PrivateKey(g.key(elliptic.P256())))))
	for range 20 {
		der := spki(&g.key(elliptic.P256()).PublicKey)
		switch g.r.IntN(3) {
		case 0:
			der = der[:g.r.IntN(len(der))]
		case 1:
			der[g.r.IntN(len(der))] ^= byte(1 + g.r.IntN(255))
		case 2:
			der = append(der, g.bytes(1+g.r.IntN(4))...)
		}
		add(b64(der))
	}
}

func xrayRustWarpAddresses(v *xrayRustWarpVectors) {
	for _, list := range [][]string{
		{"172.16.0.2/32", "fd00::2/128"},
		{"172.16.0.2", "fd00::2"},
		{"fd00::2/128", "10.0.0.5/24"},
		{"10.0.0.5/24"},
		{"2001:db8::1/64"},
		{"2001:DB8::A"},
		{"fe80::1%eth0"},
		{"fe80::1%eth0/64"},
		{"fe80::1/64%eth0"},
		{"192.0.2.1/0"},
		{"10.0.0.1/32", "10.0.0.2/32"},
		{"fd00::1", "fd00::2"},
		{},
		{"bogus"},
		{"10.0.0.1/33"},
		{"010.0.0.1"},
		{" 10.0.0.1"},
		{"10.0.0.1/032"},
		{"10.0.0.1/ 32"},
		{"10.0.0.1/-1"},
		{"192.0.2.10", "2001:db8::10", "198.51.100.1"},
		{""},
	} {
		result := xrayRustWarpAddress{Input: list}
		if out, err := parseWarpAddress(list); err == nil {
			result.OK, result.Output = true, out
		}
		if result.Input == nil {
			result.Input = []string{}
		}
		v.Addresses = append(v.Addresses, result)
	}
}

func TestXrayRustWarpOracle(t *testing.T) {
	out := os.Getenv("MASQUE_WARP_ORACLE_OUT")
	if out == "" {
		t.Skip("MASQUE_WARP_ORACLE_OUT is not set")
	}
	g := xrayRustWarpGen{rand.New(rand.NewPCG(0x77617270, 0x6b657973))}
	var v xrayRustWarpVectors
	g.private(&v)
	g.public(&v)
	xrayRustWarpAddresses(&v)
	data, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

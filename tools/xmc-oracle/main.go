// Records the RSA public key Xray-core's xmc mask derives from each password,
// as x509.MarshalPKIXPublicKey writes it: what its server sends and its
// client compares. The derivation is deterministic, so a fresh run matches
// tests/fixtures/xmc/vectors.json byte for byte.
// Run with go -C <pinned checkout> run -mod=readonly <this file> out.json.
package main

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/xtls/xray-core/transport/internet/finalmask/xmc"
)

type key struct {
	Password  string `json:"password"`
	PublicKey string `json:"publicKey"`
}

type result struct {
	Keys []key `json:"keys"`
}

func main() {
	var out result
	for _, password := range []string{"synthetic-xmc-password", "x", "пароль", "0123456789abcdef0123456789abcdef"} {
		private, err := xmc.DeriveRSAKey(password)
		if err != nil {
			panic(err)
		}
		public, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
		if err != nil {
			panic(err)
		}
		out.Keys = append(out.Keys, key{password, hex.EncodeToString(public)})
	}
	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[1], append(encoded, '\n'), 0600); err != nil {
		panic(err)
	}
}

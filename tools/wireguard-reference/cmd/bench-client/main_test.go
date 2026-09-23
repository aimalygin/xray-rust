package main

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"testing"
)

func TestAddressRoundtripAndTruncation(t *testing.T) {
	for _, s := range []string{"127.0.0.1:54321", "[::1]:54321"} {
		a := netip.MustParseAddrPort(s)
		b := addrBytes(a)
		got, err := readAddr(bytes.NewReader(b))
		if err != nil || got != a {
			t.Fatalf("address roundtrip: %v %v", got, err)
		}
		for end := 0; end < len(b); end++ {
			if _, err := readAddr(bytes.NewReader(b[:end])); err == nil {
				t.Fatal("accepted truncated address")
			}
		}
	}
	if _, err := readAddr(bytes.NewReader([]byte{3, 1, 'x', 0, 1})); err == nil {
		t.Fatal("accepted domain")
	}
}

func TestKeysRequireExactly32Bytes(t *testing.T) {
	for _, size := range []int{0, 31, 33} {
		if _, err := key(base64.StdEncoding.EncodeToString(make([]byte, size))); err == nil {
			t.Fatal("accepted wrong key size")
		}
	}
	if got, err := key(base64.StdEncoding.EncodeToString(make([]byte, 32))); err != nil || len(got) != 64 {
		t.Fatal("rejected valid key")
	}
}

package main

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

func TestForwarderNeverUsesInnerDestinationAsHostAddress(t *testing.T) {
	for _, ip := range []string{"198.51.100.7", "2001:db8::7", "192.0.2.9", "203.0.113.9"} {
		id := stack.TransportEndpointID{LocalAddress: tcpip.AddrFromSlice(netip.MustParseAddr(ip).AsSlice()), LocalPort: 53}
		for _, port := range []uint16{0, 9000} {
			target, ok := loopbackTarget(id, port)
			if !ok || !strings.HasPrefix(target, "127.0.0.1:") {
				t.Fatalf("non-loopback forwarding: %q", target)
			}
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "8.8.8.8", "::1", "2606:4700::1111"} {
		id := stack.TransportEndpointID{LocalAddress: tcpip.AddrFromSlice(netip.MustParseAddr(ip).AsSlice()), LocalPort: 53}
		if _, ok := loopbackTarget(id, 9000); ok {
			t.Fatalf("unexpected inner range: %s", ip)
		}
	}
}

func TestConfigRejectsPublicListenersAndRedactsBadKeys(t *testing.T) {
	base := config{Listen: "127.0.0.1:43210", PrivateKey: strings.Repeat("42", 32), PeerKey: strings.Repeat("53", 32)}
	path := filepath.Join(t.TempDir(), "config.json")
	check := func(c config) error {
		data, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, err = readConfig(path)
		return err
	}
	if err := check(base); err != nil {
		t.Fatal(err)
	}
	for _, listen := range []string{"0.0.0.0:43210", "[::]:43210", "192.0.2.7:43210", "127.0.0.1:0"} {
		c := base
		c.Listen = listen
		if err := check(c); err == nil {
			t.Fatalf("accepted listener %s", listen)
		}
	}
	base.PresharedKey = "synthetic-malformed-secret"
	if err := check(base); err == nil || strings.Contains(err.Error(), base.PresharedKey) {
		t.Fatalf("bad key error: %v", err)
	}
}

func TestPacketTunCloseUnblocksReadAndIsIdempotent(t *testing.T) {
	tun := newPacketTun()
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := tun.Read([][]byte{make([]byte, mtu)}, make([]int, 1), 0); err != os.ErrClosed {
		t.Fatalf("read after close: %v", err)
	}
	if _, ok := <-tun.Events(); ok {
		t.Fatal("event channel remained open")
	}
}

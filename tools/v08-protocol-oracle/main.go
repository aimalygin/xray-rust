// Generate client wire fixtures from the exact pinned Xray-core module.
// Synthetic credentials only. This is not a live-server interoperability test.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/proxy/trojan"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	requests := []map[string]any{}
	packets := []map[string]any{}
	limits := []map[string]any{}
	addresses := []string{"192.0.2.1", "2001:db8::1", "example.test"}
	for _, password := range []string{"v08-test-password", "v08-тест-🔑"} {
		account, err := (&trojan.Account{Password: password}).AsAccount()
		must(err)
		for _, address := range addresses {
			for _, network := range []string{"tcp", "udp"} {
				target := net.TCPDestination(net.ParseAddress(address), 443)
				if network == "udp" {
					target = net.UDPDestination(net.ParseAddress(address), 443)
				}
				var wire bytes.Buffer
				writer := trojan.ConnWriter{Writer: &wire, Target: target, Account: account.(*trojan.MemoryAccount)}
				_, err := writer.Write(nil)
				must(err)
				requests = append(requests, map[string]any{
					"password": password, "address": address, "port": 443,
					"network": network, "wire": hex.EncodeToString(wire.Bytes()),
				})
			}
		}
	}
	// The pinned writer uses one 8192-byte stack buffer including framing,
	// while its reader permits an 8192-byte payload. Record both boundaries.
	for _, address := range addresses {
		target := net.UDPDestination(net.ParseAddress(address), 53)
		var prefix bytes.Buffer
		writer := trojan.PacketWriter{Writer: &prefix, Target: target}
		packet := buf.New()
		_, err := packet.Write([]byte{0})
		must(err)
		must(writer.WriteMultiBuffer(buf.MultiBuffer{packet}))
		headerLen := prefix.Len() - 1
		maxPayload := 8192 - headerLen
		for _, length := range []int{maxPayload, maxPayload + 1} {
			packet := buf.New()
			_, err := packet.Write(make([]byte, length))
			must(err)
			var wire bytes.Buffer
			writer := trojan.PacketWriter{Writer: &wire, Target: target}
			err = writer.WriteMultiBuffer(buf.MultiBuffer{packet})
			if (err == nil) != (length == maxPayload) {
				panic("Trojan writer boundary changed")
			}
		}
		for _, length := range []int{8192, 8193} {
			wire := append([]byte(nil), prefix.Bytes()[:headerLen]...)
			binary.BigEndian.PutUint16(wire[headerLen-4:headerLen-2], uint16(length))
			wire = append(wire, make([]byte, length)...)
			reader := trojan.PacketReader{Reader: bytes.NewReader(wire)}
			decoded, err := reader.ReadMultiBuffer()
			buf.ReleaseMulti(decoded)
			if (err == nil) != (length == 8192) {
				panic("Trojan reader boundary changed")
			}
		}
		limits = append(limits, map[string]any{"address": address, "maxReadPayload": 8192, "maxWritePayload": maxPayload})
	}
	for _, address := range addresses {
		target := net.UDPDestination(net.ParseAddress(address), 53)
		payload := []byte{0, 1, 127, 255, '\r', '\n', 42}
		var wire bytes.Buffer
		packet := buf.New()
		_, err := packet.Write(payload)
		must(err)
		writer := trojan.PacketWriter{Writer: &wire, Target: target}
		must(writer.WriteMultiBuffer(buf.MultiBuffer{packet}))
		reader := trojan.PacketReader{Reader: bytes.NewReader(wire.Bytes())}
		decoded, err := reader.ReadMultiBuffer()
		must(err)
		if len(decoded) != 1 || !bytes.Equal(decoded[0].Bytes(), payload) || *decoded[0].UDP != target {
			panic("Trojan UDP oracle round trip")
		}
		buf.ReleaseMulti(decoded)
		packets = append(packets, map[string]any{
			"address": address, "port": 53,
			"payload": hex.EncodeToString(payload), "wire": hex.EncodeToString(wire.Bytes()),
		})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	must(encoder.Encode(map[string]any{
		"xrayCoreCommit":  "5ca6f4b7d4dc20a881d4330e498892697627ec0c",
		"vmess":           vmessFixtures(),
		"mux":             muxFixtures(),
		"shadowsocks2022": ss2022Fixtures(),
		"trojanRequests":  requests, "trojanUdpPackets": packets, "trojanUdpLimits": limits,
	}))
}

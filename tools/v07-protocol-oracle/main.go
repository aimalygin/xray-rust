// Generates wire/routing fixtures using the exact pinned Xray-core module.
// This is a codec oracle, not an end-to-end Hysteria/WireGuard session test.
package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"

	"github.com/apernet/quic-go/quicvarint"
	"github.com/xtls/xray-core/infra/conf"
	proxy "github.com/xtls/xray-core/proxy/hysteria"
	transport "github.com/xtls/xray-core/transport/internet/hysteria"
	"golang.zx2c4.com/wireguard/device"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func udpWire(message proxy.UDPMessage) string {
	wire := make([]byte, message.Size())
	if message.Serialize(wire) != len(wire) {
		panic("serialization size")
	}
	// Xray's UDP transport owns the first four bytes, not Serialize itself.
	binary.BigEndian.PutUint32(wire, message.SessionID)
	parsed, err := proxy.ParseUDPMessage(wire)
	must(err)
	if parsed.SessionID != message.SessionID || !bytes.Equal(parsed.Data, message.Data) {
		panic("UDP oracle round trip")
	}
	return hex.EncodeToString(wire)
}

func main() {
	transport.TcpRequestPadding.Min, transport.TcpRequestPadding.Max = 0, 1
	transport.TcpResponsePadding.Min, transport.TcpResponsePadding.Max = 0, 1
	requests := []map[string]any{}
	for _, address := range []string{"example.com:443", "192.0.2.1:80", "[2001:db8::1]:53"} {
		wire := bytes.NewBuffer(quicvarint.Append(nil, transport.FrameTypeTCPRequest))
		must(proxy.WriteTCPRequest(wire, address))
		encoded := hex.EncodeToString(wire.Bytes())
		reader := bytes.NewReader(wire.Bytes())
		kind, err := quicvarint.Read(reader)
		must(err)
		if kind != transport.FrameTypeTCPRequest {
			panic("request kind")
		}
		decoded, err := proxy.ReadTCPRequest(reader)
		must(err)
		if decoded != address || reader.Len() != 0 {
			panic("request round trip")
		}
		requests = append(requests, map[string]any{"address": address, "wire": encoded})
	}
	responses := []map[string]any{}
	for _, ok := range []bool{true, false} {
		message := ""
		if !ok {
			message = "connection refused"
		}
		var wire bytes.Buffer
		must(proxy.WriteTCPResponse(&wire, ok, message))
		responses = append(responses, map[string]any{"ok": ok, "message": message, "wire": hex.EncodeToString(wire.Bytes())})
	}
	message := proxy.UDPMessage{SessionID: 0x01020304, PacketID: 0x1234, FragCount: 1, Addr: "example.com:53", Data: []byte("0123456789abcdefghijklmnopqrstuvwxyz")}
	fragments := []string{}
	for _, fragment := range proxy.FragUDPMessage(&message, 32) {
		fragments = append(fragments, udpWire(fragment))
	}

	// Synthetic public test material, never deployment credentials.
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(224 + i)
	}
	keys := []map[string]any{}
	for _, input := range []string{hex.EncodeToString(keyBytes), base64.StdEncoding.EncodeToString(keyBytes), base64.RawStdEncoding.EncodeToString(keyBytes), base64.URLEncoding.EncodeToString(keyBytes), base64.RawURLEncoding.EncodeToString(keyBytes)} {
		decoded, err := conf.ParseWireGuardKey(input)
		must(err)
		keys = append(keys, map[string]any{"input": input, "decodedHex": decoded})
	}

	prefixes := []string{"0.0.0.0/0", "10.0.0.0/8", "10.42.0.0/16", "10.42.1.0/24", "10.42.1.99/24", "::/0", "2001:db8::/32", "::ffff:c000:200/120"}
	peers := make([]*device.Peer, len(prefixes))
	var table device.AllowedIPs
	routes := []map[string]any{}
	for i, prefix := range prefixes {
		peers[i] = &device.Peer{}
		table.Insert(netip.MustParsePrefix(prefix), peers[i])
		routes = append(routes, map[string]any{"prefix": prefix, "peer": i})
	}
	lookups := []map[string]any{}
	for _, address := range []string{"203.0.113.7", "10.1.2.3", "10.42.2.1", "10.42.1.200", "2001:db8::1", "fd00::1", "::ffff:c000:204", "192.0.2.4"} {
		peer := table.Lookup(netip.MustParseAddr(address).AsSlice())
		index := -1
		for i, candidate := range peers {
			if candidate == peer {
				index = i
			}
		}
		lookups = append(lookups, map[string]any{"address": address, "peer": index})
	}
	result := map[string]any{
		"reference":   "Xray-core v26.7.28 / 5ca6f4b7d4dc20a881d4330e498892697627ec0c",
		"scope":       "wire codecs and WireGuard allowed-IP lookup; no live network interop",
		"tcpRequests": requests, "tcpResponses": responses,
		"udp":  map[string]any{"wire": udpWire(message), "maxDatagramSize": 32, "fragments": fragments},
		"keys": keys, "routes": routes, "lookups": lookups,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	must(encoder.Encode(result))
}

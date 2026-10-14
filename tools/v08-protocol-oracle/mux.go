package main

import (
	"encoding/hex"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
)

func muxFixtures() []map[string]any {
	cases := []map[string]any{}
	for _, network := range []string{"tcp", "udp"} {
		for _, address := range []string{"192.0.2.1", "2001:db8::1", "example.test"} {
			for _, status := range []mux.SessionStatus{mux.SessionStatusNew, mux.SessionStatusKeep, mux.SessionStatusEnd, mux.SessionStatusKeepAlive} {
				dest := net.TCPDestination(net.ParseAddress(address), 8443)
				if network == "udp" {
					dest = net.UDPDestination(net.ParseAddress(address), 8443)
				}
				meta := mux.FrameMetadata{Target: dest, SessionID: 37, SessionStatus: status, GlobalID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}}
				payload := []byte{0, 1, 127, 255}
				if status == mux.SessionStatusNew || status == mux.SessionStatusKeep {
					meta.Option.Set(mux.OptionData)
				} else {
					payload = nil
				}
				b := buf.New()
				if network == "udp" && (status == mux.SessionStatusNew || status == mux.SessionStatusKeep) {
					b.UDP = &dest
				}
				must(meta.WriteTo(b))
				if payload != nil {
					b.WriteByte(0)
					b.WriteByte(byte(len(payload)))
					b.Write(payload)
				}
				cases = append(cases, map[string]any{"network": network, "address": address, "port": 8443, "sessionId": 37, "status": status, "payload": hex.EncodeToString(payload), "wire": hex.EncodeToString(b.Bytes())})
				b.Release()
			}
		}
	}
	return cases
}

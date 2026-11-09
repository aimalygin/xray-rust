// A stand-in for Cloudflare's WARP endpoint, built from Xray-core
// v26.10.31's own warp_test.go servers, for the client's live tests. It
// never contacts Cloudflare.
//
// It runs inside the masque package, added without touching the checkout,
// as a test binary:
//
//	go -C <pinned checkout> test -c -o warp-server -overlay overlay.json \
//	    ./transport/internet/masque
//	MASQUE_WARP_SERVER_DIR=dir MASQUE_WARP_SERVER_MODE=h3-draft \
//	    ./warp-server -test.run '^TestXrayRustWarpServer$'
//
// where overlay.json maps masque/xray_rust_warp_server_test.go to this file.
// The directory holds client.spki, the device's public key, before start;
// the server then writes spki, its own key in base64, and port. It checks
// each tunnel as Xray's tests check the client — the device certificate,
// the request, the draft datagram setting, no address request — appends
// any failure to errors and each accepted tunnel to tunnels, and sends back
// every UDP packet with its addresses and ports swapped. Modes: h3-draft,
// h3-rfc, h2 and h2-noalpn.
package masque

import (
	"crypto/ecdsa"
	gotls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	gonet "net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/xtls/xray-core/transport/internet/masque/connectip"
	"golang.org/x/net/http2"
)

var xrayRustWarpLog sync.Mutex

func xrayRustWarpAppend(dir, name, line string) {
	xrayRustWarpLog.Lock()
	defer xrayRustWarpLog.Unlock()
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, line)
}

// xrayRustWarpEcho turns a UDP packet around: addresses and ports swapped,
// which leaves both checksums valid. Anything else is dropped.
func xrayRustWarpEcho(b []byte) []byte {
	b = append([]byte(nil), b...)
	swap := func(i, j, n int) {
		for k := range n {
			b[i+k], b[j+k] = b[j+k], b[i+k]
		}
	}
	switch {
	case len(b) >= 20 && b[0]>>4 == 4:
		ihl := int(b[0]&0x0f) * 4
		if b[9] != 17 || len(b) < ihl+8 {
			return nil
		}
		swap(12, 16, 4)
		swap(ihl, ihl+2, 2)
	case len(b) >= 48 && b[0]>>4 == 6:
		if b[6] != 17 {
			return nil
		}
		swap(8, 24, 16)
		swap(40, 42, 2)
	default:
		return nil
	}
	return b
}

func TestXrayRustWarpServer(t *testing.T) {
	dir, mode := os.Getenv("MASQUE_WARP_SERVER_DIR"), os.Getenv("MASQUE_WARP_SERVER_MODE")
	if dir == "" {
		t.Skip("MASQUE_WARP_SERVER_DIR is not set")
	}
	fail := func(format string, args ...any) {
		xrayRustWarpAppend(dir, "errors", mode+": "+fmt.Sprintf(format, args...))
	}
	der, err := os.ReadFile(filepath.Join(dir, "client.spki"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	client, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("the device key is not ECDSA")
	}
	alpn := map[string]string{"h3-draft": http3.NextProtoH3, "h3-rfc": http3.NextProtoH3, "h2": http2.NextProtoTLS, "h2-noalpn": ""}[mode]
	serverTLS, serverKey, _ := warpServerTLS(t, client, alpn)
	if err := os.WriteFile(filepath.Join(dir, "spki"), []byte(base64.StdEncoding.EncodeToString(serverKey)), 0o644); err != nil {
		t.Fatal(err)
	}

	var port int
	switch mode {
	case "h3-draft", "h3-rfc":
		draft := mode == "h3-draft"
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			settings := w.(http3.Settingser)
			<-settings.ReceivedSettings()
			switch {
			case settings.Settings().Other[connectip.SettingDatagramDraft00] != 1:
				fail("the client didn't send the draft datagram setting")
			case r.Method != http.MethodConnect, r.Proto != "cf-connect-ip", r.Host != WarpHost, r.URL.Path != WarpPath:
				fail("unexpected request %s %s %s%s", r.Method, r.Proto, r.Host, r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			xrayRustWarpAppend(dir, "tunnels", mode)
			str := w.(http3.HTTPStreamer).HTTPStream()
			go func() {
				if types := readCapsuleTypes(str, nil); len(types) > 0 {
					for _, typ := range types {
						if typ == 2 {
							fail("the client sent an ADDRESS_REQUEST")
						}
					}
				}
			}()
			for {
				b, err := str.ReceiveDatagram(r.Context())
				if err != nil {
					return
				}
				if len(b) == 0 || b[0] != 0 {
					fail("a datagram without context ID 0")
					continue
				}
				if out := xrayRustWarpEcho(b[1:]); out != nil {
					str.SendDatagram(append([]byte{0}, out...))
				}
			}
		})
		udp, err := gonet.ListenUDP("udp4", &gonet.UDPAddr{IP: gonet.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		server := &http3.Server{
			Handler:         handler,
			TLSConfig:       serverTLS,
			QUICConfig:      &quic.Config{EnableDatagrams: true},
			EnableDatagrams: !draft,
		}
		if draft {
			server.AdditionalSettings = map[uint64]uint64{connectip.SettingDatagramDraft00: 1}
		}
		go server.Serve(udp)
		port = udp.LocalAddr().(*gonet.UDPAddr).Port
	case "h2", "h2-noalpn":
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method != http.MethodConnect, r.ProtoMajor != 2, r.Host != WarpHost+":443":
				fail("unexpected request %s %s %s", r.Method, r.Proto, r.Host)
			case r.Header.Get("Cf-Connect-Proto") != "cf-connect-ip", r.Header.Get("Pq-Enabled") != "false":
				fail("unexpected headers %v", r.Header)
			case r.Header.Get("Capsule-Protocol") != "", r.Header.Get(":protocol") != "":
				fail("unexpected headers %v", r.Header)
			}
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			xrayRustWarpAppend(dir, "tunnels", mode)
			p := http3.NewCapsuleParser(r.Body)
			for {
				typ, cr, err := p.Next()
				if err != nil {
					return
				}
				b, err := io.ReadAll(cr)
				if err != nil {
					return
				}
				switch typ {
				case 0:
					if len(b) == 0 || b[0]>>4 != 4 && b[0]>>4 != 6 {
						fail("a DATAGRAM capsule that is not a bare packet")
						continue
					}
					if out := xrayRustWarpEcho(b); out != nil {
						w.Write(warpCapsule(0, out))
						w.(http.Flusher).Flush()
					}
				case 2:
					fail("the client sent an ADDRESS_REQUEST")
				}
			}
		})
		ln, err := gonet.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func() {
					defer c.Close()
					tc := gotls.Server(c, serverTLS)
					if err := tc.Handshake(); err != nil {
						fail("TLS: %v", err)
						return
					}
					(&http2.Server{}).ServeConn(tc, &http2.ServeConnOpts{Handler: handler})
				}()
			}
		}()
		port = ln.Addr().(*gonet.TCPAddr).Port
	default:
		t.Fatalf("unknown mode %q", mode)
	}
	if err := os.WriteFile(filepath.Join(dir, "port"), []byte(strconv.Itoa(port)), 0o644); err != nil {
		t.Fatal(err)
	}
	select {}
}

// Records the frames Xray-core v26.10.31's own HTTP/2 client writes for a
// MASQUE tunnel, from its SETTINGS through the extended CONNECT request:
// newHTTP2ClientConn on one end of a pipe and establish sending the
// request, against a server that enables extended CONNECT. Xray draws its
// browser versions per process, so the browser User-Agents are pinned and
// recorded; nothing else is random, and a fresh run matches
// tests/fixtures/masque/http2-request-vectors.json byte for byte.
//
// It runs inside the package, added without touching the checkout:
//
//	go -C <pinned checkout> test -overlay overlay.json \
//	    ./transport/internet/masque -run TestXrayRustHTTP2Oracle
//
// where overlay.json maps masque/xray_rust_http2_oracle_test.go to this
// file, and MASQUE_HTTP2_ORACLE_OUT names the output file.
package masque

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
	"github.com/xtls/xray-core/transport/internet/masque/connectip"
)

type xrayRustH2Frame struct {
	Type    uint8  `json:"type"`
	Flags   uint8  `json:"flags"`
	Stream  uint32 `json:"stream"`
	Payload string `json:"payload"`
}

type xrayRustH2Case struct {
	Name       string            `json:"name"`
	ServerName string            `json:"serverName"`
	Port       uint16            `json:"port"`
	Host       string            `json:"host"`
	Path       string            `json:"path"`
	Headers    map[string]string `json:"headers"`
	// Warp: Cloudflare's tunnel, with these addresses.
	Warp []string `json:"warp,omitempty"`
	// Canonical: the headers as http.Header.Set keeps them, sorted.
	Canonical [][2]string       `json:"canonical"`
	Frames    []xrayRustH2Frame `json:"frames"`
}

type xrayRustH2Vectors struct {
	// Versions: the pinned browser versions, which the fixture safety scan
	// reads to tell Chrome's version from an address.
	Versions map[string]int `json:"versions"`
	// UserAgents: what the browser presets send in this run.
	UserAgents map[string]string `json:"userAgents"`
	Cases      []xrayRustH2Case  `json:"cases"`
}

// The browser versions the run pins.
const (
	xrayRustChromeVersion  = 148
	xrayRustFirefoxVersion = 150
)

// The server's SETTINGS: ENABLE_CONNECT_PROTOCOL = 1.
var xrayRustH2ServerSettings = []byte{0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1}

func TestXrayRustHTTP2Oracle(t *testing.T) {
	out := os.Getenv("MASQUE_HTTP2_ORACLE_OUT")
	if out == "" {
		t.Skip("MASQUE_HTTP2_ORACLE_OUT is not set")
	}
	utils.ChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/" +
		strconv.Itoa(xrayRustChromeVersion) + ".0.0.0 Safari/537.36"
	utils.FirefoxUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:" + strconv.Itoa(xrayRustFirefoxVersion) +
		".0) Gecko/20100101 Firefox/" + strconv.Itoa(xrayRustFirefoxVersion) + ".0"
	cases := []xrayRustH2Case{
		{Name: "defaults", ServerName: "masque.example", Port: 443, Path: DefaultPath},
		{
			Name: "credentials, a port and a custom header", ServerName: "masque.example", Port: 8443,
			Path:    "/masque/*/*/",
			Headers: map[string]string{"Authorization": "Basic bWFzcXVlQHRlc3Q6c3ludGhldGlj", "x-custom": "1"},
		},
		{
			Name: "the golang preset", ServerName: "masque.example", Port: 443, Path: DefaultPath,
			Headers: map[string]string{"User-Agent": "golang", "X-A": "1", "X-_": "2"},
		},
		{
			Name: "no user agent", ServerName: "masque.example", Port: 443, Path: DefaultPath,
			Headers: map[string]string{"User-Agent": ""},
		},
		{
			Name: "firefox and a host", ServerName: "masque.example", Port: 443, Path: DefaultPath,
			Host: "proxy.example", Headers: map[string]string{"User-Agent": "firefox"},
		},
		{Name: "an IPv6 server name", ServerName: "[2001:db8::1]", Port: 8443, Path: DefaultPath},
		{
			Name: "connection fields", ServerName: "masque.example", Port: 443, Path: DefaultPath,
			Headers: map[string]string{
				"Connection": "close", "Keep-Alive": "1", "Proxy-Connection": "1",
				"Transfer-Encoding": "chunked", "Upgrade": "websocket", "Te": "trailers",
			},
		},
		{
			Name: "a long header", ServerName: "masque.example", Port: 443, Path: DefaultPath,
			Headers: map[string]string{"X-Padding": xrayRustH2Padding(300)},
		},
		{
			Name: "warp", ServerName: "consumer-masque.cloudflareclient.com", Port: 443,
			Host: WarpHost, Path: WarpPath, Warp: []string{"172.16.0.2/32", "fd00::2/128"},
		},
		{
			Name: "warp with a host of its own and a header", ServerName: "warp.example", Port: 8443,
			Host: "warp.example:2408", Path: WarpPath, Warp: []string{"172.16.0.2/32"},
			Headers: map[string]string{"User-Agent": "golang", "X-Device": "1"},
		},
	}
	for i := range cases {
		c := &cases[i]
		c.Canonical = [][2]string{}
		for _, k := range slices.Sorted(maps.Keys(c.Headers)) {
			c.Canonical = append(c.Canonical, [2]string{http.CanonicalHeaderKey(k), c.Headers[k]})
		}
		slices.SortFunc(c.Canonical, func(a, b [2]string) int { return strings.Compare(a[0], b[0]) })
		c.Frames = xrayRustH2Frames(t, c)
	}
	data, err := json.MarshalIndent(xrayRustH2Vectors{
		Versions:   map[string]int{"chrome": xrayRustChromeVersion, "firefox": xrayRustFirefoxVersion},
		UserAgents: map[string]string{"chrome": utils.ChromeUA, "firefox": utils.FirefoxUA},
		Cases:      cases,
	}, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func xrayRustH2Padding(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = "abcdefghijklmnopqrstuvwxyz0123456789-"[i%37]
	}
	return string(b)
}

// xrayRustH2Frames returns what the client writes after its preface, up to
// and including the request's last header block frame.
func xrayRustH2Frames(t *testing.T, c *xrayRustH2Case) []xrayRustH2Frame {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	frames := make(chan []xrayRustH2Frame, 1)
	go func() {
		var got []xrayRustH2Frame
		defer func() { frames <- got }()
		preface := make([]byte, 24)
		if _, err := io.ReadFull(server, preface); err != nil {
			return
		}
		sent := false
		for {
			head := make([]byte, 9)
			if _, err := io.ReadFull(server, head); err != nil {
				return
			}
			payload := make([]byte, int(head[0])<<16|int(head[1])<<8|int(head[2]))
			if _, err := io.ReadFull(server, payload); err != nil {
				return
			}
			f := xrayRustH2Frame{
				Type: head[3], Flags: head[4],
				Stream:  binary.BigEndian.Uint32(head[5:9]) & 0x7fffffff,
				Payload: hex.EncodeToString(payload),
			}
			got = append(got, f)
			if f.Type == 4 && f.Flags&1 == 0 && !sent {
				sent = true
				go server.Write(xrayRustH2ServerSettings)
			}
			if (f.Type == 1 || f.Type == 9) && f.Flags&4 != 0 {
				return
			}
		}
	}()
	cc, err := newHTTP2ClientConn(client, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer cc.Close()
	config := &Config{Path: c.Path, Host: c.Host, Headers: c.Headers}
	var tunnels tunnelClient = connectip.NewHTTP2ClientConn(cc)
	if c.Warp != nil {
		config.Warp = &Warp{Address: c.Warp}
		tunnels = connectip.NewCloudflareHTTP2ClientConn(cc)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go establish(ctx, tunnels, cc, func() { cc.Close() }, config,
		authority(config, c.ServerName, xnet.Port(c.Port)))
	select {
	case got := <-frames:
		return got
	case <-ctx.Done():
		t.Fatalf("%s: no request within the deadline", c.Name)
		return nil
	}
}

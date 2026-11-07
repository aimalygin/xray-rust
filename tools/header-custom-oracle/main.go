// Command header-custom-oracle records what Xray-core's own header-custom TCP
// client and server put on the wire for a set of configs: each case runs
// Xray's client connection against Xray's server connection over a pipe, with
// fixed addresses for the metadata, and records the bytes each side wrote
// before the payload and whether the client's handshake succeeded. Run it
// inside a pinned Xray-core checkout:
//
//	go -C Xray-core run -mod=readonly ../tools/header-custom-oracle/main.go out.json
//
// Cases avoid random items, whose bytes differ every run.
package main

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
)

var (
	localAddr  = &net.TCPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 40000}
	remoteAddr = &net.TCPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 443}
)

// addrConn gives a pipe end the addresses the metadata reads.
type addrConn struct {
	net.Conn
	local, remote net.Addr
}

func (c addrConn) LocalAddr() net.Addr  { return c.local }
func (c addrConn) RemoteAddr() net.Addr { return c.remote }

// recorder keeps every byte written through it.
type recorder struct {
	net.Conn
	mu      sync.Mutex
	written []byte
}

func (r *recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.written = append(r.written, p...)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

func (r *recorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.written...)
}

type testCase struct {
	Name   string          `json:"name"`
	Client json.RawMessage `json:"client"`
	Server json.RawMessage `json:"server,omitempty"`
}

type result struct {
	Name           string          `json:"name"`
	Client         json.RawMessage `json:"client"`
	Server         json.RawMessage `json:"server"`
	ClientToServer string          `json:"clientToServer"`
	ServerToClient string          `json:"serverToClient"`
	ClientOK       bool            `json:"clientOk"`
	BuildError     string          `json:"buildError,omitempty"`
}

const payload = "PAYLOAD"

func build(raw json.RawMessage) (*custom.TCPConfig, error) {
	settings := new(conf.HeaderCustomTCP)
	if err := json.Unmarshal(raw, settings); err != nil {
		return nil, err
	}
	message, err := settings.Build()
	if err != nil {
		return nil, err
	}
	return message.(*custom.TCPConfig), nil
}

func run(c testCase) result {
	if len(c.Server) == 0 {
		c.Server = c.Client
	}
	r := result{Name: c.Name, Client: c.Client, Server: c.Server}
	clientConfig, err := build(c.Client)
	if err != nil {
		r.BuildError = err.Error()
		return r
	}
	serverConfig, err := build(c.Server)
	if err != nil {
		r.BuildError = err.Error()
		return r
	}
	clientEnd, serverEnd := net.Pipe()
	clientRaw := &recorder{Conn: addrConn{clientEnd, localAddr, remoteAddr}}
	serverRaw := &recorder{Conn: addrConn{serverEnd, remoteAddr, localAddr}}
	client, _ := custom.NewConnClientTCP(clientConfig, clientRaw)
	server, _ := custom.NewConnServerTCP(serverConfig, serverRaw)

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		buf := make([]byte, len(payload))
		total := 0
		for total < len(buf) {
			n, err := server.Read(buf[total:])
			if err != nil {
				return
			}
			total += n
		}
	}()
	clientDone := make(chan error, 1)
	go func() {
		_, err := client.Write([]byte(payload))
		clientDone <- err
	}()
	select {
	case err := <-clientDone:
		r.ClientOK = err == nil
	case <-time.After(3 * time.Second):
	}
	// Let the server finish what it writes, an errors sequence included.
	select {
	case <-serverDone:
	case <-time.After(300 * time.Millisecond):
	}
	clientEnd.Close()
	serverEnd.Close()
	sent := clientRaw.bytes()
	if r.ClientOK && len(sent) >= len(payload) {
		sent = sent[:len(sent)-len(payload)]
	}
	r.ClientToServer = hex.EncodeToString(sent)
	r.ServerToClient = hex.EncodeToString(serverRaw.bytes())
	return r
}

func main() {
	var cases []testCase
	if err := json.Unmarshal([]byte(cases_json), &cases); err != nil {
		panic(err)
	}
	var results []result
	for _, c := range cases {
		results = append(results, run(c))
	}
	file, err := os.Create(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", " ")
	if err := enc.Encode(results); err != nil {
		panic(err)
	}
}

// The cases: a client config and, where it differs, the server's.
const cases_json = `[
 {"name": "fixed bytes each way",
  "client": {"clients": [[{"packet": [1, 2, 3]}]], "servers": [[{"packet": "AAEC"}]]}},
 {"name": "every packet type",
  "client": {"clients": [[{"type": "str", "packet": "GET / HTTP/1.1\r\n"}, {"type": "hex", "packet": "0D0a"},
             {"type": "base64", "packet": "aGVsbG8="}, {"type": "ARRAY", "packet": [255]}]],
             "servers": [[{"type": "Str", "packet": "OK"}]]}},
 {"name": "a captured nonce echoed back",
  "client": {"clients": [[{"capture": "nonce", "type": "str", "packet": "ABCDEFGH"}]],
             "servers": [[{"reuse": "nonce"}]]}},
 {"name": "the server captures and the client checks its transform",
  "client": {"clients": [[{"type": "str", "packet": "hi"}]],
             "servers": [[{"capture": "token", "type": "str", "packet": "0123"},
                          {"transform": {"op": "concat", "args": [{"reuse": "token"}, {"type": "str", "bytes": "!"}]}}]]}},
 {"name": "packs and arithmetic",
  "client": {"clients": [[
    {"transform": {"op": "be16", "args": [{"u64": 513}]}},
    {"transform": {"op": "le16", "args": [{"u64": 513}]}},
    {"transform": {"op": "be32", "args": [{"transform": {"op": "add", "args": [{"u64": 4294967294}, {"u64": 1}]}}]}},
    {"transform": {"op": "le32", "args": [{"transform": {"op": "sub", "args": [{"u64": 10}, {"u64": 3}]}}]}},
    {"transform": {"op": "le64", "args": [{"transform": {"op": "shl", "args": [{"u64": 1}, {"u64": 63}]}}]}},
    {"transform": {"op": "be16", "args": [{"transform": {"op": "xor16", "args": [{"u64": 65535}, {"u64": 4660}]}}]}},
    {"transform": {"op": "be32", "args": [{"transform": {"op": "xor32", "args": [{"u64": 4294967295}, {"u64": 305419896}]}}]}},
    {"transform": {"op": "be16", "args": [{"transform": {"op": "and", "args": [{"u64": 61680}, {"u64": 4080}]}}]}},
    {"transform": {"op": "be16", "args": [{"transform": {"op": "or", "args": [{"u64": 61440}, {"u64": 15}]}}]}},
    {"transform": {"op": "be16", "args": [{"transform": {"op": "shr", "args": [{"u64": 65280}, {"u64": 8}]}}]}}
  ]], "servers": [[{"packet": [0]}]]}},
 {"name": "byte operations",
  "client": {"clients": [[
    {"transform": {"op": "concat", "args": [{"type": "str", "bytes": "ab"}, {"type": "hex", "bytes": "00ff"}, {"bytes": [7]}]}},
    {"transform": {"op": "slice", "args": [{"type": "str", "bytes": "abcdef"}, {"u64": 1}, {"u64": 3}]}},
    {"transform": {"op": "pad", "args": [{"type": "str", "bytes": "ab"}, {"u64": 7}, {"type": "str", "bytes": "xy"}]}},
    {"transform": {"op": "truncate", "args": [{"type": "str", "bytes": "hello"}, {"u64": 3}]}},
    {"transform": {"op": "pad", "args": [{"type": "str", "bytes": "abc"}, {"u64": 3}, {"type": "str", "bytes": "z"}]}}
  ]], "servers": [[{"packet": [0]}]]}},
 {"name": "the addresses as metadata",
  "client": {"clients": [[
    {"transform": {"op": "be16", "args": [{"metadata": "local_port"}]}},
    {"transform": {"op": "be16", "args": [{"metadata": "remote_port"}]}},
    {"transform": {"op": "be16", "args": [{"metadata": "src_port_u16"}]}},
    {"transform": {"op": "be16", "args": [{"metadata": "dst_port_u16"}]}},
    {"transform": {"op": "be32", "args": [{"metadata": "local_ip4_u32"}]}},
    {"transform": {"op": "be32", "args": [{"metadata": "remote_ip4_u32"}]}},
    {"transform": {"op": "be32", "args": [{"metadata": "src_ip4_u32"}]}},
    {"transform": {"op": "be32", "args": [{"metadata": "dst_ip4_u32"}]}}
  ]], "servers": [[{"transform": {"op": "be16", "args": [{"metadata": "remote_port"}]}}]]}},
 {"name": "rounds in turn",
  "client": {"clients": [[{"type": "str", "packet": "c0"}], [{"type": "str", "packet": "c1"}]],
             "servers": [[{"type": "str", "packet": "s0"}], [{"type": "str", "packet": "s1"}]]}},
 {"name": "a client round reuses what the server sent",
  "client": {"clients": [[{"type": "str", "packet": "c0"}], [{"reuse": "token"}, {"type": "str", "packet": "!"}]],
             "servers": [[{"capture": "token", "type": "str", "packet": "TOKEN"}]]}},
 {"name": "more server sequences",
  "client": {"clients": [[{"type": "str", "packet": "c0"}]],
             "servers": [[{"type": "str", "packet": "s0"}], [{"type": "str", "packet": "s1"}], [{"type": "str", "packet": "s2"}]]}},
 {"name": "more client sequences",
  "client": {"clients": [[{"type": "str", "packet": "c0"}], [{"type": "str", "packet": "c1"}], [{"type": "str", "packet": "c2"}]],
             "servers": [[{"type": "str", "packet": "s0"}]]}},
 {"name": "a delay splits the sequence",
  "client": {"clients": [[{"type": "str", "packet": "before"}, {"delay": "5-6", "type": "str", "packet": "after"}]],
             "servers": [[{"type": "str", "packet": "ok"}]]}},
 {"name": "empty items and sequences",
  "client": {"clients": [[], [{}], [{"type": "str", "packet": "x"}]], "servers": [[], [{}]]}},
 {"name": "nothing to send",
  "client": {}},
 {"name": "the server answers with its errors sequence",
  "client": {"clients": [[{"type": "str", "packet": "hello"}]], "servers": [[{"type": "str", "packet": "fine"}]]},
  "server": {"clients": [[{"type": "str", "packet": "other"}]], "servers": [[{"type": "str", "packet": "fine"}]],
             "errors": [[{"type": "str", "packet": "nope"}]]}},
 {"name": "the server sends other bytes",
  "client": {"clients": [[{"type": "str", "packet": "hello"}]], "servers": [[{"type": "str", "packet": "fine"}]]},
  "server": {"clients": [[{"type": "str", "packet": "hello"}]], "servers": [[{"type": "str", "packet": "FINE"}]]}},
 {"name": "an unknown op",
  "client": {"clients": [[{"type": "str", "packet": "a"}, {"transform": {"op": "rot13", "args": [{"u64": 1}]}}]],
             "servers": [[{"packet": [0]}]]}},
 {"name": "a slice out of bounds",
  "client": {"clients": [[{"transform": {"op": "slice", "args": [{"type": "str", "bytes": "abc"}, {"u64": 2}, {"u64": 2}]}}]],
             "servers": [[{"packet": [0]}]]}},
 {"name": "an unknown variable",
  "client": {"clients": [[{"reuse": "missing"}]], "servers": [[{"packet": [0]}]]}},
 {"name": "unknown metadata",
  "client": {"clients": [[{"transform": {"op": "be16", "args": [{"metadata": "local_port6"}]}}]],
             "servers": [[{"packet": [0]}]]}},
 {"name": "a pack overflow",
  "client": {"clients": [[{"transform": {"op": "be16", "args": [{"u64": 65536}]}}]], "servers": [[{"packet": [0]}]]}},
 {"name": "a server transform the client cannot size",
  "client": {"clients": [[{"type": "str", "packet": "a"}]],
             "servers": [[{"transform": {"op": "add", "args": [{"u64": 1}, {"u64": 2}]}}]]}},
 {"name": "a config Xray refuses",
  "client": {"clients": [[{"packet": [1], "rand": 2}]]}}
]`

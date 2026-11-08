// Records exchanges between Xray-core's UDP custom client and server.
// Run with go -C <pinned checkout> run -mod=readonly <this file> out.json.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask/header/custom"
)

type pipe struct {
	local  net.Addr
	peer   *pipe
	in     chan []byte
	closed chan struct{}
	once   sync.Once
	mu     sync.Mutex
	sent   []string
}

func (p *pipe) LocalAddr() net.Addr              { return p.local }
func (p *pipe) SetDeadline(time.Time) error      { return nil }
func (p *pipe) SetReadDeadline(time.Time) error  { return nil }
func (p *pipe) SetWriteDeadline(time.Time) error { return nil }
func (p *pipe) Close() error                     { p.once.Do(func() { close(p.closed) }); return nil }
func (p *pipe) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case data := <-p.in:
		return copy(b, data), p.peer.local, nil
	case <-p.closed:
		return 0, nil, net.ErrClosed
	case <-time.After(time.Second):
		return 0, nil, os.ErrDeadlineExceeded
	}
}
func (p *pipe) WriteTo(b []byte, _ net.Addr) (int, error) {
	p.mu.Lock()
	p.sent = append(p.sent, hex.EncodeToString(b))
	p.mu.Unlock()
	select {
	case p.peer.in <- append([]byte(nil), b...):
		return len(b), nil
	case <-p.closed:
		return 0, net.ErrClosed
	}
}
func (p *pipe) packets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string{}, p.sent...)
}

// scriptedPeer answers the first datagram with an empty one, as an empty
// server sequence does, and hands on the rest.
type scriptedPeer struct {
	net.PacketConn
	answered bool
}

func (p *scriptedPeer) ReadFrom(b []byte) (int, net.Addr, error) {
	if !p.answered {
		p.answered = true
		_, addr, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			return 0, addr, err
		}
		if _, err = p.PacketConn.WriteTo(nil, addr); err != nil {
			return 0, addr, err
		}
	}
	return p.PacketConn.ReadFrom(b)
}

type result struct {
	Name           string          `json:"name"`
	Settings       json.RawMessage `json:"settings"`
	ClientToServer []string        `json:"clientToServer"`
	ServerToClient []string        `json:"serverToClient"`
}

// run records Xray's client against Xray's server, or against a scripted
// peer: Xray's standalone server measures the client sequence, so it
// refuses one that only the client evaluates.
func run(name, settings string, scripted bool) result {
	cfg := new(conf.HeaderCustomUDP)
	if err := json.Unmarshal([]byte(settings), cfg); err != nil {
		panic(err)
	}
	built, err := cfg.Build()
	if err != nil {
		panic(err)
	}
	clientRaw := &pipe{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 40000}, in: make(chan []byte, 32), closed: make(chan struct{})}
	serverRaw := &pipe{local: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: 443}, in: make(chan []byte, 32), closed: make(chan struct{})}
	clientRaw.peer = serverRaw
	serverRaw.peer = clientRaw
	defer clientRaw.Close()
	defer serverRaw.Close()
	var client, server net.PacketConn
	switch c := built.(type) {
	case *custom.UDPConfig:
		client, err = custom.NewConnClientUDP(c, clientRaw)
		if err == nil {
			server, err = custom.NewConnServerUDP(c, serverRaw)
		}
	case *custom.UDPStandaloneConfig:
		client, err = custom.NewConnClientUDPStandalone(c, clientRaw)
		if err == nil && scripted {
			server = &scriptedPeer{PacketConn: serverRaw}
		} else if err == nil {
			server, err = custom.NewConnServerUDPStandalone(c, serverRaw)
		}
	}
	if err != nil {
		panic(fmt.Sprintf("%s: %v", name, err))
	}
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 8192)
		for i := 0; i < 2; i++ {
			n, addr, err := server.ReadFrom(buf)
			if err != nil {
				done <- err
				return
			}
			if _, err = server.WriteTo(buf[:n], addr); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 2; i++ {
		payload := []byte(fmt.Sprintf("PAYLOAD%d", i))
		if _, err = client.WriteTo(payload, serverRaw.local); err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		buf := make([]byte, 8192)
		n, _, err := client.ReadFrom(buf)
		if err != nil || string(buf[:n]) != string(payload) {
			panic(fmt.Sprintf("%s: echo %x %v", name, buf[:n], err))
		}
	}
	if err = <-done; err != nil {
		panic(err)
	}
	return result{name, json.RawMessage(settings), clientRaw.packets(), serverRaw.packets()}
}

func main() {
	cases := []struct{ name, items string }{
		{"empty", `"client":[],"server":[]`},
		{"fixed", `"client":[{"type":"str","packet":"hello"}],"server":[{"type":"hex","packet":"aabb"}]`},
		{"capture-reuse", `"client":[{"type":"str","packet":"token","capture":"x"},{"reuse":"x"}],"server":[{"reuse":"x"}]`},
		{"random-fixed-range", `"client":[{"rand":4,"randRange":65,"capture":"x"}],"server":[{"reuse":"x"}]`},
		{"transform", `"client":[{"type":"str","packet":"ABCD","capture":"x"},{"transform":{"op":"slice","args":[{"reuse":"x"},{"u64":1},{"u64":2}]},"capture":"slice"}],"server":[{"transform":{"op":"concat","args":[{"reuse":"slice"},{"type":"base64","bytes":"IQ=="}]}}]`},
		{"integer-transform", `"client":[{"transform":{"op":"be16","args":[{"transform":{"op":"xor16","args":[{"u64":443},{"u64":255}]}}]},"capture":"port"}],"server":[{"reuse":"port"}]`},
	}
	// Xray measures a prefix client sequence when it dials, but evaluates a
	// standalone one without measuring it, so a computed length works there.
	standaloneOnly := []struct{ name, items string }{
		{"computed-pad", `"client":[{"transform":{"op":"pad","args":[{"type":"str","bytes":"x"},{"transform":{"op":"shr","args":[{"metadata":"remote_port"},{"u64":6}]}},{"type":"str","bytes":"-"}]}}],"server":[]`},
	}
	var results []result
	for _, mode := range []string{"prefix", "standalone"} {
		for _, c := range cases {
			results = append(results, run(mode+"-"+c.name, `{"mode":"`+mode+`",`+c.items+`}`, false))
		}
	}
	for _, c := range standaloneOnly {
		settings := `{"mode":"standalone",` + c.items + `}`
		prefix := new(conf.HeaderCustomUDP)
		if err := json.Unmarshal([]byte(`{"mode":"prefix",`+c.items+`}`), prefix); err != nil {
			panic(err)
		}
		built, err := prefix.Build()
		if err != nil {
			panic(err)
		}
		if _, err = custom.NewConnClientUDP(built.(*custom.UDPConfig), nil); err == nil {
			panic(c.name + ": a prefix client dialed")
		}
		results = append(results, run("standalone-"+c.name, settings, true))
	}
	encoded, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[1], append(encoded, '\n'), 0600); err != nil {
		panic(err)
	}
}

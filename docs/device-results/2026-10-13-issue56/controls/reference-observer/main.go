package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/core"
	_ "github.com/xtls/xray-core/main/distro/all"
	"github.com/xtls/xray-core/transport/internet"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var mu sync.Mutex
var seq atomic.Uint64

func logrow(r map[string]any) {
	r["time"] = float64(time.Now().UnixNano()) / 1e9
	mu.Lock()
	defer mu.Unlock()
	json.NewEncoder(os.Stdout).Encode(r)
}
func tag(b []byte) string {
	if len(b) != 67 && len(b) != 83 {
		return ""
	}
	q := append([]byte(nil), b[:67]...)
	copy(q[2:12], []byte{1, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	h := sha256.Sum256(q)
	return hex.EncodeToString(h[:8])
}

type packet struct {
	net.PacketConn
	id uint64
}

func (p *packet) ReadFrom(b []byte) (int, net.Addr, error) {
	n, a, e := p.PacketConn.ReadFrom(b)
	r := map[string]any{"event": "reference-udp-read", "socket": p.id, "bytes": n}
	if n > 0 {
		r["tag"] = tag(b[:n])
	}
	if e != nil {
		r["error"] = e.Error()
	}
	logrow(r)
	return n, a, e
}
func (p *packet) WriteTo(b []byte, a net.Addr) (int, error) {
	n, e := p.PacketConn.WriteTo(b, a)
	r := map[string]any{"event": "reference-udp-write", "socket": p.id, "bytes": n, "tag": tag(b)}
	if e != nil {
		r["error"] = e.Error()
	}
	logrow(r)
	return n, e
}
func (p *packet) Close() error {
	e := p.PacketConn.Close()
	logrow(map[string]any{"event": "reference-udp-close", "socket": p.id})
	return e
}

type dialer struct{ internet.DefaultSystemDialer }

func (d *dialer) Dial(ctx context.Context, src net.Address, dest net.Destination, opt *internet.SocketConfig) (net.Conn, error) {
	c, e := d.DefaultSystemDialer.Dial(ctx, src, dest, opt)
	if e == nil {
		if p, ok := c.(*internet.PacketConnWrapper); ok {
			id := seq.Add(1)
			logrow(map[string]any{"event": "reference-udp-open", "socket": id, "local": p.LocalAddr().String(), "remote": p.RemoteAddr().String()})
			p.PacketConn = &packet{p.PacketConn, id}
		}
	}
	return c, e
}
func main() {
	if len(os.Args) == 2 && os.Args[1] == "version" {
		fmt.Println("issue56 diagnostic wrapper; Xray-core 5ca6f4b")
		return
	}
	path := os.Args[len(os.Args)-1]
	b, e := os.ReadFile(path)
	if e != nil {
		panic(e)
	}
	internet.UseAlternativeSystemDialer(&dialer{})
	s, e := core.StartInstance("json", b)
	if e != nil {
		panic(e)
	}
	defer s.Close()
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}

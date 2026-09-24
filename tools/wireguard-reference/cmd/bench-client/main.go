// Benchmark-only SOCKS adapter for the pinned official wireguard-go netstack.
// All tunnel/TCP/UDP behavior belongs to upstream. No host interfaces or routes.
package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type config struct {
	Listen       string   `json:"listen"`
	PrivateKey   string   `json:"private_key"`
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"preshared_key"`
	Endpoint     string   `json:"endpoint"`
	Addresses    []string `json:"addresses"`
	MTU          int      `json:"mtu"`
}

func key(s string) (string, error) {
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil || len(b) != 32 {
		return "", errors.New("invalid key")
	}
	return hex.EncodeToString(b), nil
}
func readAddr(r io.Reader) (netip.AddrPort, error) {
	var t [1]byte
	if _, e := io.ReadFull(r, t[:]); e != nil {
		return netip.AddrPort{}, e
	}
	n := 4
	if t[0] == 4 {
		n = 16
	} else if t[0] != 1 {
		return netip.AddrPort{}, errors.New("benchmark requires IP destination")
	}
	b := make([]byte, n+2)
	if _, e := io.ReadFull(r, b); e != nil {
		return netip.AddrPort{}, e
	}
	ip, _ := netip.AddrFromSlice(b[:n])
	return netip.AddrPortFrom(ip, binary.BigEndian.Uint16(b[n:])), nil
}
func addrBytes(a netip.AddrPort) []byte {
	t := byte(1)
	if a.Addr().Is6() {
		t = 4
	}
	b := append([]byte{t}, a.Addr().AsSlice()...)
	return binary.BigEndian.AppendUint16(b, a.Port())
}
func reply(c net.Conn, a netip.AddrPort) error {
	_, e := c.Write(append([]byte{5, 0, 0}, addrBytes(a)...))
	return e
}
func serve(c net.Conn, n *netstack.Net) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(15 * time.Second))
	var h [2]byte
	if _, e := io.ReadFull(c, h[:]); e != nil || h[0] != 5 || h[1] == 0 {
		return
	}
	methods := make([]byte, int(h[1]))
	if _, e := io.ReadFull(c, methods); e != nil {
		return
	}
	found := false
	for _, m := range methods {
		if m == 0 {
			found = true
		}
	}
	if !found {
		c.Write([]byte{5, 255})
		return
	}
	if _, e := c.Write([]byte{5, 0}); e != nil {
		return
	}
	var q [3]byte
	if _, e := io.ReadFull(c, q[:]); e != nil || q[0] != 5 || q[2] != 0 {
		return
	}
	target, e := readAddr(c)
	if e != nil {
		return
	}
	if q[1] == 1 {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		up, e := n.DialContextTCPAddrPort(ctx, target)
		cancel()
		if e != nil {
			return
		}
		defer up.Close()
		if reply(c, netip.MustParseAddrPort("127.0.0.1:0")) != nil {
			return
		}
		c.SetDeadline(time.Time{})
		done := make(chan struct{})
		go func() { defer close(done); io.Copy(up, c); up.CloseWrite() }()
		io.Copy(c, up)
		if tcp, ok := c.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		<-done
	} else if q[1] == 3 {
		udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if e != nil {
			return
		}
		defer udp.Close()
		if reply(c, udp.LocalAddr().(*net.UDPAddr).AddrPort()) != nil {
			return
		}
		c.SetDeadline(time.Time{})
		go func() { io.Copy(io.Discard, c); udp.Close() }()
		var remote net.Conn
		defer func() {
			if remote != nil {
				remote.Close()
			}
		}()
		var destination netip.AddrPort
		var sender netip.AddrPort
		b := make([]byte, 65535)
		ans := make([]byte, 65535)
		for {
			size, from, e := udp.ReadFromUDPAddrPort(b)
			if e != nil {
				return
			}
			if size < 10 || b[0] != 0 || b[1] != 0 || b[2] != 0 {
				continue
			}
			to, e := readAddr(strings.NewReader(string(b[3:size])))
			if e != nil {
				continue
			}
			header := 3 + len(addrBytes(to))
			if header > size {
				continue
			}
			if remote == nil {
				remote, e = n.Dial("udp", to.String())
				if e != nil {
					return
				}
				destination = to
				sender = from
			}
			if to != destination || from != sender {
				continue
			}
			remote.SetDeadline(time.Now().Add(10 * time.Second))
			if _, e = remote.Write(b[header:size]); e != nil {
				return
			}
			got, e := remote.Read(ans)
			if e != nil {
				return
			}
			packet := append(append([]byte{0, 0, 0}, addrBytes(to)...), ans[:got]...)
			if _, e = udp.WriteToUDPAddrPort(packet, from); e != nil {
				return
			}
		}
	}
}
func run(c config) error {
	l, e := netip.ParseAddrPort(c.Listen)
	if e != nil || !l.Addr().IsLoopback() {
		return errors.New("SOCKS must bind loopback")
	}
	ep, e := netip.ParseAddrPort(c.Endpoint)
	if e != nil || !ep.Addr().IsLoopback() {
		return errors.New("carrier must be loopback")
	}
	if c.MTU < 1280 || c.MTU > 1500 {
		return errors.New("invalid MTU")
	}
	var ips []netip.Addr
	for _, a := range c.Addresses {
		p, e := netip.ParsePrefix(a)
		if e != nil {
			return e
		}
		ips = append(ips, p.Addr())
	}
	if len(ips) == 0 || len(ips) > 2 {
		return errors.New("invalid addresses")
	}
	private, e := key(c.PrivateKey)
	if e != nil {
		return e
	}
	public, e := key(c.PublicKey)
	if e != nil {
		return e
	}
	psk, e := key(c.PresharedKey)
	if e != nil {
		return e
	}
	tun, n, e := netstack.CreateNetTUN(ips, nil, c.MTU)
	if e != nil {
		return e
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, "benchmark: "))
	defer dev.Close()
	ipc := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\npreshared_key=%s\nendpoint=%s\nreplace_allowed_ips=true\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\npersistent_keepalive_interval=1\n", private, public, psk, c.Endpoint)
	if e = dev.IpcSet(ipc); e != nil {
		return e
	}
	if e = dev.Up(); e != nil {
		return e
	}
	listener, e := net.Listen("tcp", c.Listen)
	if e != nil {
		return e
	}
	defer listener.Close()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stop)
	go func() { <-stop; listener.Close() }()
	for {
		c, e := listener.Accept()
		if e != nil {
			return nil
		}
		go serve(c, n)
	}
}
func main() {
	if len(os.Args) != 2 {
		panic("usage: bench-client CONFIG.json")
	}
	f, e := os.Open(os.Args[1])
	if e != nil {
		panic(e)
	}
	var c config
	d := json.NewDecoder(io.LimitReader(f, 8192))
	d.DisallowUnknownFields()
	e = d.Decode(&c)
	f.Close()
	if e == nil {
		e = run(c)
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}

package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/tun"
)

const mtu = 1420

type packetTun struct {
	incoming    chan []byte
	done        chan struct{}
	events      chan tun.Event
	once        sync.Once
	writePacket func([]byte) error
}

func newPacketTun() *packetTun {
	return &packetTun{incoming: make(chan []byte, 8), done: make(chan struct{}), events: make(chan tun.Event)}
}
func (t *packetTun) inject(packet []byte) bool {
	select {
	case t.incoming <- packet:
		return true
	case <-t.done:
		return false
	}
}
func (t *packetTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case packet := <-t.incoming:
		if len(packet) > len(bufs[0])-offset {
			return 0, errors.New("short IP buffer")
		}
		sizes[0] = copy(bufs[0][offset:], packet)
		return 1, nil
	case <-t.done:
		return 0, os.ErrClosed
	}
}
func (t *packetTun) Write(bufs [][]byte, offset int) (int, error) {
	for i, packet := range bufs {
		if offset > len(packet) {
			return i, errors.New("invalid IP offset")
		}
		if err := t.writePacket(packet[offset:]); err != nil {
			return i, err
		}
	}
	return len(bufs), nil
}
func (t *packetTun) File() *os.File           { return nil }
func (t *packetTun) MTU() (int, error)        { return mtu, nil }
func (t *packetTun) Name() (string, error)    { return "wireguard-reference-memory", nil }
func (t *packetTun) Events() <-chan tun.Event { return t.events }
func (t *packetTun) BatchSize() int           { return 1 }
func (t *packetTun) Close() error {
	t.once.Do(func() { close(t.done); close(t.events) })
	return nil
}

// A single loopback socket gives tests an explicit IPv4/IPv6 endpoint without
// opening the reference on the host's public interfaces.
type loopbackBind struct {
	ip     netip.Addr
	mu     sync.Mutex
	socket *net.UDPConn
}
type endpoint struct{ address netip.AddrPort }

func (e *endpoint) ClearSrc()           {}
func (e *endpoint) SrcToString() string { return "" }
func (e *endpoint) DstToString() string { return e.address.String() }
func (e *endpoint) DstIP() netip.Addr   { return e.address.Addr() }
func (e *endpoint) SrcIP() netip.Addr   { return netip.Addr{} }
func (e *endpoint) DstToBytes() []byte {
	return binary.BigEndian.AppendUint16(e.address.Addr().AsSlice(), e.address.Port())
}
func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	network := "udp4"
	if b.ip.Is6() {
		network = "udp6"
	}
	socket, err := net.ListenUDP(network, net.UDPAddrFromAddrPort(netip.AddrPortFrom(b.ip, port)))
	if err != nil {
		return nil, 0, err
	}
	b.socket = socket
	receive := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, address, err := socket.ReadFromUDPAddrPort(bufs[0])
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		eps[0] = &endpoint{address}
		return 1, nil
	}
	return []conn.ReceiveFunc{receive}, uint16(socket.LocalAddr().(*net.UDPAddr).Port), nil
}
func (b *loopbackBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.socket == nil {
		return nil
	}
	err := b.socket.Close()
	b.socket = nil
	return err
}
func (b *loopbackBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	e, ok := ep.(*endpoint)
	if !ok || !e.address.Addr().IsLoopback() {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	socket := b.socket
	b.mu.Unlock()
	if socket == nil {
		return net.ErrClosed
	}
	for _, packet := range bufs {
		if _, err := socket.WriteToUDPAddrPort(packet, e.address); err != nil {
			return err
		}
	}
	return nil
}
func (b *loopbackBind) ParseEndpoint(value string) (conn.Endpoint, error) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.Addr().IsLoopback() {
		return nil, errors.New("non-loopback endpoint")
	}
	return &endpoint{address}, nil
}
func (b *loopbackBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errors.New("marks unsupported by reference")
	}
	return nil
}
func (b *loopbackBind) BatchSize() int { return 1 }

var _ tun.Device = (*packetTun)(nil)
var _ conn.Bind = (*loopbackBind)(nil)

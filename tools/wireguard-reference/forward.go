package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var testNetworks = []netip.Prefix{
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
}

func loopbackTarget(id stack.TransportEndpointID, redirect uint16) (string, bool) {
	ip, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return "", false
	}
	for _, prefix := range testNetworks {
		if prefix.Contains(ip) {
			port := id.LocalPort
			if redirect != 0 {
				port = redirect
			}
			return fmt.Sprintf("127.0.0.1:%d", port), port != 0
		}
	}
	return "", false
}

func attachForwarder(t *packetTun, redirect uint16) (func(), error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(8, mtu, "")
	ctx, cancel := context.WithCancel(context.Background())
	cleanup := func() { cancel(); ep.Close(); s.Close() }
	if err := s.CreateNIC(1, ep); err != nil {
		cleanup()
		return nil, fmt.Errorf("reference NIC: %s", err)
	}
	if err := s.SetPromiscuousMode(1, true); err != nil {
		cleanup()
		return nil, fmt.Errorf("reference mode: %s", err)
	}
	if err := s.SetSpoofing(1, true); err != nil {
		cleanup()
		return nil, fmt.Errorf("reference routes: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: 1},
		{Destination: header.IPv6EmptySubnet, NIC: 1},
	})
	t.writePacket = func(packet []byte) error {
		if len(packet) == 0 || len(packet) > mtu {
			return nil
		}
		var protocol tcpip.NetworkProtocolNumber
		switch packet[0] >> 4 {
		case 4:
			protocol = ipv4.ProtocolNumber
		case 6:
			protocol = ipv6.ProtocolNumber
		default:
			return nil
		}
		p := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), packet...))})
		ep.InjectInbound(protocol, p)
		p.DecRef()
		return nil
	}
	go func() {
		for {
			packet := ep.ReadContext(ctx)
			if packet == nil {
				return
			}
			view := packet.ToView()
			bytes := append([]byte(nil), view.AsSlice()...)
			view.Release()
			packet.DecRef()
			if !t.inject(bytes) {
				return
			}
		}
	}()
	slots := make(chan struct{}, 32)
	claim := func() bool {
		select {
		case slots <- struct{}{}:
			return true
		default:
			return false
		}
	}
	tcpForwarder := tcp.NewForwarder(s, 0, 32, func(r *tcp.ForwarderRequest) {
		target, allowed := loopbackTarget(r.ID(), redirect)
		if !allowed || !claim() {
			r.Complete(true)
			return
		}
		go func() {
			defer func() { <-slots }()
			var queue waiter.Queue
			endpoint, err := r.CreateEndpoint(&queue)
			if err != nil {
				r.Complete(true)
				return
			}
			r.Complete(false)
			inner := gonet.NewTCPConn(&queue, endpoint)
			defer inner.Close()
			host, dialErr := net.DialTimeout("tcp4", target, 3*time.Second)
			if dialErr != nil {
				return
			}
			defer host.Close()
			_ = host.SetDeadline(time.Now().Add(time.Minute))
			_ = inner.SetDeadline(time.Now().Add(time.Minute))
			var copies sync.WaitGroup
			copies.Add(1)
			go func() { defer copies.Done(); _, _ = io.Copy(host, inner); _ = host.(*net.TCPConn).CloseWrite() }()
			_, _ = io.Copy(inner, host)
			_ = inner.CloseWrite()
			copies.Wait()
		}()
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) bool {
		target, allowed := loopbackTarget(r.ID(), redirect)
		if !allowed || !claim() {
			return false
		}
		var queue waiter.Queue
		endpoint, err := r.CreateEndpoint(&queue)
		if err != nil {
			<-slots
			return false
		}
		inner := gonet.NewUDPConn(&queue, endpoint)
		go func() {
			defer func() { <-slots }()
			defer inner.Close()
			host, err := net.Dial("udp4", target)
			if err != nil {
				return
			}
			defer host.Close()
			finished := make(chan struct{}, 1)
			copyPackets := func(dst, src net.Conn) {
				packet := make([]byte, mtu)
				for {
					_ = src.SetReadDeadline(time.Now().Add(10 * time.Second))
					n, err := src.Read(packet)
					if err != nil {
						return
					}
					_ = dst.SetWriteDeadline(time.Now().Add(time.Second))
					if _, err := dst.Write(packet[:n]); err != nil {
						return
					}
				}
			}
			go func() { copyPackets(host, inner); finished <- struct{}{} }()
			go func() { copyPackets(inner, host); finished <- struct{}{} }()
			<-finished
		}()
		return true
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)
	return cleanup, nil
}

// Records what Xray-core's own code writes on a VLESS reverse proxy: the
// frames its portal sends over the reverse Mux.Cool connection (mux.Writer
// with the client's inbound, as fetchInput sets it under IsReverseMux), the
// frames its bridge answers with (mux.NewResponseWriter, as the server
// worker's handle writes them), the portal's control messages, and the VLESS
// request that opens a tunnel. Nothing is random, so a fresh run matches
// tests/fixtures/reverse/vectors.json byte for byte.
// Run with go -C <pinned checkout> run -mod=readonly <this file> out.json.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/xtls/xray-core/app/reverse"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/uuid"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/encoding"
	"google.golang.org/protobuf/proto"
)

type endpoint struct {
	Network string `json:"network"`
	Address string `json:"address"`
	Port    uint16 `json:"port"`
}

type frame struct {
	Name    string    `json:"name"`
	Session uint16    `json:"session"`
	Status  byte      `json:"status"`
	Error   bool      `json:"error"`
	Target  *endpoint `json:"target"`
	Source  *endpoint `json:"source"`
	Local   *endpoint `json:"local"`
	Payload *string   `json:"payload"`
	Wire    string    `json:"wire"`
}

type control struct {
	State  int32  `json:"state"`
	Random string `json:"random"`
	Wire   string `json:"wire"`
}

type request struct {
	Flow string `json:"flow"`
	Wire string `json:"wire"`
}

type result struct {
	Portal  []frame   `json:"portal"`
	Bridge  []frame   `json:"bridge"`
	Control []control `json:"control"`
	Request []request `json:"request"`
}

// capture keeps each frame a mux writer hands over: one WriteMultiBuffer
// call per frame.
type capture struct {
	frames [][]byte
}

func (c *capture) WriteMultiBuffer(mb buf.MultiBuffer) error {
	var b bytes.Buffer
	for _, part := range mb {
		b.Write(part.Bytes())
	}
	buf.ReleaseMulti(mb)
	c.frames = append(c.frames, b.Bytes())
	return nil
}

func (c *capture) take() []byte {
	if len(c.frames) != 1 {
		panic("expected one frame")
	}
	f := c.frames[0]
	c.frames = nil
	return f
}

func describe(d net.Destination) *endpoint {
	if !d.IsValid() && d.Address == nil {
		return nil
	}
	e := &endpoint{Port: uint16(d.Port)}
	switch d.Network {
	case net.Network_TCP:
		e.Network = "tcp"
	case net.Network_UDP:
		e.Network = "udp"
	}
	if d.Address.Family().IsDomain() {
		e.Address = d.Address.Domain()
	} else {
		e.Address = d.Address.IP().String()
	}
	return e
}

func payload(data []byte) *string {
	if data == nil {
		return nil
	}
	s := hex.EncodeToString(data)
	return &s
}

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = seed + byte(i*7)
	}
	return b
}

func packet(data []byte, from *net.Destination) buf.MultiBuffer {
	b := buf.New()
	b.Write(data)
	if from != nil {
		d := *from
		b.UDP = &d
	}
	return buf.MultiBuffer{b}
}

func main() {
	var out result
	tcp := func(addr string, port uint16) net.Destination {
		return net.TCPDestination(net.ParseAddress(addr), net.Port(port))
	}
	udp := func(addr string, port uint16) net.Destination {
		return net.UDPDestination(net.ParseAddress(addr), net.Port(port))
	}
	var c capture
	portal := func(name string, id uint16, status mux.SessionStatus, target, source, local *net.Destination, data []byte) {
		f := frame{Name: name, Session: id, Status: byte(status), Payload: payload(data), Wire: hex.EncodeToString(c.take())}
		if target != nil {
			f.Target = describe(*target)
		}
		if source != nil {
			f.Source = describe(*source)
		}
		if local != nil {
			f.Local = describe(*local)
		}
		out.Portal = append(out.Portal, f)
	}

	// The control session: udp reverse:0, opened without a payload, then
	// one message per frame.
	ctlDest := net.UDPDestination(net.DomainAddress("reverse"), 0)
	ctl := mux.NewWriter(1, ctlDest, &c, protocol.TransferTypePacket, [8]byte{}, nil)
	ctl.WriteMultiBuffer(buf.MultiBuffer{})
	portal("control opens", 1, mux.SessionStatusNew, &ctlDest, nil, nil, nil)
	for _, m := range []struct {
		name  string
		state reverse.Control_State
		rand  []byte
	}{
		{"control active", reverse.Control_ACTIVE, pattern(13, 1)},
		{"control drain", reverse.Control_DRAIN, pattern(64, 0xc0)},
	} {
		message, err := proto.Marshal(&reverse.Control{State: m.state, Random: m.rand})
		if err != nil {
			panic(err)
		}
		ctl.WriteMultiBuffer(buf.MergeBytes(nil, message))
		portal(m.name, 1, mux.SessionStatusKeep, nil, nil, nil, message)
		out.Control = append(out.Control, control{State: int32(m.state), Random: hex.EncodeToString(m.rand), Wire: hex.EncodeToString(message)})
	}
	message, err := proto.Marshal(&reverse.Control{State: reverse.Control_State(5), Random: []byte{0x42}})
	if err != nil {
		panic(err)
	}
	out.Control = append(out.Control, control{State: 5, Random: "42", Wire: hex.EncodeToString(message)})
	ctl.Close()
	portal("control ends", 1, mux.SessionStatusEnd, nil, nil, nil, nil)

	// A TCP session from a client of the portal, its first payload in the
	// New frame, then more of the stream.
	target := tcp("127.0.0.1", 8080)
	source := tcp("198.51.100.7", 40000)
	local := tcp("203.0.113.1", 443)
	w := mux.NewWriter(2, target, &c, protocol.TransferTypeStream, [8]byte{}, &session.Inbound{Source: source, Local: local})
	w.WriteMultiBuffer(buf.MergeBytes(nil, []byte("GET / HTTP/1.1\r\n")))
	portal("tcp opens with data", 2, mux.SessionStatusNew, &target, &source, &local, []byte("GET / HTTP/1.1\r\n"))
	long := pattern(8192, 3)
	w.WriteMultiBuffer(buf.MergeBytes(nil, long))
	portal("tcp keeps 8 KiB", 2, mux.SessionStatusKeep, nil, nil, nil, long)
	w.Close()
	portal("tcp ends", 2, mux.SessionStatusEnd, nil, nil, nil, nil)

	// A domain target from an IPv6 client, opened without a payload.
	target = tcp("service.example", 443)
	source = tcp("2001:db8::7", 50000)
	local = tcp("192.0.2.1", 8443)
	w = mux.NewWriter(3, target, &c, protocol.TransferTypeStream, [8]byte{}, &session.Inbound{Source: source, Local: local})
	w.WriteMultiBuffer(buf.MultiBuffer{})
	portal("domain opens from ipv6", 3, mux.SessionStatusNew, &target, &source, &local, nil)

	// A client without a local address: only the source goes out.
	target = tcp("10.0.0.2", 22)
	source = tcp("198.51.100.8", 1)
	w = mux.NewWriter(4, target, &c, protocol.TransferTypeStream, [8]byte{}, &session.Inbound{Source: source})
	w.WriteMultiBuffer(buf.MultiBuffer{})
	portal("source only", 4, mux.SessionStatusNew, &target, &source, nil, nil)

	// A UDP session: no global ID beside the client's addresses, then a
	// datagram for another address and one for the session's target.
	target = udp("10.0.0.53", 53)
	source = udp("198.51.100.9", 5353)
	local = udp("203.0.113.1", 53)
	w = mux.NewWriter(5, target, &c, protocol.TransferTypePacket, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, &session.Inbound{Source: source, Local: local})
	w.WriteMultiBuffer(packet([]byte("query"), &target))
	portal("udp opens with a datagram", 5, mux.SessionStatusNew, &target, &source, &local, []byte("query"))
	other := udp("192.0.2.99", 9999)
	w.WriteMultiBuffer(packet([]byte("elsewhere"), &other))
	portal("udp datagram for another address", 5, mux.SessionStatusKeep, &other, nil, nil, []byte("elsewhere"))
	w.WriteMultiBuffer(packet([]byte("again"), nil))
	portal("udp datagram for the target", 5, mux.SessionStatusKeep, nil, nil, nil, []byte("again"))

	// An End with the error flag, and a keepalive.
	b := buf.New()
	mux.FrameMetadata{SessionID: 6, SessionStatus: mux.SessionStatusEnd, Option: mux.OptionError}.WriteTo(b)
	c.WriteMultiBuffer(buf.MultiBuffer{b})
	f := frame{Name: "end with error", Session: 6, Status: byte(mux.SessionStatusEnd), Error: true, Wire: hex.EncodeToString(c.take())}
	out.Portal = append(out.Portal, f)
	b = buf.New()
	mux.FrameMetadata{SessionID: 0, SessionStatus: mux.SessionStatusKeepAlive}.WriteTo(b)
	c.WriteMultiBuffer(buf.MultiBuffer{b})
	out.Portal = append(out.Portal, frame{Name: "keepalive", Session: 0, Status: byte(mux.SessionStatusKeepAlive), Wire: hex.EncodeToString(c.take())})

	// What the bridge answers with, as its worker's handle writes it.
	bridge := func(name string, id uint16, status mux.SessionStatus, isErr bool, source *net.Destination, data []byte) {
		f := frame{Name: name, Session: id, Status: byte(status), Error: isErr, Payload: payload(data), Wire: hex.EncodeToString(c.take())}
		if source != nil {
			f.Target = describe(*source)
		}
		out.Bridge = append(out.Bridge, f)
	}
	r := mux.NewResponseWriter(2, &c, protocol.TransferTypeStream)
	r.WriteMultiBuffer(buf.MergeBytes(nil, []byte("HTTP/1.1 200 OK\r\n")))
	bridge("stream answer", 2, mux.SessionStatusKeep, false, nil, []byte("HTTP/1.1 200 OK\r\n"))
	r.WriteMultiBuffer(buf.MergeBytes(nil, long))
	bridge("stream answer of 8 KiB", 2, mux.SessionStatusKeep, false, nil, long)
	r.Close()
	bridge("stream ends", 2, mux.SessionStatusEnd, false, nil, nil)
	r = mux.NewResponseWriter(5, &c, protocol.TransferTypePacket)
	for _, from := range []net.Destination{udp("10.0.0.53", 53), udp("2001:db8::53", 5353)} {
		r.WriteMultiBuffer(packet([]byte("answer"), &from))
		bridge("datagram from "+from.NetAddr(), 5, mux.SessionStatusKeep, false, &from, []byte("answer"))
	}
	b = buf.New()
	mux.FrameMetadata{SessionID: 7, SessionStatus: mux.SessionStatusEnd, Option: mux.OptionError}.WriteTo(b)
	c.WriteMultiBuffer(buf.MultiBuffer{b})
	bridge("ends with error", 7, mux.SessionStatusEnd, true, nil, nil)

	// The request that opens a tunnel: the reverse command, no address.
	id, err := uuid.ParseString("27848739-7e62-4138-9fd3-098a63964b6b")
	if err != nil {
		panic(err)
	}
	user := &protocol.MemoryUser{Account: &vless.MemoryAccount{ID: protocol.NewID(id)}}
	for _, flow := range []string{"", vless.XRV} {
		var header bytes.Buffer
		err := encoding.EncodeRequestHeader(&header, &protocol.RequestHeader{
			Version: encoding.Version,
			User:    user,
			Command: protocol.RequestCommandRvs,
			Address: net.DomainAddress("v1.rvs.cool"),
			Port:    0,
		}, &encoding.Addons{Flow: flow})
		if err != nil {
			panic(err)
		}
		out.Request = append(out.Request, request{Flow: flow, Wire: hex.EncodeToString(header.Bytes())})
	}

	encoded, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	if err = os.WriteFile(os.Args[1], append(encoded, '\n'), 0600); err != nil {
		panic(err)
	}
}

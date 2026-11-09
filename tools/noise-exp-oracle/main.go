// Command noise-exp-oracle writes the vectors xray-rust's noise tests compare
// against: how Xray-core's configuration reads each `exp` packet of the
// FinalMask noise mask, and the noise packets its finalmask then sends for
// expressions without random parts, `<c>` counters included. Run it inside a
// pinned Xray-core checkout:
//
//	go -C Xray-core run -mod=readonly ../tools/noise-exp-oracle/main.go out.json
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/transport/internet/finalmask"
	"github.com/xtls/xray-core/transport/internet/finalmask/noise"
)

type capture struct{ sent [][]byte }

func (c *capture) ReadFrom(p []byte) (int, net.Addr, error) { return 0, nil, fmt.Errorf("eof") }
func (c *capture) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.sent = append(c.sent, append([]byte(nil), p...))
	return len(p), nil
}
func (c *capture) Close() error                       { return nil }
func (c *capture) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (c *capture) SetDeadline(t time.Time) error      { return nil }
func (c *capture) SetReadDeadline(t time.Time) error  { return nil }
func (c *capture) SetWriteDeadline(t time.Time) error { return nil }

type segment struct {
	Kind  string `json:"kind"`
	Bytes string `json:"bytes,omitempty"`
	Min   int64  `json:"min,omitempty"`
	Max   int64  `json:"max,omitempty"`
}

type parsed struct {
	// The JSON value of the item's `packet`.
	Packet   json.RawMessage `json:"packet"`
	Rand     int32           `json:"rand,omitempty"`
	Segments []segment       `json:"segments,omitempty"`
	Error    string          `json:"error,omitempty"`
}

type item struct {
	Exp      string    `json:"exp"`
	Segments []segment `json:"segments"`
}

type send struct {
	Items   []item   `json:"items"`
	Payload string   `json:"payload"`
	Sent    []string `json:"sent"`
}

// build reads one noise item as Xray-core's configuration does.
func build(packet json.RawMessage, rand int32) (*noise.Config, error) {
	mask := &conf.NoiseMask{Noise: []conf.NoiseItem{{
		Type:   "exp",
		Packet: packet,
		Rand:   conf.Int32Range{From: rand, To: rand},
	}}}
	config, err := mask.Build()
	if err != nil {
		return nil, err
	}
	return config.(*noise.Config), nil
}

func segments(config *noise.Config) []segment {
	var out []segment
	for _, s := range config.Items[0].Segments {
		out = append(out, segment{
			Kind:  s.Kind.String(),
			Bytes: hex.EncodeToString(s.Bytes),
			Min:   s.MinSize,
			Max:   s.MaxSize,
		})
	}
	return out
}

func quoted(exp string) json.RawMessage {
	raw, err := json.Marshal(exp)
	if err != nil {
		panic(err)
	}
	return raw
}

func main() {
	var cases []parsed
	add := func(packet json.RawMessage, rand int32) {
		c := parsed{Packet: packet, Rand: rand}
		if config, err := build(packet, rand); err != nil {
			c.Error = err.Error()
		} else {
			c.Segments = segments(config)
		}
		cases = append(cases, c)
	}
	for _, exp := range []string{
		// Read.
		"<b 01 02 03>", "<b 0x0a0B>", "<b\t0X ff>", "<b 0x0Xab>", "<b  01 02>",
		"<r 5>", "<r 1-3>", "<rc 4>", "<rd 2-6>", "<r 0>", "<r 0-0>", "<r 65535>", "<r +3>",
		"<r 2 >", "<rc\n7\r>", "<t>", "<c>", "<n>", "<t >", "< t>", "<\tc\t>",
		"  <b 01>\n<c>\t<t>  ", " <c> ", "<b 01><b 02>", "<r 3-3><rd 1><rc 2-4><n>",
		// Refused.
		"", "   ", "<x>", "<B 01>", "<b>", "<b 0x>", "<b 123>", "<b zz>", "<b +1>",
		"<b 0X0xab>", "<r>", "<r 3-1>", "<r -1>", "<r 65536>", "<r 1 - 3>", "<r 1-3-5>",
		"<r 1x>", "<t 1>", "<c x>", "<n 8>", "abc", "<b 01> junk", "junk <b 01>", "<b 01",
		"<rd5>", "<\vt>", "<t\v>", "<r 1\v>", "<b 01 <c>", "<<t>", "<t>>", "<t><", "<>",
		"< >", "<1>", "<r 5>",
	} {
		add(quoted(exp), 0)
	}
	// A packet that is not a string, and a random length beside it.
	add(json.RawMessage(`5`), 0)
	add(json.RawMessage(`null`), 0)
	add(quoted("<b 01>"), 3)

	var sends []send
	for _, exps := range [][]string{
		{"<b 0102><c>", "<c><b 03>"},
		{"<c><c><c>"},
		{"<b 00 11 22 33 44 55 66 77 88 99 aa bb cc dd ee ff>"},
	} {
		var masks []finalmask.UDPMask
		s := send{Payload: hex.EncodeToString([]byte("payload"))}
		config := &noise.Config{}
		for _, exp := range exps {
			one, err := build(quoted(exp), 0)
			if err != nil {
				panic(err)
			}
			config.Items = append(config.Items, one.Items...)
			s.Items = append(s.Items, item{Exp: exp, Segments: segments(one)})
		}
		masks = append(masks, config)
		c := &capture{}
		fm := finalmask.NewFinalMask(nil, masks, nil, nil,
			func(ctx context.Context, dest xnet.Destination) (net.PacketConn, net.Addr, error) {
				return c, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1}, nil
			}, nil)
		conn, err := fm.DialUDP(context.Background(), xnet.UDPDestination(xnet.ParseAddress("192.0.2.1"), 1))
		if err != nil {
			panic(err)
		}
		if _, err := conn.Write([]byte("payload")); err != nil {
			panic(err)
		}
		for _, sent := range c.sent {
			s.Sent = append(s.Sent, hex.EncodeToString(sent))
		}
		sends = append(sends, s)
	}

	out, err := json.MarshalIndent(map[string]interface{}{"cases": cases, "sends": sends}, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(os.Args[1], append(out, '\n'), 0o644); err != nil {
		panic(err)
	}
}

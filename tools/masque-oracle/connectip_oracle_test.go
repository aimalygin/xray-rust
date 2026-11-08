// Records what Xray-core v26.10.31's connectip package writes and reads:
// CONNECT-IP capsules, the datagrams composeDatagram builds, the ICMP
// messages composeICMPTooLargePacket builds, which incoming packets
// handleIncomingProxiedPacket accepts and what ReadPacket takes from the
// datagrams of a capsule stream. Randomness is seeded, so a fresh run
// matches tests/fixtures/masque/connectip-vectors.json byte for byte.
//
// It runs inside the package, added without touching the checkout:
//
//	go -C <pinned checkout> test -overlay overlay.json \
//	    ./transport/internet/masque/connectip -run TestXrayRustOracle
//
// where overlay.json maps connectip/xray_rust_oracle_test.go to this file,
// and MASQUE_ORACLE_OUT names the output file. MASQUE_ORACLE_FULL=1 writes
// the ten times larger corpus scripts/check-masque-interop.sh reads.
package connectip

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"slices"
	"testing"

	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"
)

type xrayRustAddress struct {
	RequestID uint64 `json:"requestId"`
	Prefix    string `json:"prefix"`
}

type xrayRustRoute struct {
	Start    string `json:"start"`
	End      string `json:"end"`
	Protocol uint8  `json:"protocol"`
}

type xrayRustEncode struct {
	Kind    string            `json:"kind"`
	Entries []xrayRustAddress `json:"entries"`
	Bytes   string            `json:"bytes"`
}

type xrayRustParse struct {
	Kind    uint64            `json:"kind"`
	Value   string            `json:"value"`
	Entries []xrayRustAddress `json:"entries,omitempty"`
	Routes  []xrayRustRoute   `json:"routes,omitempty"`
	Error   bool              `json:"error,omitempty"`
	Limit   bool              `json:"limit,omitempty"`
}

type xrayRustCompose struct {
	Packet string `json:"packet"`
	// Capsule: the DATAGRAM capsule form of HTTP/2; bare: without a
	// context ID, as WARP over HTTP/2.
	Capsule bool   `json:"capsule"`
	Bare    bool   `json:"bare"`
	Out     string `json:"out,omitempty"`
	Dropped bool   `json:"dropped,omitempty"`
}

type xrayRustIcmp struct {
	Packet   string `json:"packet"`
	MTU      int    `json:"mtu"`
	Out      string `json:"out,omitempty"`
	TooSmall bool   `json:"tooSmall,omitempty"`
	Error    bool   `json:"error,omitempty"`
}

type xrayRustIncoming struct {
	Packet   string          `json:"packet"`
	Assigned []string        `json:"assigned"`
	Routes   []xrayRustRoute `json:"routes"`
	Peer     []string        `json:"peer"`
	Allowed  bool            `json:"allowed"`
}

// xrayRustRead is a DATAGRAM capsule's value as ReadPacket reads it over
// HTTP/2: the packet after its context ID, or, bare, as WARP sends it.
type xrayRustRead struct {
	Datagram string `json:"datagram"`
	Bare     bool   `json:"bare"`
	Packet   string `json:"packet,omitempty"`
	Dropped  bool   `json:"dropped,omitempty"`
}

type xrayRustVectors struct {
	Encode   []xrayRustEncode   `json:"encode"`
	Parse    []xrayRustParse    `json:"parse"`
	Compose  []xrayRustCompose  `json:"compose"`
	Icmp     []xrayRustIcmp     `json:"icmp"`
	Incoming []xrayRustIncoming `json:"incoming"`
	Read     []xrayRustRead     `json:"read"`
}

// Fixtures carry no globally routable address (scripts/tests/
// check-json-fixture-safety.py), so addresses come from private,
// documentation and link-local space, and prefixes stay inside it.
var (
	xrayRustV4Space = []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
	}
	xrayRustV6Space = []netip.Prefix{
		netip.MustParsePrefix("fd00::/8"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("fe80::/10"),
	}
)

// xrayRustAddr draws an address of the family inside the space above.
func xrayRustAddr(r *rand.Rand, v4 bool) (netip.Addr, int) {
	space := xrayRustV6Space
	if v4 {
		space = xrayRustV4Space
	}
	base := space[r.IntN(len(space))]
	b := base.Addr().AsSlice()
	for i := base.Bits(); i < len(b)*8; i++ {
		if r.IntN(2) == 1 {
			b[i/8] |= 1 << (7 - i%8)
		}
	}
	addr, _ := netip.AddrFromSlice(b)
	return addr, base.Bits()
}

// xrayRustLocal reports whether an address may appear in a fixture: inside
// the space above, unspecified, or in 0.0.0.0/8, where the routes start.
func xrayRustLocal(addr netip.Addr) bool {
	if addr.IsUnspecified() || addr.Is4() && addr.As4()[0] == 0 {
		return true
	}
	for _, p := range append(slices.Clone(xrayRustV4Space), xrayRustV6Space...) {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// xrayRustLocalResult reports whether a parse result names only such
// addresses; a mutated capsule can name others, and is drawn again.
func xrayRustLocalResult(result xrayRustParse) bool {
	for _, e := range result.Entries {
		if !xrayRustLocal(netip.MustParsePrefix(e.Prefix).Addr()) {
			return false
		}
	}
	for _, route := range result.Routes {
		if !xrayRustLocal(netip.MustParseAddr(route.Start)) || !xrayRustLocal(netip.MustParseAddr(route.End)) {
			return false
		}
	}
	return true
}

func xrayRustPrefix(r *rand.Rand, v4 bool) netip.Prefix {
	if r.IntN(12) == 0 {
		// The whole family, whose network address is unspecified.
		if v4 {
			return netip.PrefixFrom(netip.IPv4Unspecified(), 0)
		}
		return netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	}
	addr, bits := xrayRustAddr(r, v4)
	return netip.PrefixFrom(addr, bits+r.IntN(addr.BitLen()-bits+1)).Masked()
}

var xrayRustRequestIDs = []uint64{0, 1, 2, 63, 64, 16383, 16384, 1 << 30, 1<<62 - 1}

func xrayRustEntries(r *rand.Rand, n int, request bool) ([]AssignedAddress, []xrayRustAddress) {
	var entries []AssignedAddress
	var out []xrayRustAddress
	for range n {
		id := xrayRustRequestIDs[r.IntN(len(xrayRustRequestIDs))]
		if request && id == 0 {
			id = 1
		}
		var prefix netip.Prefix
		switch r.IntN(6) {
		case 0:
			prefix = rejectedIPv4Prefix
		case 1:
			prefix = rejectedIPv6Prefix
		default:
			prefix = xrayRustPrefix(r, r.IntN(2) == 0)
		}
		entries = append(entries, AssignedAddress{RequestID: AddressRequestID(id), IPPrefix: prefix})
		out = append(out, xrayRustAddress{RequestID: id, Prefix: prefix.String()})
	}
	return entries, out
}

func xrayRustParseValue(kind uint64, value []byte) xrayRustParse {
	result := xrayRustParse{Kind: kind, Value: hex.EncodeToString(value)}
	data := quicvarint.Append(nil, kind)
	data = quicvarint.Append(data, uint64(len(value)))
	data = append(data, value...)
	_, cr, err := http3.NewCapsuleParser(bytes.NewReader(data)).Next()
	if err != nil {
		panic(err)
	}
	var parseErr error
	switch http3.CapsuleType(kind) {
	case capsuleTypeAddressAssign, capsuleTypeAddressRequest:
		var addresses []AssignedAddress
		if http3.CapsuleType(kind) == capsuleTypeAddressAssign {
			var c *addressAssignCapsule
			if c, parseErr = parseAddressAssignCapsule(cr); parseErr == nil {
				addresses = c.AssignedAddresses
			}
		} else {
			var c *addressRequestCapsule
			if c, parseErr = parseAddressRequestCapsule(cr); parseErr == nil {
				for i, p := range c.Prefixes {
					addresses = append(addresses, AssignedAddress{RequestID: c.RequestIDs[i], IPPrefix: p})
				}
			}
		}
		for _, a := range addresses {
			result.Entries = append(result.Entries, xrayRustAddress{RequestID: uint64(a.RequestID), Prefix: a.IPPrefix.String()})
		}
	case capsuleTypeRouteAdvertisement:
		var c *routeAdvertisementCapsule
		if c, parseErr = parseRouteAdvertisementCapsule(cr); parseErr == nil {
			for _, route := range c.IPAddressRanges {
				result.Routes = append(result.Routes, xrayRustRoute{route.StartIP.String(), route.EndIP.String(), route.IPProtocol})
			}
		}
	}
	if parseErr != nil {
		result.Error = true
		result.Entries, result.Routes = nil, nil
		result.Limit = errors.Is(parseErr, errCapsuleLimit)
	}
	return result
}

func xrayRustRoutes(r *rand.Rand, ordered bool) ([]IPRoute, []byte) {
	var routes []IPRoute
	var start uint32
	for range 1 + r.IntN(5) {
		begin := start + r.Uint32N(1<<20)
		end := begin + r.Uint32N(1<<20)
		start = end + 1 + r.Uint32N(16)
		var b, e [4]byte
		binary.BigEndian.PutUint32(b[:], begin)
		binary.BigEndian.PutUint32(e[:], end)
		routes = append(routes, IPRoute{StartIP: netip.AddrFrom4(b), EndIP: netip.AddrFrom4(e)})
	}
	if r.IntN(2) == 0 {
		lo := netip.MustParseAddr("2001:db8::")
		hi := netip.MustParseAddr("2001:db8::ffff")
		routes = append(routes, IPRoute{StartIP: lo, EndIP: hi, IPProtocol: uint8(r.IntN(3) * 6)})
	}
	if !ordered && len(routes) > 1 {
		i, j := r.IntN(len(routes)), r.IntN(len(routes))
		routes[i], routes[j] = routes[j], routes[i]
		if i == j {
			routes[0].EndIP = routes[1].StartIP
		}
	}
	return routes, (&routeAdvertisementCapsule{IPAddressRanges: routes}).append(nil)
}

// xrayRustFull selects the larger corpus with full-size payloads.
var xrayRustFull = os.Getenv("MASQUE_ORACLE_FULL") == "1"

func xrayRustCount(n int) int {
	if xrayRustFull {
		return n * 10
	}
	return n
}

// xrayRustPacket draws a packet: mostly well formed, of either family, with
// small payloads unless large asks for some of full size.
func xrayRustPacket(r *rand.Rand, large bool) []byte {
	switch r.IntN(10) {
	case 0:
		return nil
	case 1:
		b := make([]byte, r.IntN(60))
		for i := range b {
			b[i] = byte(r.Uint32())
		}
		return b
	}
	size := r.IntN(64)
	if xrayRustFull {
		size = r.IntN(1500)
	} else if large && r.IntN(10) == 0 {
		size = 1200 + r.IntN(300)
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(r.Uint32())
	}
	ttls := []byte{0, 1, 2, 64, 255}
	if r.IntN(2) == 0 {
		ihl := 5
		if r.IntN(4) == 0 {
			ihl = 5 + r.IntN(11)
		}
		b := make([]byte, ihl*4+len(payload))
		b[0] = 0x40 | byte(ihl)
		total := len(b)
		switch r.IntN(8) {
		case 0:
			total += 1 + r.IntN(20)
		case 1:
			total = r.IntN(ihl * 4)
		case 2:
			b = append(b, make([]byte, 1+r.IntN(30))...)
		}
		binary.BigEndian.PutUint16(b[2:4], uint16(total))
		b[8] = ttls[r.IntN(len(ttls))]
		b[9] = []byte{1, 6, 17}[r.IntN(3)]
		for i := 20; i < ihl*4; i++ {
			b[i] = byte(r.Uint32())
		}
		src, _ := xrayRustAddr(r, true)
		dst, _ := xrayRustAddr(r, true)
		copy(b[12:16], src.AsSlice())
		copy(b[16:20], dst.AsSlice())
		copy(b[ihl*4:], payload)
		return b
	}
	b := make([]byte, 40+len(payload))
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(len(payload)))
	b[6] = []byte{58, 6, 17}[r.IntN(3)]
	b[7] = ttls[r.IntN(len(ttls))]
	src, _ := xrayRustAddr(r, false)
	dst, _ := xrayRustAddr(r, false)
	copy(b[8:24], src.AsSlice())
	copy(b[24:40], dst.AsSlice())
	copy(b[40:], payload)
	return b
}

func TestXrayRustOracle(t *testing.T) {
	out := os.Getenv("MASQUE_ORACLE_OUT")
	if out == "" {
		t.Skip("MASQUE_ORACLE_OUT is not set")
	}
	r := rand.New(rand.NewPCG(0x4d415351, 0x55452d4950))
	var v xrayRustVectors

	// What a client writes: its address request and its refusals.
	v.Encode = append(v.Encode, xrayRustEncode{
		Kind: "request",
		Entries: []xrayRustAddress{
			{RequestID: 1, Prefix: "0.0.0.0/32"},
			{RequestID: 2, Prefix: "::/128"},
		},
		Bytes: hex.EncodeToString((&addressRequestCapsule{
			RequestIDs: []AddressRequestID{1, 2},
			Prefixes:   []netip.Prefix{rejectedIPv4Prefix, rejectedIPv6Prefix},
		}).append(nil)),
	})
	for range xrayRustCount(40) {
		entries, out := xrayRustEntries(r, 1+r.IntN(6), false)
		v.Encode = append(v.Encode, xrayRustEncode{
			Kind: "assign", Entries: out,
			Bytes: hex.EncodeToString((&addressAssignCapsule{AssignedAddresses: entries}).append(nil)),
		})
		entries, out = xrayRustEntries(r, 1+r.IntN(6), true)
		c := &addressRequestCapsule{}
		for _, e := range entries {
			c.RequestIDs = append(c.RequestIDs, e.RequestID)
			c.Prefixes = append(c.Prefixes, e.IPPrefix)
		}
		v.Encode = append(v.Encode, xrayRustEncode{Kind: "request", Entries: out, Bytes: hex.EncodeToString(c.append(nil))})
	}

	// What a client reads: valid capsules and mutated ones.
	for len(v.Parse) < xrayRustCount(120) {
		kind := uint64(1 + r.IntN(3))
		var value []byte
		switch kind {
		case 1:
			entries, _ := xrayRustEntries(r, r.IntN(5), false)
			value = (&addressAssignCapsule{AssignedAddresses: entries}).append(nil)
		case 2:
			entries, _ := xrayRustEntries(r, r.IntN(5), true)
			c := &addressRequestCapsule{}
			for _, e := range entries {
				c.RequestIDs = append(c.RequestIDs, e.RequestID)
				c.Prefixes = append(c.Prefixes, e.IPPrefix)
			}
			value = c.append(nil)
		case 3:
			_, value = xrayRustRoutes(r, r.IntN(3) != 0)
		}
		// Strip the capsule header the append methods wrote.
		_, n, _ := quicvarint.Parse(value)
		_, m, _ := quicvarint.Parse(value[n:])
		value = value[n+m:]
		switch r.IntN(6) {
		case 0:
			if len(value) > 0 {
				value = value[:r.IntN(len(value))]
			}
		case 1:
			if len(value) > 0 {
				value[r.IntN(len(value))] ^= byte(1 + r.IntN(255))
			}
		}
		if result := xrayRustParseValue(kind, value); xrayRustLocalResult(result) {
			v.Parse = append(v.Parse, result)
		}
	}
	for _, value := range [][]byte{
		{},
		{1, 4, 10, 0, 0, 1, 24},
		{1, 4, 10, 0, 0, 0, 33},
		{1, 5, 0},
		{0, 4, 0, 0, 0, 0, 32},
	} {
		for kind := uint64(1); kind <= 2; kind++ {
			v.Parse = append(v.Parse, xrayRustParseValue(kind, value))
		}
	}
	// One entry past the limit, and the limit itself; 128 KiB, so only in
	// the full corpus.
	if xrayRustFull {
		for _, count := range []int{maxAddressesPerCapsule, maxAddressesPerCapsule + 1} {
			var limit []byte
			for i := range count {
				limit = quicvarint.Append(limit, uint64(i+1))
				limit = append(limit, 4, 10, byte(i>>8), byte(i), 0, 32)
			}
			v.Parse = append(v.Parse, xrayRustParseValue(1, limit), xrayRustParseValue(2, limit))
		}
	}

	// Datagrams composed from local packets.
	for range xrayRustCount(100) {
		packet := xrayRustPacket(r, false)
		for _, form := range []struct{ capsule, bare bool }{{false, false}, {true, false}, {true, true}} {
			c := &Conn{bare: form.bare}
			if !form.capsule {
				c.h3 = &mockStream{}
			}
			in := bytes.Clone(packet)
			out, err := c.composeDatagram(in)
			result := xrayRustCompose{Packet: hex.EncodeToString(packet), Capsule: form.capsule, Bare: form.bare}
			if err != nil {
				result.Dropped = true
			} else {
				result.Out = hex.EncodeToString(out)
			}
			v.Compose = append(v.Compose, result)
		}
	}

	// ICMP Packet Too Big for packets of each family and size.
	for range xrayRustCount(120) {
		packet := xrayRustPacket(r, true)
		mtu := []int{0, 67, 68, 576, 1200, 1279, 1280, 1350, 1500}[r.IntN(9)]
		result := xrayRustIcmp{Packet: hex.EncodeToString(packet), MTU: mtu}
		icmp, err := composeICMPTooLargePacket(packet, mtu)
		switch {
		case errors.Is(err, ErrMTUTooSmall):
			result.TooSmall = true
		case err != nil:
			result.Error = true
		default:
			result.Out = hex.EncodeToString(icmp)
		}
		v.Icmp = append(v.Icmp, result)
	}

	// Incoming packets against assigned prefixes, routes and a peer.
	for range xrayRustCount(200) {
		packet := xrayRustPacket(r, false)
		var assigned, peer []netip.Prefix
		var routes []IPRoute
		for range r.IntN(3) {
			assigned = append(assigned, xrayRustPrefix(r, r.IntN(2) == 0))
		}
		if len(packet) >= 20 && r.IntN(3) == 0 {
			// Often aim the packet at an assigned address.
			var dst netip.Addr
			if packet[0]>>4 == 4 {
				dst = netip.AddrFrom4([4]byte(packet[16:20]))
			} else if len(packet) >= 40 {
				dst = netip.AddrFrom16([16]byte(packet[24:40]))
			}
			if dst.IsValid() && xrayRustLocal(dst) {
				assigned = append(assigned, netip.PrefixFrom(dst, dst.BitLen()))
			}
		}
		if r.IntN(3) == 0 {
			routes, _ = xrayRustRoutes(r, true)
			if len(packet) >= 20 && packet[0]>>4 == 4 && r.IntN(2) == 0 {
				if dst := netip.AddrFrom4([4]byte(packet[16:20])); xrayRustLocal(dst) {
					routes = []IPRoute{{StartIP: dst, EndIP: dst, IPProtocol: uint8(r.IntN(2) * 6)}}
				}
			}
		}
		if r.IntN(4) == 0 {
			peer = []netip.Prefix{}
			for range r.IntN(3) {
				peer = append(peer, xrayRustPrefix(r, r.IntN(2) == 0))
			}
		}
		c := &Conn{assignedAddresses: assigned, localRoutes: routes, peerAddresses: peer}
		result := xrayRustIncoming{Packet: hex.EncodeToString(packet), Allowed: c.handleIncomingProxiedPacket(packet) == nil}
		for _, p := range assigned {
			result.Assigned = append(result.Assigned, p.String())
		}
		for _, route := range routes {
			result.Routes = append(result.Routes, xrayRustRoute{route.StartIP.String(), route.EndIP.String(), route.IPProtocol})
		}
		if peer != nil {
			result.Peer = []string{}
			for _, p := range peer {
				result.Peer = append(result.Peer, p.String())
			}
		}
		v.Incoming = append(v.Incoming, result)
	}

	// Datagrams a capsule stream reads, each followed by a sentinel packet
	// that ReadPacket returns when it dropped the first. Every destination
	// is assigned, so only the form decides.
	sentinel := make([]byte, 20)
	sentinel[0], sentinel[3], sentinel[8], sentinel[9] = 0x45, 20, 64, 17
	copy(sentinel[12:], []byte{10, 0, 0, 2, 10, 0, 0, 1})
	for range xrayRustCount(100) {
		packet := xrayRustPacket(r, false)
		var datagram []byte
		switch r.IntN(6) {
		case 0, 1:
			datagram = slices.Clone(packet)
		case 2:
			datagram = append([]byte{0}, packet...)
		case 3:
			datagram = append([]byte{0x40, 0}, packet...)
		case 4:
			datagram = append(quicvarint.Append(nil, uint64(1+r.IntN(20000))), packet...)
		case 5:
			datagram = slices.Clone(packet[:min(len(packet), r.IntN(3))])
		}
		for _, bare := range []bool{false, true} {
			c := &Conn{
				bare:      bare,
				datagrams: make(chan []byte, 2),
				closeChan: make(chan struct{}),
				assignedAddresses: []netip.Prefix{
					netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0"),
				},
			}
			c.datagrams <- slices.Clone(datagram)
			c.datagrams <- append([]byte{0}, sentinel...)
			b := make([]byte, 8192)
			n, err := c.ReadPacket(b)
			result := xrayRustRead{Datagram: hex.EncodeToString(datagram), Bare: bare}
			if err != nil || bytes.Equal(b[:n], sentinel) {
				result.Dropped = true
			} else {
				result.Packet = hex.EncodeToString(b[:n])
			}
			v.Read = append(v.Read, result)
		}
	}

	data, err := json.MarshalIndent(v, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

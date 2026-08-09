//go:build reality_oracle_grpc_wire

// This oracle is intentionally invoked from the repository root with:
//
//	go run -C tools/reality-oracle/grpc -tags reality_oracle_grpc_wire . \
//	  -wire connection_preamble > tests/fixtures/grpc/connection_preamble.json
//
// `-C` moves Go, not the shell, so the redirect above is still relative to the
// repository root while `-check` takes a path relative to this directory:
//
//	go run -C tools/reality-oracle/grpc -tags reality_oracle_grpc_wire . \
//	  -wire connection_preamble \
//	  -check ../../../tests/fixtures/grpc/connection_preamble.json
//
// It lives in a module of its own rather than in the root one, because both
// google.golang.org/grpc and xray-core raise the root module's
// golang.org/x/crypto, and uTLS compiled against a different x/crypto emits
// different ClientHello bytes, which breaks the committed REALITY fixtures.
// See the comment in this directory's go.mod before moving it.
//
// # What it captures
//
// One real gRPC dial, through grpc-go, over an in-memory pipe whose client end
// is tapped. Everything the client writes is recorded and then read back as
// HTTP/2 frames, so all three artefacts below come from the same connection
// rather than from three transcriptions of one.
//
// The dial options are transcribed from `Xray-core/transport/internet/grpc/
// dial.go:93-179` rather than called, because `dialgRPC` wants a
// `*internet.MemoryStreamConfig`, a registered transport dialer and a real
// socket. The list is kept in the same order as the reference so the two can be
// diffed by eye; `grpc.WithConnectParams` changes no byte on a connection that
// never reconnects and is here for exactly that reason.
//
// The three artefacts, and how far each one is allowed to claim:
//
//   - `connection_preamble` is byte-exact. Under Xray's defaults grpc-go's
//     opening burst is the 24-byte client preface and an *empty* SETTINGS
//     frame, which is a signature in itself: `initialWindowSize` reaches the
//     wire only above grpc-go's own default and `MaxHeaderListSize` only when
//     a dial option sets it (`grpc@v1.81.0/internal/transport/
//     http2_client.go:433-451`), and neither is configured here. No connection
//     WINDOW_UPDATE follows either, because `icwz` is left at
//     `defaultWindowSize` and the delta is zero (`http2_client.go:315-317,
//     453-458`). `frames_before_first_headers` records the burst as frames so
//     that a future grpc-go adding one to it fails the check rather than
//     passing unnoticed; the SETTINGS ACK in there is a reply to the server's
//     own SETTINGS, queued on the control buffer before `newHTTP2Client`
//     returns and therefore always ahead of the call's HEADERS.
//
//   - `request_headers` is the decoded field list, in order, and deliberately
//     not the encoded block. Two independent divergences make a byte
//     comparison of the HPACK bytes unmeetable: `http::HeaderMap` orders
//     `:authority` before `:path` where grpc-go is the other way round, and
//     encodes `:path` as a literal without indexing where grpc-go indexes it
//     incrementally. Neither is reachable without forking the crate, so the
//     field list is the bar, and it is the field list the Rust side in
//     `crates/xray-transport/tests/stream_grpc_tests.rs` is held to.
//
//   - `hunk_framing` is byte-exact. Each vector is one `hc.Send(&Hunk{Data:
//     ...})` as it left the wire, reassembled from the call's DATA frames, so
//     the 16 KiB vector is one message across two frames rather than two
//     messages. Payload *content* is not recorded: it is a literal suffix of
//     `message_hex`, so storing it twice would only be a second copy to keep
//     in step. `payload_rule` is what the reader needs to rebuild the input.
//
// # What it does not claim
//
// The user agent is a literal rather than Xray's default. `dial.go:193-204`
// maps an unset `userAgent` onto `utils.ChromeUA`, which is derived from the
// current date and from a PRNG seeded with the host CPU, so a fixture
// generated from it would drift with the calendar and between machines --
// exactly the property that forces `tests/fixtures/masquerade` through a
// version-drift classifier. The gRPC transport sends whatever string it is
// handed, and `stream_grpc_request_headers_tests` already pins the mapping
// itself against the masquerade block, so nothing is lost by pinning a literal
// here.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"reflect"
	"runtime/debug"
	"sync"
	"time"

	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

// The call the capture makes.
//
// `authority` is a documentation domain on purpose:
// `scripts/tests/check-json-fixture-safety.py` refuses a globally routable IP
// literal anywhere under `tests/fixtures`, and this string is copied into the
// fixture verbatim.
//
// `dialTarget` is the shape `dial.go:188-191` builds, a `passthrough:///` URL
// around the outbound's own `host:port`. It reaches no byte of the wire here
// and so is not recorded in the fixture: `WithAuthority` wins the `:authority`
// outright (`grpc@v1.81.0/clientconn.go:1977-1978`), and the context dialer
// ignores the address it is handed.
//
// `serviceName` is already in the escaped form `Config.getServiceName()`
// produces, because escaping is the `:path` builder's business and is pinned
// on the Rust side by `stream_grpc_path_tests`; there is nothing for a Go
// oracle to add to it.
const (
	authority          = "grpc.example.com"
	dialTarget         = "passthrough:///grpc.example.com:443"
	serviceName        = "xray.grpc"
	tunStreamName      = "Tun"
	tunMultiStreamName = "TunMulti"
	userAgent          = "xray-grpc-oracle/1"
)

// The client connection preface, `grpc@v1.81.0/internal/transport/
// http_util.go:53` by way of RFC 9113 section 3.4.
const clientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// The payload lengths the framing vectors cover.
//
// 0 is proto3's implicit-presence case, where the `Hunk` body vanishes
// entirely and only the five-byte gRPC prefix goes out. 127 and 128 bracket
// the one-to-two byte varint boundary in the field's length prefix, and 16384
// is the smallest payload needing three -- and, not coincidentally, the first
// one that outgrows HTTP/2's default 16 KiB frame, so it also pins that one
// `Send` stays one gRPC message across two DATA frames.
var payloadLengths = []int{0, 1, 5, 127, 128, 16384}

// How the framing vectors' payload bytes are rebuilt, recorded in the fixture
// because they are not stored.
const payloadRule = "payload[i] = i mod 256"

// deadline bounds the whole capture. A pipe deadlock would otherwise hang CI
// rather than fail it.
const deadline = 30 * time.Second

type moduleVersions struct {
	Grpc string `json:"google.golang.org/grpc"`
	Net  string `json:"golang.org/x/net"`
}

type settingEntry struct {
	ID    string `json:"id"`
	Value uint32 `json:"value"`
}

type frameDescriptor struct {
	Type       string   `json:"type"`
	Flags      []string `json:"flags"`
	StreamID   uint32   `json:"stream_id"`
	PayloadLen int      `json:"payload_len"`
}

type headerField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type callShape struct {
	ServiceName string `json:"service_name"`
	StreamName  string `json:"stream_name"`
	Authority   string `json:"authority"`
	UserAgent   string `json:"user_agent"`
}

type hunkVector struct {
	PayloadLen int    `json:"payload_len"`
	MessageHex string `json:"message_hex"`
}

type preambleFixture struct {
	Wire             string            `json:"wire"`
	Modules          moduleVersions    `json:"modules"`
	PrefaceHex       string            `json:"preface_hex"`
	PrefaceText      string            `json:"preface_text"`
	SettingsFrameHex string            `json:"settings_frame_hex"`
	Settings         []settingEntry    `json:"settings"`
	OpeningFrames    []frameDescriptor `json:"frames_before_first_headers"`
}

type headersFixture struct {
	Wire    string         `json:"wire"`
	Modules moduleVersions `json:"modules"`
	Call    callShape      `json:"call"`
	Headers []headerField  `json:"headers"`
}

type framingFixture struct {
	Wire        string         `json:"wire"`
	Modules     moduleVersions `json:"modules"`
	PayloadRule string         `json:"payload_rule"`
	Vectors     []hunkVector   `json:"vectors"`
}

// recordedFrame is one HTTP/2 frame with the bytes it occupied, so an artefact
// can be byte-exact without re-encoding anything.
type recordedFrame struct {
	kind     uint8
	flags    uint8
	streamID uint32
	payload  []byte
	raw      []byte
}

// capture is everything one dial produced.
type capture struct {
	preface  []byte
	frames   []recordedFrame
	headers  []hpack.HeaderField
	messages [][]byte
}

// recordingConn tees the client half of the connection.
//
// Only writes are recorded: the artefacts are all about what an Xray client
// puts on the wire, and the server end of this pipe is scaffolding.
type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.mu.Lock()
	c.written.Write(p[:n])
	c.mu.Unlock()
	return n, err
}

func (c *recordingConn) recorded() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return bytes.Clone(c.written.Bytes())
}

// pipeListener hands `grpc.Server` the one connection there is and then blocks
// until it is closed, which is what lets `Serve` return cleanly on `Stop`.
type pipeListener struct {
	conn      net.Conn
	handOver  sync.Once
	closeOnce sync.Once
	closed    chan struct{}
}

func newPipeListener(conn net.Conn) *pipeListener {
	return &pipeListener{conn: conn, closed: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	var conn net.Conn
	l.handOver.Do(func() { conn = l.conn })
	if conn != nil {
		return conn, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}

func (l *pipeListener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

// drainServer accepts the tunnel and reads it, which is all the capture needs
// from a server: a `Send` is only proof of a write once the far end has the
// message.
type drainServer struct {
	encoding.UnimplementedGRPCServiceServer
	want     int
	received chan struct{}
	once     sync.Once
}

func (s *drainServer) Tun(stream encoding.GRPCService_TunServer) error {
	for count := 0; ; count++ {
		if count == s.want {
			s.once.Do(func() { close(s.received) })
		}
		if _, err := stream.Recv(); err != nil {
			return nil
		}
	}
}

// setUserAgent is `Xray-core/transport/internet/grpc/dial.go:212-218`, copied
// because it reaches an unexported field and there is no exported way to do
// what it does. It removes the "grpc-go/<version>" suffix that
// `grpc.WithUserAgent` appends unconditionally
// (`grpc@v1.81.0/dialoptions.go:551-555`), which is why the captured
// `user-agent` is the configured string alone. `requestHeaders` checks that it
// took effect rather than trusting it: a reflection walk that quietly found
// nothing would bake the suffix into the fixture.
func setUserAgent(conn *grpc.ClientConn, ua string) {
	if f := reflect.ValueOf(conn).Elem().FieldByName("dopts").FieldByName("copts").FieldByName("UserAgent"); f.IsValid() {
		*(*string)(f.Addr().UnsafePointer()) = ua
	}
}

func payloadOf(length int) []byte {
	payload := make([]byte, length)
	for i := range payload {
		payload[i] = byte(i)
	}
	return payload
}

func captureDial(ctx context.Context) (*capture, error) {
	// The call runs on a context that can be cancelled but carries no
	// deadline, and `ctx` reaches it only as a cancellation. grpc-go writes a
	// `grpc-timeout` header for any context that has one
	// (`grpc@v1.81.0/internal/transport/http2_client.go:600-608`), and Xray's
	// outbound dial path installs none -- there is no `context.WithTimeout`
	// between the proxy handler and `internet.Dial`. Handing the deadline
	// straight to the RPC would put a header in the fixture that no Xray dial
	// sends, and one whose value is the microseconds left on the clock, so it
	// would differ on every run.
	callCtx, cancelCall := context.WithCancel(context.Background())
	defer cancelCall()
	defer context.AfterFunc(ctx, cancelCall)()

	clientEnd, serverEnd := net.Pipe()
	tap := &recordingConn{Conn: clientEnd}

	server := grpc.NewServer()
	drain := &drainServer{want: len(payloadLengths), received: make(chan struct{})}
	encoding.RegisterGRPCServiceServerX(server, drain, serviceName, tunStreamName, tunMultiStreamName)

	listener := newPipeListener(serverEnd)
	served := make(chan struct{})
	go func() {
		defer close(served)
		_ = server.Serve(listener)
	}()
	defer func() {
		server.Stop()
		<-served
	}()

	// Transcribed from `dial.go:93-166`, in its order. The context dialer is
	// the one option with different contents: Xray's reaches
	// `internet.DialSystem` and then layers TLS or REALITY on top, all of
	// which is below the bytes this oracle is about.
	dialOptions := []grpc.DialOption{
		grpc.WithConnectParams(grpc.ConnectParams{
			Backoff: backoff.Config{
				BaseDelay:  500 * time.Millisecond,
				Multiplier: 1.5,
				Jitter:     0.2,
				MaxDelay:   19 * time.Second,
			},
			MinConnectTimeout: 5 * time.Second,
		}),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return tap, nil
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithAuthority(authority),
		// `WithKeepaliveParams` and `WithInitialWindowSize` are attached only
		// when the matching `grpcSettings` field is set (`dial.go:169-179`),
		// and this capture is of the defaults, so both are absent here as
		// well.
	}

	conn, err := grpc.NewClient(dialTarget, dialOptions...)
	if err != nil {
		return nil, fmt.Errorf("build the gRPC client: %w", err)
	}
	defer conn.Close()
	setUserAgent(conn, userAgent)
	conn.Connect()

	client, ok := encoding.NewGRPCServiceClient(conn).(encoding.GRPCServiceClientX)
	if !ok {
		return nil, errors.New("the generated client no longer offers TunCustomName")
	}
	stream, err := client.TunCustomName(callCtx, serviceName, tunStreamName)
	if err != nil {
		return nil, fmt.Errorf("open the tunnel: %w", err)
	}

	for _, length := range payloadLengths {
		if err := stream.Send(&encoding.Hunk{Data: payloadOf(length)}); err != nil {
			return nil, fmt.Errorf("send a %d byte hunk: %w", length, err)
		}
	}
	if err := stream.CloseSend(); err != nil {
		return nil, fmt.Errorf("half-close the tunnel: %w", err)
	}

	// `Send` only queues onto grpc-go's control buffer, so the far end having
	// every message is the proof that every message was written.
	select {
	case <-drain.received:
	case <-ctx.Done():
		return nil, fmt.Errorf("the peer never received all %d hunks: %w", len(payloadLengths), ctx.Err())
	}

	return parseCapture(tap.recorded())
}

func parseCapture(raw []byte) (*capture, error) {
	if !bytes.HasPrefix(raw, []byte(clientPreface)) {
		return nil, errors.New("the client did not open with the HTTP/2 connection preface")
	}
	captured := &capture{preface: raw[:len(clientPreface)]}

	// A frame still being flushed when the tap was read is dropped rather than
	// reported as a truncation. The capture waits only until the far end has
	// every message, so the half-close queued behind the last one may or may
	// not have reached the wire, and demanding a whole frame there would fail
	// on a race no artefact depends on: the preamble is the first frame, the
	// call is the first HEADERS, and `readMessages` insists on exactly the
	// messages that were sent, so a truncation that mattered still fails.
	rest := raw[len(clientPreface):]
	for {
		frame, width, whole := readFrame(rest)
		if !whole {
			break
		}
		captured.frames = append(captured.frames, frame)
		rest = rest[width:]
	}

	callStream, err := captured.readHeaders()
	if err != nil {
		return nil, err
	}
	return captured, captured.readMessages(callStream)
}

const (
	frameData         uint8 = 0x0
	frameHeaders      uint8 = 0x1
	frameSettings     uint8 = 0x4
	flagAck           uint8 = 0x1
	flagEndHeaders    uint8 = 0x4
	flagPadded        uint8 = 0x8
	flagPriority      uint8 = 0x20
	frameHeaderLength       = 9
)

// readFrame reads one frame off the front of `bytesIn`, reporting whether a
// whole one was there.
func readFrame(bytesIn []byte) (recordedFrame, int, bool) {
	if len(bytesIn) < frameHeaderLength {
		return recordedFrame{}, 0, false
	}
	length := int(bytesIn[0])<<16 | int(bytesIn[1])<<8 | int(bytesIn[2])
	total := frameHeaderLength + length
	if len(bytesIn) < total {
		return recordedFrame{}, 0, false
	}
	return recordedFrame{
		kind:     bytesIn[3],
		flags:    bytesIn[4],
		streamID: binary.BigEndian.Uint32(bytesIn[5:9]) &^ (1 << 31),
		payload:  bytesIn[frameHeaderLength:total],
		raw:      bytesIn[:total],
	}, total, true
}

// readHeaders decodes the call's HEADERS block and returns the stream it
// opened.
func (c *capture) readHeaders() (uint32, error) {
	for _, frame := range c.frames {
		if frame.kind != frameHeaders {
			continue
		}
		if frame.flags&flagEndHeaders == 0 {
			return 0, errors.New("the HEADERS block spans CONTINUATION frames, which this oracle does not join")
		}
		if frame.flags&(flagPadded|flagPriority) != 0 {
			return 0, errors.New("the HEADERS frame is padded or carries a priority section, which this oracle does not strip")
		}
		fields, err := hpack.NewDecoder(4096, nil).DecodeFull(frame.payload)
		if err != nil {
			return 0, fmt.Errorf("decode the HEADERS block: %w", err)
		}
		c.headers = fields
		return frame.streamID, nil
	}
	return 0, errors.New("the client never opened a call")
}

// readMessages reassembles the gRPC messages the call's DATA frames carried.
//
// Frames are concatenated first and split on the five-byte prefixes second,
// which is what a receiver does and the only reading that survives a message
// larger than one frame.
func (c *capture) readMessages(callStream uint32) error {
	var body []byte
	for _, frame := range c.frames {
		if frame.kind != frameData || frame.streamID != callStream {
			continue
		}
		if frame.flags&flagPadded != 0 {
			return errors.New("a DATA frame is padded, which this oracle does not strip")
		}
		body = append(body, frame.payload...)
	}

	for len(body) > 0 {
		if len(body) < 5 {
			return fmt.Errorf("a gRPC message header was cut short at %d bytes", len(body))
		}
		if body[0] != 0 {
			return fmt.Errorf("a gRPC message arrived with payload format %d, not uncompressed", body[0])
		}
		length := int(binary.BigEndian.Uint32(body[1:5]))
		if len(body) < 5+length {
			return fmt.Errorf("a gRPC message promising %d bytes was cut short at %d", length, len(body)-5)
		}
		c.messages = append(c.messages, body[:5+length])
		body = body[5+length:]
	}

	if len(c.messages) != len(payloadLengths) {
		return fmt.Errorf("the call carried %d messages, not the %d that were sent", len(c.messages), len(payloadLengths))
	}
	return nil
}

// The frame and setting registries of RFC 9113, sections 6 and 11.
var (
	frameTypeNames = map[uint8]string{
		0x0: "DATA",
		0x1: "HEADERS",
		0x2: "PRIORITY",
		0x3: "RST_STREAM",
		0x4: "SETTINGS",
		0x5: "PUSH_PROMISE",
		0x6: "PING",
		0x7: "GOAWAY",
		0x8: "WINDOW_UPDATE",
		0x9: "CONTINUATION",
	}
	settingNames = map[uint16]string{
		0x1: "SETTINGS_HEADER_TABLE_SIZE",
		0x2: "SETTINGS_ENABLE_PUSH",
		0x3: "SETTINGS_MAX_CONCURRENT_STREAMS",
		0x4: "SETTINGS_INITIAL_WINDOW_SIZE",
		0x5: "SETTINGS_MAX_FRAME_SIZE",
		0x6: "SETTINGS_MAX_HEADER_LIST_SIZE",
	}
)

func frameTypeName(kind uint8) string {
	if name, known := frameTypeNames[kind]; known {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%02x)", kind)
}

// describeFlags names the one flag the opening burst can carry.
//
// `openingFrames` stops at the first HEADERS, so no frame whose bits mean
// something else in the same position -- DATA's END_STREAM shares 0x1 with
// SETTINGS' ACK -- reaches this function. Anything unaccounted for is printed
// as the raw bits rather than guessed at, which is what makes a frame grpc-go
// starts sending show up as a diff instead of a plausible-looking name.
func describeFlags(kind, flags uint8) []string {
	named := []string{}
	remaining := flags
	if kind == frameSettings && flags&flagAck != 0 {
		named = append(named, "ACK")
		remaining &^= flagAck
	}
	if remaining != 0 {
		named = append(named, fmt.Sprintf("0x%02x", remaining))
	}
	return named
}

// openingFrames is everything written before the call, which is what makes
// "the preamble is a preface and an empty SETTINGS" a claim rather than a
// hope: a frame grpc-go starts adding shows up here and fails `-check`.
func (c *capture) openingFrames() []frameDescriptor {
	described := []frameDescriptor{}
	for _, frame := range c.frames {
		if frame.kind == frameHeaders {
			break
		}
		described = append(described, frameDescriptor{
			Type:       frameTypeName(frame.kind),
			Flags:      describeFlags(frame.kind, frame.flags),
			StreamID:   frame.streamID,
			PayloadLen: len(frame.payload),
		})
	}
	return described
}

func settingName(id uint16) string {
	if name, known := settingNames[id]; known {
		return name
	}
	return fmt.Sprintf("UNKNOWN(0x%04x)", id)
}

// preamble is the preface plus the first frame, which has to be the client's
// own SETTINGS: an ACK here would mean the capture started mid-connection.
func (c *capture) preamble() (preambleFixture, error) {
	if len(c.frames) == 0 {
		return preambleFixture{}, errors.New("the client wrote no frames after the preface")
	}
	settings := c.frames[0]
	if settings.kind != frameSettings || settings.flags&flagAck != 0 {
		return preambleFixture{}, fmt.Errorf(
			"the first frame after the preface is %s, not the client's own SETTINGS",
			frameTypeName(settings.kind))
	}
	if len(settings.payload)%6 != 0 {
		return preambleFixture{}, fmt.Errorf("a SETTINGS payload of %d bytes is not a whole number of entries", len(settings.payload))
	}

	entries := []settingEntry{}
	for offset := 0; offset < len(settings.payload); offset += 6 {
		entries = append(entries, settingEntry{
			ID:    settingName(binary.BigEndian.Uint16(settings.payload[offset : offset+2])),
			Value: binary.BigEndian.Uint32(settings.payload[offset+2 : offset+6]),
		})
	}

	modules, err := modulesUsed()
	if err != nil {
		return preambleFixture{}, err
	}
	return preambleFixture{
		Wire:             "connection_preamble",
		Modules:          modules,
		PrefaceHex:       hex.EncodeToString(c.preface),
		PrefaceText:      string(c.preface),
		SettingsFrameHex: hex.EncodeToString(settings.raw),
		Settings:         entries,
		OpeningFrames:    c.openingFrames(),
	}, nil
}

func (c *capture) requestHeaders() (headersFixture, error) {
	fields := make([]headerField, 0, len(c.headers))
	seen := map[string]string{}
	for _, field := range c.headers {
		fields = append(fields, headerField{Name: field.Name, Value: field.Value})
		seen[field.Name] = field.Value
	}

	// The capture has to be the call that was asked for, or the fixture pins
	// somebody else's request. `user-agent` is the one that has actually gone
	// wrong before: `setUserAgent` reaches an unexported field by reflection,
	// and a walk that found nothing would silently leave grpc-go's own
	// "grpc-go/<version>" suffix on the value.
	for _, expected := range []struct {
		name  string
		value string
	}{
		{":authority", authority},
		{":path", "/" + serviceName + "/" + tunStreamName},
		{"user-agent", userAgent},
	} {
		if seen[expected.name] != expected.value {
			return headersFixture{}, fmt.Errorf(
				"the captured %s is %q, not the %q this oracle dialled",
				expected.name, seen[expected.name], expected.value)
		}
	}

	modules, err := modulesUsed()
	if err != nil {
		return headersFixture{}, err
	}
	return headersFixture{
		Wire:    "request_headers",
		Modules: modules,
		Call: callShape{
			ServiceName: serviceName,
			StreamName:  tunStreamName,
			Authority:   authority,
			UserAgent:   userAgent,
		},
		Headers: fields,
	}, nil
}

func (c *capture) hunkFraming() (framingFixture, error) {
	vectors := make([]hunkVector, 0, len(c.messages))
	for index, message := range c.messages {
		vectors = append(vectors, hunkVector{
			PayloadLen: payloadLengths[index],
			MessageHex: hex.EncodeToString(message),
		})
	}

	modules, err := modulesUsed()
	if err != nil {
		return framingFixture{}, err
	}
	return framingFixture{
		Wire:        "hunk_framing",
		Modules:     modules,
		PayloadRule: payloadRule,
		Vectors:     vectors,
	}, nil
}

// modulesUsed reports the two dependencies whose behaviour the fixtures pin.
//
// `http::HeaderMap` documents that its iteration order may change without a
// semver bump, and this repository has already had a routine dependency bump
// move committed fixtures once, in the uTLS oracle's `x/crypto`. Recording the
// versions turns the next such move from an unexplained mismatch into a diff
// that names its cause.
func modulesUsed() (moduleVersions, error) {
	info, readable := debug.ReadBuildInfo()
	if !readable {
		return moduleVersions{}, errors.New("this binary carries no module build info")
	}

	versions := map[string]string{}
	for _, dependency := range info.Deps {
		if dependency.Replace != nil {
			return moduleVersions{}, fmt.Errorf("%s is replaced, so its recorded version would be a fiction", dependency.Path)
		}
		versions[dependency.Path] = dependency.Version
	}

	used := moduleVersions{
		Grpc: versions["google.golang.org/grpc"],
		Net:  versions["golang.org/x/net"],
	}
	if used.Grpc == "" || used.Net == "" {
		return moduleVersions{}, fmt.Errorf("build info names neither version: grpc %q, x/net %q", used.Grpc, used.Net)
	}
	// grpc-go prints its own version into the user agent it would otherwise
	// append, so the two have to agree or one of them is describing a
	// different build.
	if declared := "v" + grpc.Version; used.Grpc != declared {
		return moduleVersions{}, fmt.Errorf("build info says grpc %s but the package constant says %s", used.Grpc, declared)
	}
	return used, nil
}

func render(wire string, captured *capture) (any, error) {
	switch wire {
	case "connection_preamble":
		return captured.preamble()
	case "request_headers":
		return captured.requestHeaders()
	case "hunk_framing":
		return captured.hunkFraming()
	default:
		return nil, fmt.Errorf("unknown -wire %q: want connection_preamble, request_headers or hunk_framing", wire)
	}
}

func main() {
	wire := flag.String("wire", "connection_preamble",
		"which artefact to print: connection_preamble, request_headers or hunk_framing")
	checkPath := flag.String("check", "", "compare the generated artefact with a committed JSON file")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	defer cancel()

	captured, err := captureDial(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "capture a gRPC dial: %v\n", err)
		os.Exit(1)
	}

	fixture, err := render(*wire, captured)
	if err != nil {
		fmt.Fprintf(os.Stderr, "render the artefact: %v\n", err)
		os.Exit(1)
	}

	generated, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal the artefact: %v\n", err)
		os.Exit(1)
	}
	generated = append(generated, '\n')

	if *checkPath == "" {
		_, _ = os.Stdout.Write(generated)
		return
	}

	expected, err := os.ReadFile(*checkPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read fixture: %v\n", err)
		os.Exit(1)
	}
	if !bytes.Equal(expected, generated) {
		fmt.Fprintf(os.Stderr, "fixture mismatch: %s\n", *checkPath)
		os.Exit(1)
	}
}

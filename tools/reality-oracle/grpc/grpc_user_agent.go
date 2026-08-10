//go:build reality_oracle_grpc_wire

// The `user_agent_validity` artefact: which `grpcSettings.user_agent` values a
// real grpc-go client sends, and which of those a real grpc-go server accepts.
//
//	go run -C tools/reality-oracle/grpc -tags reality_oracle_grpc_wire . \
//	  -wire user_agent_validity > tests/fixtures/grpc/user_agent_validity.json
//
// # Why this is its own capture
//
// The four artefacts in `grpc_wire.go` come from one dial, because they are
// four views of one client's behaviour. This one is a boundary, and a boundary
// needs a dial per point: the user agent is fixed when the connection is built
// (`Xray-core/transport/internet/grpc/dial.go:193-218`), so sixteen values mean
// sixteen connections.
//
// # What it answers
//
// `xray-rust` refuses a `user_agent` that `http::HeaderValue` will not hold,
// when the outbound is built rather than once per dial
// (`crates/xray-transport/src/stream/grpc/config.rs`, `GrpcConfig::user_agent`).
// The whole justification for refusing is that the value was unusable anyway —
// that the set `HeaderValue` rejects is the set a grpc-go peer rejects. That is
// a claim about two predicates in two languages, and nothing else in this
// repository would notice if either changed its mind. This fixture is what
// notices: `stream_grpc_user_agent_validity_tests` reads it back and asserts
// that `HeaderValue::from_bytes` agrees with `peer_received_message` on every
// case.
//
// Both halves are recorded, because they fail differently and the difference is
// the point:
//
//   - `sent_verbatim` is about the *client*. grpc-go never validates the string
//     `WithUserAgent` was given, so every case below reaches the wire unchanged,
//     control bytes included. A future grpc-go that started escaping or
//     rejecting would flip this and the fixture check would catch it. Only the
//     boolean is stored: what was sent instead is not knowable from a fixture
//     that never expected to differ, and storing a second copy of every input
//     to record "equal" sixteen times is the kind of duplication the `Hunk`
//     vectors next door already decline.
//   - `peer_received_message` is about the *server*, and is the half that
//     decides whether a config works. A refused value is refused with
//     RST_STREAM before the handler is entered, so the tunnel never carries a
//     byte — recorded in `call_error`, which for a refused case is grpc-go's
//     own status text and for an accepted one is the clean `EOF` that ends a
//     half-closed stream.
//
// # Why hex
//
// `user_agent_hex` rather than the string itself because `high_byte_0x80` is a
// lone `0x80`, which is not valid UTF-8 and therefore not representable in a
// JSON string at all. Hex for one case and a string for the rest would make the
// reader branch; hex throughout does not. It also keeps the control bytes this
// fixture is about from being invisible in a diff.
//
// # The cases
//
// Every transition of `http`'s predicate, which is
// `b >= 32 && b != 127 || b == b'\t'` (`http-1.5.0/src/header/value.rs:563-565`):
// NUL, the bottom and top of C0 either side of the HTAB exception, LF, CR, the
// top printable byte, DEL, and the first byte above it. Leading and trailing
// whitespace are in there because RFC 9113 section 8.2.1 calls a field value
// with either malformed while both `httpguts` and `http` accept it, so the
// question of who enforces that is settled by measurement rather than by
// reading the RFC. `crlf_header_injection` is the shape that looks like
// smuggling and is not: HPACK is length-prefixed, so the injected text stays
// inside the value and no second header appears.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/xtls/xray-core/transport/internet/grpc/encoding"
	"golang.org/x/net/http2/hpack"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"
	"google.golang.org/grpc/credentials/insecure"
)

// userAgentValidityWire names the artefact, and is what `-wire` selects.
const userAgentValidityWire = "user_agent_validity"

// userAgentDeadline bounds the whole capture, and is larger than `deadline`
// for the one reason that this mode is sixteen dials rather than one. Each is
// over a `net.Pipe` and resolves in milliseconds; the margin is for a loaded
// CI runner, not for the work.
const userAgentDeadline = 120 * time.Second

// The message the capture sends down each tunnel. Its content is irrelevant --
// what is being measured is whether the far end is reached at all -- so it is
// the shortest thing that is not the empty `Hunk` the framing vectors already
// cover.
var userAgentProbePayload = []byte("probe")

// userAgentCase is one configured `grpcSettings.user_agent` and what became of
// it. `bytes` is the input; everything in `userAgentVerdict` is measured.
type userAgentCase struct {
	name  string
	bytes []byte
}

type userAgentVerdict struct {
	Name string `json:"name"`
	// The configured value, hex-encoded. See the package comment.
	UserAgentHex string `json:"user_agent_hex"`
	// Whether the client encoded the configured bytes into the HEADERS block
	// unchanged.
	SentVerbatim bool `json:"sent_verbatim"`
	// Whether the server's handler received the tunnel's first message. False
	// means the stream was reset before the handler was entered.
	PeerReceivedMessage bool `json:"peer_received_message"`
	// What the client's first `Recv` returned: `EOF` for a stream the peer
	// accepted and then ended, grpc-go's status text for one it refused.
	CallError string `json:"call_error"`
}

type userAgentFixture struct {
	Wire    string             `json:"wire"`
	Modules moduleVersions     `json:"modules"`
	Call    callShape          `json:"call"`
	Cases   []userAgentVerdict `json:"cases"`
}

// userAgentCases is the boundary, in the order the package comment walks it:
// the accepted shapes first, then every rejected byte.
//
// `printable_ascii` and `empty` are the two an unmodified Xray produces --
// `dial.go:193-204` maps every keyword onto a browser UA or onto `""` -- and
// they are here as the control, not as the interesting part.
var userAgentCases = []userAgentCase{
	{"printable_ascii", []byte("xray-grpc-oracle/1")},
	{"empty", []byte("")},
	{"tilde_0x7e", []byte("xray-grpc-oracle/1~")},
	{"htab_interior", []byte("xray-grpc-oracle\t1")},
	{"htab_trailing", []byte("xray-grpc-oracle/1\t")},
	{"space_leading", []byte(" xray-grpc-oracle/1")},
	{"space_trailing", []byte("xray-grpc-oracle/1 ")},
	{"utf8_multibyte", []byte("Mozilla/5.0 (例え)")},
	{"high_byte_0x80", []byte("xray-grpc-oracle/1\x80")},
	{"nul_0x00", []byte("xray-grpc-oracle/1\x00suffix")},
	{"ctl_0x01", []byte("xray-grpc-oracle/1\x01")},
	{"lf_0x0a", []byte("xray-grpc-oracle/1\nx-injected: 1")},
	{"cr_0x0d", []byte("xray-grpc-oracle/1\rsuffix")},
	{"crlf_header_injection", []byte("xray-grpc-oracle/1\r\nx-injected: 1")},
	{"ctl_0x1f", []byte("xray-grpc-oracle/1\x1f")},
	{"del_0x7f", []byte("xray-grpc-oracle/1\x7f")},
}

// captureUserAgentValidity dials once per case and reports what each dial met.
func captureUserAgentValidity(ctx context.Context) (userAgentFixture, error) {
	modules, err := modulesUsed()
	if err != nil {
		return userAgentFixture{}, err
	}

	verdicts := make([]userAgentVerdict, 0, len(userAgentCases))
	for _, probe := range userAgentCases {
		verdict, err := captureOneUserAgent(ctx, probe)
		if err != nil {
			return userAgentFixture{}, fmt.Errorf("case %s: %w", probe.name, err)
		}
		verdicts = append(verdicts, verdict)
	}

	return userAgentFixture{
		Wire:    userAgentValidityWire,
		Modules: modules,
		Call: callShape{
			ServiceName: serviceName,
			StreamName:  tunStreamName,
			Authority:   authority,
			// The per-case value is in `cases`; naming it here as well would
			// be one of sixteen pretending to be the one.
			UserAgent: "",
		},
		Cases: verdicts,
	}, nil
}

// captureOneUserAgent runs one dial, opens one `Tun`, sends one message, and
// waits for the call to resolve one way or the other.
//
// The wait is on the client's `Recv` rather than on the handler, because only
// one of the two outcomes ever reaches the handler: a refused value is refused
// with RST_STREAM, so waiting for the far end would mean waiting out a timeout
// on every rejected case. `Recv` answers both -- `EOF` once the accepted
// stream's handler has returned, the reset otherwise -- and by the time it has,
// the handler's own state is settled, so the non-blocking read of it below is
// not a race.
func captureOneUserAgent(ctx context.Context, probe userAgentCase) (userAgentVerdict, error) {
	verdict := userAgentVerdict{
		Name:         probe.name,
		UserAgentHex: hex.EncodeToString(probe.bytes),
	}

	clientEnd, serverEnd := net.Pipe()
	tap := &recordingConn{Conn: clientEnd}

	server := grpc.NewServer()
	drain := &drainServer{tun: newDrainCount(1), tunMulti: newDrainCount(1)}
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

	// Transcribed from `dial.go:93-167` exactly as `captureDial` transcribes
	// it, minus the two conditional options no case here configures.
	conn, err := grpc.NewClient(dialTarget,
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
	)
	if err != nil {
		return verdict, fmt.Errorf("build the gRPC client: %w", err)
	}
	defer conn.Close()
	setUserAgent(conn, string(probe.bytes))
	conn.Connect()

	client, ok := encoding.NewGRPCServiceClient(conn).(encoding.GRPCServiceClientX)
	if !ok {
		return verdict, errNoCustomName
	}

	callCtx, cancelCall := context.WithCancel(context.Background())
	defer cancelCall()
	defer context.AfterFunc(ctx, cancelCall)()

	stream, err := client.TunCustomName(callCtx, serviceName, tunStreamName)
	if err != nil {
		return verdict, fmt.Errorf("open the tunnel: %w", err)
	}
	if err := stream.Send(&encoding.Hunk{Data: userAgentProbePayload}); err != nil {
		return verdict, fmt.Errorf("send the probe hunk: %w", err)
	}
	if err := stream.CloseSend(); err != nil {
		return verdict, fmt.Errorf("half-close the tunnel: %w", err)
	}

	resolved := make(chan error, 1)
	go func() {
		_, err := stream.Recv()
		resolved <- err
	}()
	select {
	case err := <-resolved:
		if err == nil {
			return verdict, errUnexpectedResponse
		}
		verdict.CallError = err.Error()
	case <-ctx.Done():
		return verdict, fmt.Errorf("the call never resolved: %w", ctx.Err())
	}

	select {
	case <-drain.tun.received:
		verdict.PeerReceivedMessage = true
	default:
	}

	sent, err := userAgentOnTheWire(tap.recorded())
	if err != nil {
		return verdict, err
	}
	verdict.SentVerbatim = sent == string(probe.bytes)
	return verdict, nil
}

// The failures that are conditions rather than wrapped causes.
var (
	errNoCustomName       = errors.New("the generated client no longer offers TunCustomName")
	errUnexpectedResponse = errors.New("the drain server answered a call it should only ever read")
	errNoPreface          = errors.New("the client did not open with the HTTP/2 connection preface")
	errNoHeadersFrame     = errors.New("the client wrote no HEADERS frame")
	errNoUserAgentHeader  = errors.New("the HEADERS block carried no user-agent")
)

// userAgentOnTheWire decodes the `user-agent` out of the first HEADERS block
// the client wrote.
//
// It walks the frames itself rather than calling `parseCapture`, which is
// shaped for the capture next door: `readCalls` insists on exactly two HEADERS
// blocks and on each call carrying the full set of framing vectors, and this
// capture makes one call with one message. The frame reader and the constants
// are still shared, so "a HEADERS frame" means the same thing in both.
func userAgentOnTheWire(raw []byte) (string, error) {
	if !bytes.HasPrefix(raw, []byte(clientPreface)) {
		return "", errNoPreface
	}

	decoder := hpack.NewDecoder(4096, nil)
	rest := raw[len(clientPreface):]
	for {
		frame, width, whole := readFrame(rest)
		if !whole {
			return "", errNoHeadersFrame
		}
		rest = rest[width:]
		if frame.kind != frameHeaders {
			continue
		}
		if frame.flags&flagEndHeaders == 0 {
			return "", errors.New("the HEADERS block spans CONTINUATION frames, which this oracle does not join")
		}
		if frame.flags&(flagPadded|flagPriority) != 0 {
			return "", errors.New("the HEADERS frame is padded or carries a priority section, which this oracle does not strip")
		}
		fields, err := decoder.DecodeFull(frame.payload)
		if err != nil {
			return "", fmt.Errorf("decode the HEADERS block: %w", err)
		}
		for _, field := range fields {
			if field.Name == "user-agent" {
				return field.Value, nil
			}
		}
		return "", errNoUserAgentHeader
	}
}

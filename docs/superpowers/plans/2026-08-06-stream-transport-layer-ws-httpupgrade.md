# Stream Transport Layer, WebSocket and HTTPUpgrade Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a VLESS outbound speak `streamSettings.network: "ws"` and `"httpupgrade"`, at wire parity with Xray-core v26.5.9 including its browser-masquerade headers and Go's header serialization order.

**Architecture:** A new `StreamTransport` layer sits between the security layer (`ConnectorConfig`, unchanged) and the VLESS protocol code. `TransportDialer` gains `connect_stream`, which calls the existing `connect_resolved` for a secured stream and then applies the transport's framing, returning a `BoxedTransportStream` again. Nothing above — VLESS header encoding, Vision, XUDP — changes, because it already operates on `BoxedTransportStream`.

**Tech Stack:** Rust 2021, tokio, the existing `xray-transport` crate, one new dependency (`sha1` 0.10, for `Sec-WebSocket-Accept`). No HTTP or WebSocket crate: both handshakes are hand-written because the fingerprint depends on byte-level control Rust HTTP stacks do not give.

**Spec:** `docs/superpowers/specs/2026-08-06-vless-stream-transports-design.md` — sections "The transport layer sits above security, not inside it", "Shared HTTP request builder", "Compatibility matrix", and all of "Stage 1". gRPC (Stage 2) and XHTTP (Stage 3) get their own plans after this one lands.

**Prerequisite already landed:** plain-TLS uTLS ClientHello shaping (`docs/superpowers/plans/2026-08-06-plain-tls-utls-shaping.md`). ws and httpupgrade cannot use REALITY — Xray-core rejects that combination — so plain TLS is their only security, and without shaping they would have gone out over a ClientHello no Chrome ever sent.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/xray-transport/src/stream/mod.rs` (create) | The `StreamTransport` enum and the `wrap` dispatch. The only public surface of the new layer. |
| `crates/xray-transport/src/stream/http_headers.rs` (create) | Go-compatible HTTP/1.1 request serialization and the browser-masquerade header block. Shared by both transports; XHTTP will reuse it. |
| `crates/xray-transport/src/stream/httpupgrade.rs` (create) | The fake upgrade: request, strict 101 validation, raw passthrough. |
| `crates/xray-transport/src/stream/websocket.rs` (create) | RFC 6455 client: handshake, accept-key validation, masked binary framing, close, ping. |
| `crates/xray-transport/src/stream/websocket_frame.rs` (create) | Frame encode/decode, separated so the framing can be tested without a socket. |
| `crates/xray-transport/src/dialer.rs` (modify) | `connect_stream`, layering a transport over `connect_resolved`. |
| `crates/xray-transport/src/lib.rs` (modify) | Module declaration, re-exports, new `TransportError` variants. |
| `crates/xray-config/src/model.rs` (modify) | `StreamTransport` config types; `StreamSettings.transport`. |
| `crates/xray-config/src/parser.rs` (modify) | Network aliases, `wsSettings`/`httpupgradeSettings`, `?ed=N` extraction, compatibility-matrix errors. |
| `crates/xray-core-rs/src/outbound.rs` (modify) | Carry the transport into the dial, and reject Vision outside `raw`. |
| `tools/reality-oracle/masquerade_headers.go` (create) | Go oracle emitting Xray's masquerade header block, so our port is verified against the real thing rather than against my reading of it. |

Tasks 1-2 build the shared header machinery, 3-4 the config surface, 5 the simpler transport, 6-7 the harder one, 8 the wiring, 9 the live-interop proof.

---

### Task 1: Go-compatible HTTP request serialization

Go writes a request as: request line, then `Host`, then `User-Agent`, then every remaining header **sorted case-sensitively by the literal map key**, then a blank line (`net/http/request.go`, and `header.go`'s `strings.Compare`). That places `Sec-CH-UA` before `Sec-Fetch-*` (because `'C' < 'F'`) and `Upgrade` last. Header names keep their literal, often non-canonical casing. A Rust HTTP stack that lowercases names or preserves insertion order produces a different fingerprint, which is why this is hand-written.

**Files:**
- Create: `crates/xray-transport/src/stream/http_headers.rs`
- Create: `crates/xray-transport/src/stream/mod.rs`
- Modify: `crates/xray-transport/src/lib.rs`
- Test: `crates/xray-transport/tests/stream_http_headers_tests.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/xray-transport/tests/stream_http_headers_tests.rs`:

```rust
mod stream_http_headers_tests {
    use xray_transport::stream::{HeaderMap, serialize_request};

    #[test]
    fn host_and_user_agent_lead_then_case_sensitive_key_order() {
        let mut headers = HeaderMap::new();
        headers.set("Upgrade", "websocket");
        headers.set("Sec-Fetch-Mode", "websocket");
        headers.set("Sec-CH-UA-Mobile", "?0");
        headers.set("DNT", "1");
        headers.set("Connection", "Upgrade");
        headers.set("User-Agent", "TestAgent/1.0");

        let request = serialize_request("GET", "/chat", "example.com", &headers);

        assert_eq!(
            String::from_utf8(request).expect("the request must be UTF-8"),
            concat!(
                "GET /chat HTTP/1.1\r\n",
                "Host: example.com\r\n",
                "User-Agent: TestAgent/1.0\r\n",
                "Connection: Upgrade\r\n",
                "DNT: 1\r\n",
                "Sec-CH-UA-Mobile: ?0\r\n",
                "Sec-Fetch-Mode: websocket\r\n",
                "Upgrade: websocket\r\n",
                "\r\n",
            )
        );
    }

    #[test]
    fn key_order_is_case_sensitive_not_alphabetical() {
        // Go compares the literal map keys byte-wise, so every uppercase letter
        // sorts before every lowercase one. A case-insensitive sort would put
        // `Sec-ch-ua` first; Go puts it last.
        let mut headers = HeaderMap::new();
        headers.set("Sec-ch-ua", "lower");
        headers.set("Sec-CH-UA", "upper");

        let request = serialize_request("GET", "/", "h", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");
        let upper = text.find("Sec-CH-UA:").expect("upper key must be present");
        let lower = text.find("Sec-ch-ua:").expect("lower key must be present");

        assert!(upper < lower, "uppercase keys sort first:\n{text}");
    }

    #[test]
    fn a_header_set_twice_keeps_one_value() {
        let mut headers = HeaderMap::new();
        headers.set("X-Thing", "first");
        headers.set("X-Thing", "second");

        let request = serialize_request("GET", "/", "h", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");

        assert_eq!(text.matches("X-Thing:").count(), 1, "{text}");
        assert!(text.contains("X-Thing: second"), "{text}");
    }

    #[test]
    fn absent_user_agent_is_not_emitted() {
        let mut headers = HeaderMap::new();
        headers.set("Upgrade", "websocket");

        let request = serialize_request("GET", "/", "example.com", &headers);
        let text = String::from_utf8(request).expect("the request must be UTF-8");

        assert!(!text.contains("User-Agent"), "{text}");
        assert!(text.starts_with("GET / HTTP/1.1\r\nHost: example.com\r\n"), "{text}");
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p xray-transport --test stream_http_headers_tests
```

Expected: compile error, `unresolved import xray_transport::stream`.

- [ ] **Step 3: Write the implementation**

Create `crates/xray-transport/src/stream/http_headers.rs`:

```rust
//! Go-compatible HTTP/1.1 request serialization.
//!
//! Xray writes its requests with Go's `net/http`, whose header order is
//! observable and therefore part of the fingerprint: request line, `Host`,
//! `User-Agent`, then every other header sorted **case-sensitively by the
//! literal map key**. Header names keep whatever casing the caller used —
//! Xray deliberately emits non-canonical names like `Sec-CH-UA` and `DNT`.
//! A Rust HTTP stack would lowercase or reorder these, which is why this is
//! written by hand.

/// Insertion-order-independent header storage that keeps literal key casing.
///
/// Go's `http.Header` is a map, so two keys differing only in case are two
/// distinct headers, and both are emitted. This mirrors that.
#[derive(Debug, Clone, Default)]
pub struct HeaderMap {
    entries: Vec<(String, String)>,
}

impl HeaderMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces any existing value for this exact key. Comparison is
    /// case-sensitive, matching Go's map semantics.
    pub fn set(&mut self, key: &str, value: &str) {
        match self.entries.iter_mut().find(|(name, _)| name == key) {
            Some((_, existing)) => *existing = value.to_owned(),
            None => self.entries.push((key.to_owned(), value.to_owned())),
        }
    }

    /// Sets the value only when the key is absent. Xray uses this for
    /// `Accept`, `Cache-Control` and `Pragma`, which never override a
    /// user-supplied value.
    pub fn set_if_absent(&mut self, key: &str, value: &str) {
        if self.get(key).is_none() {
            self.set(key, value);
        }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value.as_str())
    }

    pub fn remove(&mut self, key: &str) {
        self.entries.retain(|(name, _)| name != key);
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Serializes a request the way Go's `Request.Write` does.
///
/// `host` becomes the `Host` header; Go carries it in `Request.Host` rather
/// than the header map, which is why it is a separate argument and why it is
/// never subject to the sort.
pub fn serialize_request(method: &str, path: &str, host: &str, headers: &HeaderMap) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    out.extend_from_slice(format!("Host: {host}\r\n").as_bytes());

    if let Some(user_agent) = headers.get("User-Agent") {
        out.extend_from_slice(format!("User-Agent: {user_agent}\r\n").as_bytes());
    }

    let mut rest: Vec<&(String, String)> = headers
        .entries
        .iter()
        .filter(|(name, _)| name != "User-Agent")
        .collect();
    rest.sort_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));

    for (name, value) in rest {
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }

    out.extend_from_slice(b"\r\n");
    out
}
```

Create `crates/xray-transport/src/stream/mod.rs`:

```rust
//! Stream transports layered over the security layer.
//!
//! Xray applies its transport framing after TLS, not inside it, so this layer
//! takes an already-secured stream and wraps it. Everything above — the VLESS
//! request header, Vision, XUDP — is unaware of which transport produced the
//! stream it was handed.

mod http_headers;

pub use http_headers::{serialize_request, HeaderMap};
```

In `crates/xray-transport/src/lib.rs`, add the module beside the others (keeping them alphabetical, so it goes after `reality_rustls`):

```rust
pub mod stream;
```

- [ ] **Step 4: Run the test to verify it passes**

```bash
cargo test -p xray-transport --test stream_http_headers_tests
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/src/stream/ crates/xray-transport/src/lib.rs crates/xray-transport/tests/stream_http_headers_tests.rs
git commit -m "feat(transport): add Go-compatible HTTP request serialization

Go emits the request line, Host, User-Agent, then every other header
sorted case-sensitively by the literal map key. That order is observable
and part of the fingerprint, so it is written by hand rather than
delegated to an HTTP crate."
```

---

### Task 2: The browser-masquerade header block, verified against a Go oracle

Xray injects a Chrome persona into every ws/httpupgrade request (`Xray-core/common/utils/browser.go`, `TryDefaultHeadersWith`). The rules are unusual enough to be worth stating exactly:

- No `User-Agent` in the config → apply the **chrome** profile.
- `User-Agent` exactly `chrome`, `firefox`, `safari`, `edge`, `curl` or `golang` → apply that profile, replacing the keyword with a real UA.
- Any other `User-Agent`, including the empty string → **apply nothing at all**; only the user's headers are sent.

Within a profile, `Sec-CH-UA`, `Sec-CH-UA-Mobile`, `Sec-CH-UA-Platform`, `DNT`, `User-Agent` and `Accept-Language` **overwrite** user values; `Accept`, `Cache-Control` and `Pragma` only fill gaps.

The Chrome major version is date-derived and the `Sec-CH-UA` brand list is GREASEd, so rather than reimplement that from a reading of the Go source and hope, this task builds a Go oracle that emits the header block and asserts our port against it — the same pattern that has held the ClientHello honest.

**Files:**
- Create: `tools/reality-oracle/masquerade_headers.go`
- Create: `tests/fixtures/masquerade/headers_chrome_ws.json`
- Create: `crates/xray-transport/src/stream/masquerade.rs`
- Modify: `crates/xray-transport/src/stream/mod.rs`
- Test: `crates/xray-transport/tests/stream_http_headers_tests.rs`

- [ ] **Step 1: Write the Go oracle**

Create `tools/reality-oracle/masquerade_headers.go`, following the build-tag convention of `clienthello_shape.go` in the same directory (read it first — it shows the flag parsing, JSON emission and `-check` mode this file should mirror):

```go
//go:build reality_oracle_masquerade_headers

// Emits Xray's masqueraded header block for a browser profile and variant, so
// the Rust port can be asserted against the real thing.
//
//	go run -tags reality_oracle_masquerade_headers ./tools/reality-oracle/masquerade_headers.go -variant ws

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"sort"

	"github.com/xtls/xray-core/common/utils"
)

type headerEntry struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type shape struct {
	Variant   string        `json:"variant"`
	UserAgent string        `json:"user_agent"`
	Headers   []headerEntry `json:"headers"`
}

func main() {
	variant := flag.String("variant", "ws", "header variant: ws, fetch, or navigate")
	userAgent := flag.String("user-agent", "", "config User-Agent value; empty means none is set")
	flag.Parse()

	header := http.Header{}
	if *userAgent != "" {
		header.Set("User-Agent", *userAgent)
	}
	utils.TryDefaultHeadersWith(header, *variant)

	entries := make([]headerEntry, 0, len(header))
	for key, values := range header {
		for _, value := range values {
			entries = append(entries, headerEntry{Key: key, Value: value})
		}
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Key < entries[j].Key })

	out, err := json.MarshalIndent(shape{Variant: *variant, UserAgent: *userAgent, Headers: entries}, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(out))
}
```

- [ ] **Step 2: Generate the fixture**

```bash
go run -tags reality_oracle_masquerade_headers ./tools/reality-oracle/masquerade_headers.go -variant ws > tests/fixtures/masquerade/headers_chrome_ws.json
```

Create the directory first if it does not exist. Then **read the generated JSON** — it is the specification for Step 4, and it settles the questions this plan deliberately does not answer from memory: the exact Chrome version string, the exact `Sec-CH-UA` brand list, and which keys carry non-canonical casing.

- [ ] **Step 3: Write the failing test**

Append to `crates/xray-transport/tests/stream_http_headers_tests.rs`:

```rust
    use xray_transport::stream::apply_masquerade;

    const CHROME_WS_FIXTURE: &str =
        include_str!("../../../tests/fixtures/masquerade/headers_chrome_ws.json");

    #[derive(serde::Deserialize)]
    struct MasqueradeFixture {
        headers: Vec<FixtureHeader>,
    }

    #[derive(serde::Deserialize)]
    struct FixtureHeader {
        key: String,
        value: String,
    }

    #[test]
    fn the_chrome_ws_block_matches_the_go_oracle() {
        let fixture: MasqueradeFixture =
            serde_json::from_str(CHROME_WS_FIXTURE).expect("the fixture must decode");

        let mut headers = HeaderMap::new();
        apply_masquerade(&mut headers, "ws");

        for expected in &fixture.headers {
            assert_eq!(
                headers.get(&expected.key),
                Some(expected.value.as_str()),
                "header {} must match the oracle",
                expected.key
            );
        }
    }

    #[test]
    fn a_real_user_agent_suppresses_the_whole_block() {
        // Xray applies nothing when the configured UA is not one of its magic
        // keywords, so "I set a custom UA" silently drops ~10 other headers.
        let mut headers = HeaderMap::new();
        headers.set("User-Agent", "MyClient/2.0");
        apply_masquerade(&mut headers, "ws");

        assert_eq!(headers.get("User-Agent"), Some("MyClient/2.0"));
        assert_eq!(headers.get("Sec-Fetch-Mode"), None);
        assert_eq!(headers.get("DNT"), None);
    }

    #[test]
    fn accept_is_filled_only_when_absent_while_dnt_overrides() {
        let mut headers = HeaderMap::new();
        headers.set("Accept", "text/plain");
        headers.set("DNT", "0");
        apply_masquerade(&mut headers, "ws");

        assert_eq!(headers.get("Accept"), Some("text/plain"), "Accept only fills gaps");
        assert_eq!(headers.get("DNT"), Some("1"), "DNT is overwritten");
    }
```

Add `serde` and `serde_json` to `crates/xray-transport/Cargo.toml`'s `[dev-dependencies]` if they are not already there (they are — the REALITY fixture tests use them).

- [ ] **Step 4: Write the implementation**

Create `crates/xray-transport/src/stream/masquerade.rs`. Port `applyMasqueradedHeaders` and `TryDefaultHeadersWith` from `Xray-core/common/utils/browser.go` — **read that file and transcribe it**, using the fixture from Step 2 to confirm every literal. The module skeleton and the rules that are easy to get backwards:

```rust
//! Xray's browser-masquerade header block.
//!
//! Ported from `Xray-core/common/utils/browser.go`. Three rules are easy to
//! invert and all three are load-bearing:
//!
//! 1. An absent `User-Agent` means apply the chrome profile. A `User-Agent`
//!    matching one of the magic keywords means apply that profile. **Any other
//!    value, including the empty string, suppresses the entire block** — so a
//!    user who sets a custom UA silently loses ten other headers.
//! 2. `Sec-CH-UA*`, `DNT`, `User-Agent` and `Accept-Language` overwrite what
//!    the user configured; `Accept`, `Cache-Control` and `Pragma` only fill
//!    gaps.
//! 3. Key casing is literal and non-canonical on purpose (`Sec-CH-UA`, `DNT`),
//!    because Go writes these through the map rather than `Header.Set`.

use super::HeaderMap;

/// Applies the persona Xray would apply for this variant.
///
/// `variant` is `"ws"` for WebSocket and HTTPUpgrade, `"fetch"` for XHTTP.
pub fn apply_masquerade(headers: &mut HeaderMap, variant: &str) {
    let profile = match headers.get("User-Agent") {
        None => "chrome",
        Some("chrome") => "chrome",
        Some("firefox") => "firefox",
        Some("safari") => "safari",
        Some("edge") => "edge",
        Some("curl") => "curl",
        Some("golang") => "golang",
        Some(_) => return,
    };

    apply_profile(headers, profile);
    apply_variant(headers, profile, variant);
}
```

Fill `apply_profile` and `apply_variant` from the Go source. For the `ws` variant the Go code sets `Sec-Fetch-Mode: websocket`, `Sec-Fetch-Dest` (`websocket` for safari, `empty` otherwise), `Sec-Fetch-Site: same-origin`, then `Cache-Control`, `Pragma` and `Accept` only if absent.

The Chrome major version and `Sec-CH-UA` brand list: port `ChromeVersion()` and `getGreasedChUa()` exactly. If their output cannot be made to match the fixture deterministically — the Go code seeds part of it — **stop and report** rather than hardcoding the fixture's string, and we will decide whether a fixed version is acceptable.

Export it from `crates/xray-transport/src/stream/mod.rs`:

```rust
mod masquerade;

pub use masquerade::apply_masquerade;
```

- [ ] **Step 5: Run the tests**

```bash
cargo test -p xray-transport --test stream_http_headers_tests
```

Expected: PASS, 7 tests.

- [ ] **Step 6: Commit**

```bash
git add tools/reality-oracle/masquerade_headers.go tests/fixtures/masquerade/ crates/xray-transport/src/stream/ crates/xray-transport/tests/stream_http_headers_tests.rs
git commit -m "feat(transport): port Xray's browser-masquerade header block

Verified against a Go oracle rather than a reading of browser.go, so the
Chrome version string and the GREASEd Sec-CH-UA brand list are the real
ones. A configured User-Agent outside Xray's magic keywords suppresses
the whole block, which is the rule most likely to be inverted."
```

---

### Task 3: Transport config types and parsing

`streamSettings.network` currently accepts only `tcp`/`raw` (`crates/xray-config/src/parser.rs:2650`). This task adds the two new names and their settings blocks.

The subtle part is `ed`. In Xray it is **only** reachable as a query parameter of the path, and the config builder strips it: `"path": "/x?ed=2048"` produces requests to `/x`. The remaining query is re-encoded through Go's `url.Values.Encode()`, which **sorts parameters alphabetically** and percent-encodes them. Emitting `?ed=2048` on the wire gives a path mismatch and a 404.

**Files:**
- Modify: `crates/xray-config/src/model.rs`
- Modify: `crates/xray-config/src/parser.rs`
- Test: `crates/xray-config/tests/parser_tests.rs`

- [ ] **Step 1: Write the failing tests**

Append to `crates/xray-config/tests/parser_tests.rs`, using the file's existing helpers — read it first; it builds raw JSON strings and uses `parse_xray_json` and `assert_parse_error_path` rather than a `json!` macro:

```rust
#[test]
fn ws_network_parses_with_its_settings() {
    let config = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/chat", "host": "cdn.example.com",
                          "headers": {"X-Thing": "v"}, "heartbeatPeriod": 30}"#,
    ))
    .expect("a ws outbound must parse");

    let StreamTransport::WebSocket(ws) = &config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/chat");
    assert_eq!(ws.host.as_deref(), Some("cdn.example.com"));
    assert_eq!(ws.headers, vec![("X-Thing".to_owned(), "v".to_owned())]);
    assert_eq!(ws.heartbeat_period_secs, 30);
    assert_eq!(ws.early_data_bytes, 0);
}

#[test]
fn websocket_is_an_alias_for_ws() {
    let config = parse_xray_json(&raw_with_stream_settings(
        r#""network": "websocket", "security": "none""#,
    ))
    .expect("the websocket alias must parse");

    assert!(matches!(
        config.outbounds[0].stream.transport,
        StreamTransport::WebSocket(_)
    ));
}

#[test]
fn the_ed_query_parameter_is_stripped_from_the_path() {
    let config = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/x?ed=2048"}"#,
    ))
    .expect("an ed path must parse");

    let StreamTransport::WebSocket(ws) = &config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/x", "ed never reaches the wire");
    assert_eq!(ws.early_data_bytes, 2048);
}

#[test]
fn the_remaining_query_is_re_encoded_alphabetically() {
    // Go's url.Values.Encode() sorts, so a path that keeps its query comes out
    // reordered. The server compares the whole path, so we must match.
    let config = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none",
           "wsSettings": {"path": "/x?zulu=1&alpha=2&ed=64"}"#,
    ))
    .expect("a multi-parameter path must parse");

    let StreamTransport::WebSocket(ws) = &config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/x?alpha=2&zulu=1");
    assert_eq!(ws.early_data_bytes, 64);
}

#[test]
fn an_empty_path_becomes_a_single_slash() {
    let config = parse_xray_json(&raw_with_stream_settings(
        r#""network": "ws", "security": "none", "wsSettings": {}"#,
    ))
    .expect("wsSettings may be empty");

    let StreamTransport::WebSocket(ws) = &config.outbounds[0].stream.transport else {
        panic!("expected a websocket transport");
    };
    assert_eq!(ws.path, "/");
}

#[test]
fn httpupgrade_rejects_a_host_header_inside_headers() {
    // ws folds headers.Host into host with a deprecation warning; httpupgrade
    // makes it a hard error.
    assert_parse_error_path(
        &raw_with_stream_settings(
            r#""network": "httpupgrade", "security": "none",
               "httpupgradeSettings": {"headers": {"Host": "x"}}"#,
        ),
        "$.outbounds[0].streamSettings.httpupgradeSettings.headers",
    );
}

#[test]
fn removed_transports_say_they_were_removed() {
    for network in ["h2", "http", "quic"] {
        let errors = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "none""#
        )))
        .expect_err("a removed transport must be rejected");
        assert!(
            errors.iter().any(|error| error.message.contains("removed")),
            "{network} must say it was removed, got: {errors:?}"
        );
    }
}
```

Add a `raw_with_stream_settings` helper alongside the file's existing raw-JSON helpers if one does not already exist, following their shape.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p xray-config --test parser_tests
```

Expected: compile error, `StreamTransport` not found, plus `unsupported stream network` failures.

- [ ] **Step 3: Add the model types**

In `crates/xray-config/src/model.rs`, add beside `StreamSettings`:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamTransport {
    Raw,
    WebSocket(WebSocketSettings),
    HttpUpgrade(HttpUpgradeSettings),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WebSocketSettings {
    /// Normalized: always begins with `/`, and `?ed=N` has been stripped with
    /// the remaining query re-encoded the way Go's `url.Values.Encode` does.
    pub path: String,
    /// `Host` header. Falls back to the TLS server name, then the destination
    /// address. Never carries a port.
    pub host: Option<String>,
    /// Extra headers in config order; the serializer sorts them.
    pub headers: Vec<(String, String)>,
    /// From `?ed=N`. Zero means early data is off.
    pub early_data_bytes: u32,
    /// Seconds between client pings. Zero means no keepalive.
    pub heartbeat_period_secs: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HttpUpgradeSettings {
    pub path: String,
    pub host: Option<String>,
    pub headers: Vec<(String, String)>,
    /// From `?ed=N`. For HTTPUpgrade this carries no payload — any positive
    /// value only means "do not block waiting for the 101".
    pub early_data_bytes: u32,
}
```

Add the field to `StreamSettings`:

```rust
pub struct StreamSettings {
    pub network: Network,
    pub transport: StreamTransport,
    pub security: StreamSecurity,
    pub socket_options: Option<SocketOptions>,
}
```

Every existing construction site now fails to compile; add `transport: StreamTransport::Raw` to each. The compiler lists them.

- [ ] **Step 4: Extend the parser**

In `crates/xray-config/src/parser.rs`, replace `parse_network`'s match arms so the network name selects a transport, and add the settings parsing. The path normalization is the part to get exactly right:

```rust
/// Splits `?ed=N` out of a configured path, returning the normalized path and
/// the early-data budget.
///
/// Xray strips `ed` at config-build time, so it never reaches the wire, and
/// re-encodes whatever query remains through Go's `url.Values.Encode()` —
/// which sorts parameters alphabetically. The server compares the whole path,
/// so both halves of that are load-bearing.
fn split_early_data_from_path(raw: &str) -> (String, u32) {
    let (path, query) = match raw.split_once('?') {
        Some((path, query)) => (path, query),
        None => (raw, ""),
    };

    let mut early_data = 0u32;
    let mut kept: Vec<(&str, &str)> = Vec::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key == "ed" {
            // A non-numeric value yields 0 and is still stripped.
            early_data = value.parse().unwrap_or(0);
            continue;
        }
        kept.push((key, value));
    }
    kept.sort_by(|(left, _), (right, _)| left.cmp(right));

    let path = if path.is_empty() {
        "/"
    } else {
        path
    };
    let mut normalized = if path.starts_with('/') {
        path.to_owned()
    } else {
        format!("/{path}")
    };
    if !kept.is_empty() {
        let query: Vec<String> = kept
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        normalized.push('?');
        normalized.push_str(&query.join("&"));
    }

    (normalized, early_data)
}
```

The network arms:

```rust
            "tcp" | "raw" => Some(Network::Tcp),
            "ws" | "websocket" => Some(Network::Tcp),
            "httpupgrade" => Some(Network::Tcp),
            network @ ("h2" | "h3" | "http" | "quic") => {
                self.error(
                    network_path,
                    format!(
                        "stream network `{network}` was removed from Xray; use `xhttp` instead"
                    ),
                );
                None
            }
            network @ ("kcp" | "mkcp" | "hysteria") => {
                self.error(
                    network_path,
                    format!("stream network `{network}` is not supported by xray-rust"),
                );
                None
            }
            network => {
                self.error(
                    network_path,
                    format!("unsupported stream network `{network}`"),
                );
                None
            }
```

Add `wsSettings` and `httpupgradeSettings` to `validate_stream_settings_compatibility`'s allowlist, and write the two settings parsers. For ws, a `Host` key inside `headers` (any case) folds into `host` when `host` is empty and is then removed, with a warning; for httpupgrade it is an error.

**The two transports disagree on config-header casing, and it is visible on the wire.** Found while implementing Task 2. ws adds config headers with Go's `header.Add`, which MIME-canonicalizes the key (`accept` becomes `Accept`); httpupgrade uses `header[key] = append(...)`, which keeps the literal casing — its own comment says people want to send `Web*S*ocket`. Our `HeaderMap` stores literal keys, so it already matches httpupgrade exactly. For **ws only**, canonicalize each config header key at insert time (uppercase the first letter and every letter after a `-`, lowercase the rest), or a user writing `accept:` will produce two `Accept` headers where Xray produces one. Add a test pinning both behaviors, since they differ deliberately.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cargo test -p xray-config
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/xray-config/
git commit -m "feat(config): parse ws and httpupgrade stream settings

?ed=N is stripped from the path at parse time and the remaining query is
re-encoded alphabetically, both matching Xray's config builder — emitting
ed on the wire would give a path mismatch and a 404. Removed transports
say they were removed rather than that they are unsupported."
```

---

### Task 4: The compatibility matrix

Xray-core enforces two restrictions at config-build time, and both must be reproduced or a profile will build cleanly here and fail on the wire:

- **REALITY is rejected for ws and httpupgrade** — `Xray-core/infra/conf/transport_internet.go:1989`, *"REALITY only supports RAW, XHTTP and gRPC for now."*
- **Vision requires a raw transport.** `Xray-core/proxy/vless/outbound/outbound.go:284` reaches into the TLS connection's private fields and fails with *"XTLS only supports TLS and REALITY directly for now."* when anything sits between. Our `validate_connector_flow` (`crates/xray-core-rs/src/outbound.rs:1634`) currently inspects only the security layer.

**Files:**
- Modify: `crates/xray-config/src/parser.rs`
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Test: `crates/xray-config/tests/parser_tests.rs`, `crates/xray-core-rs/src/outbound.rs` (inline tests)

- [ ] **Step 1: Write the failing tests**

In `crates/xray-config/tests/parser_tests.rs`:

```rust
#[test]
fn reality_is_rejected_for_ws_and_httpupgrade() {
    for network in ["ws", "httpupgrade"] {
        let errors = parse_xray_json(&raw_with_stream_settings(&format!(
            r#""network": "{network}", "security": "reality",
               "realitySettings": {{"serverName": "www.google.com",
                                    "publicKey": "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
                                    "shortId": "0123456789abcdef"}}"#
        )))
        .expect_err("REALITY must be rejected for this transport");

        assert!(
            errors
                .iter()
                .any(|error| error.message.contains("REALITY only supports")),
            "{network} must echo Xray's message, got: {errors:?}"
        );
    }
}
```

In `crates/xray-core-rs/src/outbound.rs`'s inline test module:

```rust
    #[test]
    fn vision_is_rejected_outside_the_raw_transport() {
        let error = validate_connector_flow(
            Some(VISION_FLOW),
            &ConnectorConfig::Tls(TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
                alpn: Vec::new(),
                fingerprint: Some("chrome".to_owned()),
            }),
            &StreamTransport::WebSocket(WebSocketSettings::default()),
        )
        .expect_err("Vision needs a raw transport");

        assert!(matches!(error, CoreError::UnsupportedOutboundFlow));
    }

    #[test]
    fn vision_is_accepted_over_raw_tls() {
        let flow = validate_connector_flow(
            Some(VISION_FLOW),
            &ConnectorConfig::Tls(TlsClientConfig {
                server_name: "example.com".to_owned(),
                allow_insecure: false,
                alpn: Vec::new(),
                fingerprint: Some("chrome".to_owned()),
            }),
            &StreamTransport::Raw,
        )
        .expect("Vision over raw TLS stays valid");

        assert!(flow.uses_vision());
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p xray-config --test parser_tests reality_is_rejected
cargo test -p xray-core-rs vision_is_rejected_outside
```

Expected: the parser test fails because REALITY is accepted; the core test fails to compile because `validate_connector_flow` takes two arguments.

- [ ] **Step 3: Implement both restrictions**

In `crates/xray-config/src/parser.rs`, inside `validate_stream_settings_compatibility`, after the network and security are both known:

```rust
        if matches!(security, StreamSecurity::Reality(_))
            && !matches!(transport, StreamTransport::Raw)
        {
            self.error(
                format!("$.outbounds[{index}].streamSettings.security"),
                "REALITY only supports RAW, XHTTP and gRPC for now",
            );
        }
```

In `crates/xray-core-rs/src/outbound.rs`:

```rust
fn validate_connector_flow(
    flow: Option<&str>,
    transport: &ConnectorConfig,
    stream_transport: &StreamTransport,
) -> Result<VisionFlow, CoreError> {
    // Vision unwraps the TLS connection's internals directly, so anything
    // layered between it and TLS breaks it. Xray fails with "XTLS only
    // supports TLS and REALITY directly for now."
    if !matches!(stream_transport, StreamTransport::Raw) {
        return validate_vision_flow(flow, false);
    }

    validate_vision_flow(
        flow,
        matches!(
            transport,
            ConnectorConfig::Tls(_) | ConnectorConfig::Reality(_)
        ),
    )
}
```

Update both call sites to pass the outbound's stream transport.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-config/ crates/xray-core-rs/
git commit -m "feat: enforce Xray's transport compatibility matrix

REALITY is rejected for ws and httpupgrade, and Vision is rejected
outside the raw transport. Both mirror restrictions Xray enforces at
config-build time; without them a profile builds cleanly here and then
fails on the wire."
```

---

### Task 5: The HTTPUpgrade transport

A fake upgrade with no RFC 6455 machinery: after the 101 the connection is raw bytes in both directions, with no framing, no keepalive and no close handshake.

Three details diverge from what a careful implementer would guess:

- Response validation is **stricter** than WebSocket's. The status is compared as the exact string `"101 Switching Protocols"`, and `Connection` must equal `upgrade` exactly after lowercasing — no token-list parsing. A proxy that appends `keep-alive` or drops the reason phrase breaks it.
- The configured path is assigned to Go's `URL.Path`, so Go escapes `?`: a path of `/ws?foo=bar` is emitted as `GET /ws%3Ffoo=bar`, where WebSocket sends a real query string. We reproduce this because the Xray server unescapes it back and the round trip only works if both sides agree.
- `ed` carries no payload here. Any positive value only means "do not block waiting for the 101".

**Files:**
- Create: `crates/xray-transport/src/stream/httpupgrade.rs`
- Modify: `crates/xray-transport/src/stream/mod.rs`, `crates/xray-transport/src/lib.rs`
- Test: `crates/xray-transport/tests/stream_httpupgrade_tests.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/xray-transport/tests/stream_httpupgrade_tests.rs`:

```rust
mod stream_httpupgrade_tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use xray_transport::stream::{connect_httpupgrade, HttpUpgradeConfig};

    /// Serves one canned response, then echoes. Returns the request bytes.
    async fn serve_once(
        response: &'static str,
        trailing: &'static [u8],
    ) -> (tokio::net::TcpListener, std::net::SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback listener must bind");
        let addr = listener.local_addr().expect("listener must report its address");
        let _ = (response, trailing);
        (listener, addr)
    }

    fn config(path: &str) -> HttpUpgradeConfig {
        HttpUpgradeConfig {
            path: path.to_owned(),
            host: "example.com".to_owned(),
            headers: Vec::new(),
            wait_for_response: true,
        }
    }

    #[tokio::test]
    async fn the_request_escapes_a_question_mark_in_the_path() {
        let (listener, addr) = serve_once("", b"").await;
        let recorded = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a client must connect");
            let mut buffer = vec![0u8; 2048];
            let read = stream.read(&mut buffer).await.expect("a request must arrive");
            buffer.truncate(read);
            let _ = stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                .await;
            buffer
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the loopback connect must succeed");
        connect_httpupgrade(Box::new(stream), &config("/ws?foo=bar"))
            .await
            .expect("the upgrade must succeed");

        let request = String::from_utf8(recorded.await.expect("the recorder must finish"))
            .expect("the request must be UTF-8");

        assert!(
            request.starts_with("GET /ws%3Ffoo=bar HTTP/1.1\r\n"),
            "Go escapes ? in URL.Path; WebSocket does not:\n{request}"
        );
        assert!(request.contains("\r\nConnection: Upgrade\r\n"), "{request}");
        assert!(request.contains("\r\nUpgrade: websocket\r\n"), "{request}");
        assert!(
            !request.contains("Sec-WebSocket"),
            "httpupgrade sends no RFC 6455 headers:\n{request}"
        );
    }

    #[tokio::test]
    async fn a_status_without_the_reason_phrase_is_rejected() {
        let (listener, addr) = serve_once("", b"").await;
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a client must connect");
            let mut buffer = vec![0u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 101\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                .await;
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the loopback connect must succeed");
        connect_httpupgrade(Box::new(stream), &config("/ws"))
            .await
            .expect_err("Xray compares the status as an exact string");
    }

    #[tokio::test]
    async fn a_connection_token_list_is_rejected() {
        let (listener, addr) = serve_once("", b"").await;
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a client must connect");
            let mut buffer = vec![0u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade, keep-alive\r\nUpgrade: websocket\r\n\r\n")
                .await;
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the loopback connect must succeed");
        connect_httpupgrade(Box::new(stream), &config("/ws"))
            .await
            .expect_err("httpupgrade compares Connection exactly, unlike WebSocket");
    }

    #[tokio::test]
    async fn bytes_after_the_response_reach_the_first_read() {
        let (listener, addr) = serve_once("", b"").await;
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("a client must connect");
            let mut buffer = vec![0u8; 2048];
            let _ = stream.read(&mut buffer).await;
            let _ = stream
                .write_all(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nHELLO")
                .await;
        });

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("the loopback connect must succeed");
        let mut upgraded = connect_httpupgrade(Box::new(stream), &config("/ws"))
            .await
            .expect("the upgrade must succeed");

        let mut buffer = [0u8; 5];
        upgraded
            .read_exact(&mut buffer)
            .await
            .expect("payload sent with the response must not be lost");
        assert_eq!(&buffer, b"HELLO");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p xray-transport --test stream_httpupgrade_tests
```

Expected: compile error, `connect_httpupgrade` not found.

- [ ] **Step 3: Write the implementation**

Create `crates/xray-transport/src/stream/httpupgrade.rs`:

```rust
//! Xray's HTTPUpgrade transport: an upgrade handshake with no RFC 6455
//! machinery behind it. After the 101 the connection is raw bytes.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{apply_masquerade, serialize_request, HeaderMap};
use crate::{BoxedTransportStream, TransportError};

/// Everything the dial needs, already resolved from config plus the security
/// layer's server name.
#[derive(Debug, Clone)]
pub struct HttpUpgradeConfig {
    /// Normalized path. May contain a `?`, which is percent-escaped on the
    /// wire because Go assigns it to `URL.Path`.
    pub path: String,
    /// `Host` header value: config `host`, else the TLS server name, else the
    /// destination address. Never carries a port.
    pub host: String,
    pub headers: Vec<(String, String)>,
    /// False when `ed` is non-zero: the dial returns without waiting for the
    /// 101, so the first payload write goes out right behind the request.
    pub wait_for_response: bool,
}

const EXPECTED_STATUS: &str = "HTTP/1.1 101 Switching Protocols";

/// Escapes a path the way Go's `URL.RequestURI()` does for `URL.Path`.
///
/// Go's path escaper leaves almost everything alone and escapes exactly one
/// reserved character here: `?`. So a configured path of `/ws?foo=bar` goes
/// out as `/ws%3Ffoo=bar`, where the WebSocket transport would send a real
/// query string. The Xray server unescapes it back, so the round trip works —
/// but only if we escape it too.
fn escape_path(path: &str) -> String {
    path.replace('?', "%3F")
}

pub async fn connect_httpupgrade(
    mut stream: BoxedTransportStream,
    config: &HttpUpgradeConfig,
) -> Result<BoxedTransportStream, TransportError> {
    let mut headers = HeaderMap::new();
    for (key, value) in &config.headers {
        headers.set(key, value);
    }
    apply_masquerade(&mut headers, "ws");
    headers.set("Connection", "Upgrade");
    headers.set("Upgrade", "websocket");

    let request = serialize_request("GET", &escape_path(&config.path), &config.host, &headers);
    stream
        .write_all(&request)
        .await
        .map_err(TransportError::Tcp)?;

    if !config.wait_for_response {
        return Ok(stream);
    }

    let leftover = read_and_validate_response(&mut stream).await?;
    Ok(Box::new(PrefixedStream::new(stream, leftover)))
}

/// Reads the response headers and returns any payload bytes that arrived in
/// the same read. Xray drops those; we keep them, because losing them is a
/// silent data-corruption bug waiting for a server that speaks first.
async fn read_and_validate_response(
    stream: &mut BoxedTransportStream,
) -> Result<Vec<u8>, TransportError> {
    let mut buffer = Vec::with_capacity(1024);
    let mut chunk = [0u8; 512];
    let header_end = loop {
        let read = stream.read(&mut chunk).await.map_err(TransportError::Tcp)?;
        if read == 0 {
            return Err(TransportError::HttpUpgradeRejected(
                "connection closed before the response headers".to_owned(),
            ));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(position) = find_header_end(&buffer) {
            break position;
        }
        if buffer.len() > 64 * 1024 {
            return Err(TransportError::HttpUpgradeRejected(
                "response headers exceeded 64 KiB".to_owned(),
            ));
        }
    };

    let head = String::from_utf8_lossy(&buffer[..header_end]).into_owned();
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if status != EXPECTED_STATUS {
        return Err(TransportError::HttpUpgradeRejected(format!(
            "unexpected status line `{status}`"
        )));
    }

    let mut connection = None;
    let mut upgrade = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim().to_ascii_lowercase();
        if name.eq_ignore_ascii_case("connection") && connection.is_none() {
            connection = Some(value);
        } else if name.eq_ignore_ascii_case("upgrade") && upgrade.is_none() {
            upgrade = Some(value);
        }
    }

    // Exact equality, not token-list membership. Xray compares these with ==
    // after lowercasing, so `Connection: Upgrade, keep-alive` is a failure.
    if connection.as_deref() != Some("upgrade") {
        return Err(TransportError::HttpUpgradeRejected(
            "Connection header must be exactly `upgrade`".to_owned(),
        ));
    }
    if upgrade.as_deref() != Some("websocket") {
        return Err(TransportError::HttpUpgradeRejected(
            "Upgrade header must be exactly `websocket`".to_owned(),
        ));
    }

    Ok(buffer[header_end + 4..].to_vec())
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}
```

`PrefixedStream` — a `BoxedTransportStream` that drains a leading buffer before delegating — goes in the same file; it implements `AsyncRead`, `AsyncWrite` and `TransportStream`, forwarding `poll_read_direct`/`poll_write_direct` to the plain poll methods and leaving `release_record_alignment` as the default no-op (record alignment exists only for Vision, which cannot run over this transport).

Add to `TransportError` in `crates/xray-transport/src/lib.rs`:

```rust
    #[error("httpupgrade handshake rejected: {0}")]
    HttpUpgradeRejected(String),
```

Export from `crates/xray-transport/src/stream/mod.rs`:

```rust
mod httpupgrade;

pub use httpupgrade::{connect_httpupgrade, HttpUpgradeConfig};
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p xray-transport --test stream_httpupgrade_tests
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/
git commit -m "feat(transport): add the HTTPUpgrade transport

Response validation is stricter than WebSocket's — the status is compared
as an exact string and Connection must equal `upgrade` exactly, with no
token-list parsing. The path is escaped the way Go escapes URL.Path, so a
configured `?` goes out as %3F, which is what the Xray server expects."
```

---

### Task 6: WebSocket framing

Separated from the handshake so it can be tested without a socket. Client frames are **always masked** with a fresh 4-byte key, every write is one **binary** message, and messages are fragmented at exactly **4096** payload bytes because gorilla's write buffer is `4*1024`. On the read side message boundaries carry no meaning: it is a pure byte stream, empty messages are skipped, and a masked frame from the server is a protocol error.

**Files:**
- Create: `crates/xray-transport/src/stream/websocket_frame.rs`
- Modify: `crates/xray-transport/src/stream/mod.rs`
- Test: `crates/xray-transport/tests/stream_websocket_tests.rs`

- [ ] **Step 1: Write the failing test**

Create `crates/xray-transport/tests/stream_websocket_tests.rs`:

```rust
mod stream_websocket_tests {
    use xray_transport::stream::{encode_client_frames, MAX_FRAME_PAYLOAD};

    fn unmask(payload: &mut [u8], key: [u8; 4]) {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[index % 4];
        }
    }

    #[test]
    fn a_small_write_is_one_masked_binary_frame() {
        let frames = encode_client_frames(b"hello");

        assert_eq!(frames[0], 0x82, "FIN set, opcode 0x2 (binary)");
        assert_eq!(frames[1], 0x80 | 5, "mask bit set, 5-byte payload");

        let key = [frames[2], frames[3], frames[4], frames[5]];
        let mut payload = frames[6..].to_vec();
        unmask(&mut payload, key);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn an_eight_kib_write_becomes_two_fragments_of_4096() {
        let payload = vec![0x41u8; 8192];
        let frames = encode_client_frames(&payload);

        // First fragment: FIN clear, opcode binary, 126 -> 16-bit length.
        assert_eq!(frames[0], 0x02, "FIN clear on the first fragment");
        assert_eq!(frames[1], 0x80 | 126);
        assert_eq!(u16::from_be_bytes([frames[2], frames[3]]), 4096);

        let second = 4 + 4 + 4096;
        assert_eq!(frames[second], 0x80, "FIN set, opcode 0x0 (continuation)");
        assert_eq!(frames[second + 1], 0x80 | 126);
        assert_eq!(
            u16::from_be_bytes([frames[second + 2], frames[second + 3]]),
            4096
        );
        assert_eq!(frames.len(), second + 4 + 4 + 4096);
    }

    #[test]
    fn the_fragment_size_matches_gorillas_write_buffer() {
        assert_eq!(MAX_FRAME_PAYLOAD, 4096);
    }

    #[test]
    fn each_frame_gets_a_fresh_mask_key() {
        let first = encode_client_frames(b"same");
        let second = encode_client_frames(b"same");

        assert_ne!(
            &first[2..6],
            &second[2..6],
            "a reused mask key would be a distinguishing signal"
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
cargo test -p xray-transport --test stream_websocket_tests
```

Expected: compile error, `encode_client_frames` not found.

- [ ] **Step 3: Write the implementation**

Create `crates/xray-transport/src/stream/websocket_frame.rs`:

```rust
//! RFC 6455 client framing, sized to match gorilla/websocket.
//!
//! Xray writes through gorilla with `WriteBufferSize: 4*1024`, so a message
//! larger than 4096 payload bytes is split into continuation frames at exactly
//! that boundary. The boundary is observable, so it is part of the shape.

use rand::RngCore;

/// Gorilla's write buffer, and therefore Xray's fragment size.
pub const MAX_FRAME_PAYLOAD: usize = 4096;

pub(crate) const OPCODE_CONTINUATION: u8 = 0x0;
pub(crate) const OPCODE_TEXT: u8 = 0x1;
pub(crate) const OPCODE_BINARY: u8 = 0x2;
pub(crate) const OPCODE_CLOSE: u8 = 0x8;
pub(crate) const OPCODE_PING: u8 = 0x9;
pub(crate) const OPCODE_PONG: u8 = 0xa;

const FIN: u8 = 0x80;
const MASKED: u8 = 0x80;

/// Encodes one write as a masked binary message, fragmenting at 4096 bytes.
///
/// An empty payload still produces one empty frame, matching gorilla's
/// `WriteMessage`.
pub fn encode_client_frames(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 16);
    let mut chunks = payload.chunks(MAX_FRAME_PAYLOAD).peekable();
    let mut first = true;

    if payload.is_empty() {
        encode_frame(&mut out, OPCODE_BINARY, true, &[]);
        return out;
    }

    while let Some(chunk) = chunks.next() {
        let opcode = if first { OPCODE_BINARY } else { OPCODE_CONTINUATION };
        encode_frame(&mut out, opcode, chunks.peek().is_none(), chunk);
        first = false;
    }

    out
}

pub(crate) fn encode_frame(out: &mut Vec<u8>, opcode: u8, fin: bool, payload: &[u8]) {
    out.push(if fin { FIN | opcode } else { opcode });

    let length = payload.len();
    if length < 126 {
        out.push(MASKED | length as u8);
    } else if let Ok(length) = u16::try_from(length) {
        out.push(MASKED | 126);
        out.extend_from_slice(&length.to_be_bytes());
    } else {
        out.push(MASKED | 127);
        out.extend_from_slice(&(length as u64).to_be_bytes());
    }

    // A fresh key per frame. Reusing one would be a distinguishing signal.
    let mut key = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut key);
    out.extend_from_slice(&key);

    out.extend(
        payload
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % 4]),
    );
}
```

Add to the same file a `FrameDecoder` that accumulates bytes and yields payload slices. Its rules:

- A **masked** frame from the server is a protocol error, as is any non-zero RSV bit.
- `OPCODE_TEXT`, `OPCODE_BINARY` and `OPCODE_CONTINUATION` payloads are delivered as one undifferentiated byte stream — message boundaries carry no meaning to the layer above, and empty messages are skipped.
- `OPCODE_PING` must be answered with `OPCODE_PONG` echoing the payload; `OPCODE_PONG` is ignored. There is no pong watchdog — do not add one, Xray has none.
- `OPCODE_CLOSE` ends the stream.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p xray-transport --test stream_websocket_tests
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/
git commit -m "feat(transport): add WebSocket client framing

Every write is one masked binary message, fragmented at exactly 4096
payload bytes to match gorilla's write buffer — the fragment boundary is
observable, so it is part of the fingerprint."
```

---

### Task 7: The WebSocket handshake and early data

New dependency: `sha1` 0.10, the same RustCrypto generation as the `sha2` already in the workspace. Add it to `[workspace.dependencies]` in the root `Cargo.toml` and to `crates/xray-transport/Cargo.toml`.

Early data is the part most likely to go wrong, and its rules are exact:

- With `ed > 0`, **nothing touches the network** until the upper layer's first write.
- If that first write is `<= ed` bytes, it goes entirely into `Sec-WebSocket-Protocol` as **base64url without padding**, and no WebSocket frame is sent for it.
- If it is larger, early data is **disabled for the connection** — the header is omitted entirely — rather than truncated.
- The boundary is inclusive: `== ed` still uses early data.

Note that two different base64 variants appear in one handshake: `Sec-WebSocket-Key` is standard base64 **with** padding; early data is base64url **without**.

**Files:**
- Create: `crates/xray-transport/src/stream/websocket.rs`
- Modify: `Cargo.toml`, `crates/xray-transport/Cargo.toml`, `crates/xray-transport/src/stream/mod.rs`, `crates/xray-transport/src/lib.rs`
- Test: `crates/xray-transport/tests/stream_websocket_tests.rs`

- [ ] **Step 1: Write the failing tests**

Append to `crates/xray-transport/tests/stream_websocket_tests.rs`:

```rust
    use xray_transport::stream::{accept_key_for, encode_early_data};

    #[test]
    fn the_accept_key_follows_rfc_6455() {
        // The RFC's own worked example.
        assert_eq!(
            accept_key_for("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn early_data_is_base64url_without_padding() {
        // Standard base64 of these bytes ends in '=' and uses '+' and '/';
        // Xray uses RawURLEncoding, so neither may appear.
        let encoded = encode_early_data(&[0xfb, 0xff, 0xfe]);

        assert!(!encoded.contains('='), "no padding: {encoded}");
        assert!(!encoded.contains('+') && !encoded.contains('/'), "url alphabet: {encoded}");
        assert_eq!(encoded, "-__-");
    }
```

Plus socket-level tests mirroring Task 5's shape: one asserting the handshake sends `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`, `Upgrade: websocket` and `Connection: Upgrade`; one asserting a wrong `Sec-WebSocket-Accept` is rejected; one asserting `Connection: Upgrade, keep-alive` is **accepted** here (token-list parsing, unlike httpupgrade); one asserting that with `ed = 16` a first write of 16 bytes produces a handshake carrying `Sec-WebSocket-Protocol` and **no** WebSocket frame; and one asserting that a first write of 17 bytes omits the header entirely and sends the payload as a normal frame.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cargo test -p xray-transport --test stream_websocket_tests
```

Expected: compile error, `accept_key_for` not found.

- [ ] **Step 3: Write the implementation**

Create `crates/xray-transport/src/stream/websocket.rs` with:

```rust
const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const WEBSOCKET_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64_encode(input: &[u8], alphabet: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let bits = (u32::from(chunk[0]) << 16)
            | (chunk.get(1).copied().map_or(0, u32::from) << 8)
            | chunk.get(2).copied().map_or(0, u32::from);
        let symbols = chunk.len() + 1;
        for index in 0..symbols {
            let shift = 18 - index * 6;
            out.push(alphabet[((bits >> shift) & 0x3f) as usize] as char);
        }
        if pad {
            for _ in symbols..4 {
                out.push('=');
            }
        }
    }
    out
}

/// `base64(SHA1(key + GUID))`, the RFC 6455 accept-key derivation.
///
/// Standard base64 with padding here — unlike early data, which is base64url
/// without. Two variants in one handshake is easy to get backwards.
pub fn accept_key_for(client_key: &str) -> String {
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(client_key.as_bytes());
    hasher.update(WEBSOCKET_GUID.as_bytes());
    base64_encode(&hasher.finalize(), STANDARD_ALPHABET, true)
}

/// Base64url without padding, matching Xray's `base64.RawURLEncoding`.
pub fn encode_early_data(payload: &[u8]) -> String {
    base64_encode(payload, URL_ALPHABET, false)
}

/// Everything the WebSocket dial needs, resolved from config plus the
/// security layer's server name.
#[derive(Debug, Clone)]
pub struct WebSocketConfig {
    /// Normalized path, possibly carrying a real query string. Unlike
    /// HTTPUpgrade, `?` is **not** escaped here.
    pub path: String,
    /// `Host` header: config `host`, else the TLS server name, else the
    /// destination address. Never carries a port.
    pub host: String,
    pub headers: Vec<(String, String)>,
    /// From `?ed=N`. Zero disables early data entirely.
    pub early_data_bytes: u32,
    /// Seconds between client pings; zero means no keepalive.
    pub heartbeat_period_secs: u32,
}
```

and a `connect_websocket(stream, &WebSocketConfig)` that mirrors `connect_httpupgrade`'s shape, plus a deferred-dial wrapper for the `ed > 0` case that holds the unconnected config and performs the handshake on the first write.

Response validation, looser than httpupgrade's: status code 101 (the reason phrase is not compared), `Upgrade` **token list** contains `websocket`, `Connection` token list contains `upgrade`, and `Sec-WebSocket-Accept` equals `accept_key_for(sent_key)`. Handshake deadline 8 seconds.

Write the base64 and base64url encoders by hand — both are a few lines and neither warrants a dependency; `sha1` is needed only for the digest.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p xray-transport --test stream_websocket_tests
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/xray-transport/
git commit -m "feat(transport): add the WebSocket transport with early data

Early data goes in Sec-WebSocket-Protocol as unpadded base64url when the
first write fits the budget, and is disabled outright when it does not —
Xray never truncates. With ed set, nothing touches the network until that
first write."
```

---

### Task 7A: WebSocket keepalive and close

Task 3 parses `heartbeatPeriod` and Task 6 decodes ping frames, but nothing yet **sends** a ping or closes cleanly. Both are observable, so leaving them out is a shape difference, not just a missing feature.

Xray's rules, from `Xray-core/transport/internet/websocket/connection.go`:

- The ping loop runs only when `heartbeatPeriod != 0`. The period is in **seconds**, the ping payload is **empty**, and the write carries no deadline. The goroutine exits on the first error and is not tied to connection close, so it outlives the connection by up to one period — do not replicate that leak, but do replicate the visible behavior.
- Close writes a close frame **before** the socket closes: opcode `0x8`, payload the two-byte big-endian code `1000`, no reason text, with a 5-second write deadline.

**Files:**
- Modify: `crates/xray-transport/src/stream/websocket.rs`
- Test: `crates/xray-transport/tests/stream_websocket_tests.rs`

- [ ] **Step 1: Write the failing tests**

Add two socket-level tests in the shape of the Task 5 tests: one setting `heartbeat_period_secs: 1`, then asserting that within ~2.5 seconds the server sees at least one frame with opcode `0x9` and a zero-length payload (use `tokio::time::pause`/`advance` if the file already uses them; otherwise a real sleep with a generous bound is acceptable for one test). One asserting that dropping the stream causes the server to receive a frame whose first byte is `0x88` and whose unmasked payload is exactly `[0x03, 0xe8]` — that is 1000 big-endian.

- [ ] **Step 2: Run them to verify they fail**

```bash
cargo test -p xray-transport --test stream_websocket_tests heartbeat
cargo test -p xray-transport --test stream_websocket_tests close_frame
```

Expected: FAIL — no ping is ever sent, and no close frame precedes the socket close.

- [ ] **Step 3: Implement both**

Spawn the ping task only when `heartbeat_period_secs > 0`, and give it a shutdown signal tied to the stream's lifetime so it does not outlive the connection. Send the close frame from the stream's shutdown path, using `encode_frame(out, OPCODE_CLOSE, true, &1000u16.to_be_bytes())`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cargo test -p xray-transport --test stream_websocket_tests
```

- [ ] **Step 5: Commit**

```bash
git add crates/xray-transport/
git commit -m "feat(transport): send WebSocket keepalive pings and a close frame

heartbeatPeriod is in seconds and the ping payload is empty; close writes
code 1000 with no reason before the socket closes. Both are observable,
so omitting them would be a shape difference rather than a missing
convenience. Unlike Xray's goroutine, the ping task is tied to the
stream's lifetime instead of leaking for one period."
```

---

### Task 8: Wire the transports into the dialer and the outbound

**Files:**
- Modify: `crates/xray-transport/src/stream/mod.rs`, `crates/xray-transport/src/dialer.rs`
- Modify: `crates/xray-core-rs/src/outbound.rs`
- Test: `crates/xray-core-rs/tests/runtime_data_path_tests.rs`

- [ ] **Step 1: Write the failing test**

In `crates/xray-core-rs/tests/runtime_data_path_tests.rs`, add a parse-then-build test: a `network: "ws"` VLESS config must parse, build an outbound, and carry a `StreamTransport::WebSocket` whose path and host survive. Follow the shape of `parsed_plain_tls_config_builds_an_outbound_with_the_default_fingerprint`, which the previous plan added to that file.

- [ ] **Step 2: Run it to verify it fails**

```bash
cargo test -p xray-core-rs ws_config_builds_an_outbound
```

Expected: FAIL — the outbound carries no transport.

- [ ] **Step 3: Add the enum and the dialer method**

In `crates/xray-transport/src/stream/mod.rs`:

```rust
/// The transport layered over the security layer. `Raw` is a no-op.
///
/// Deliberately **not** named `StreamTransport`: `xray_config::StreamTransport`
/// is the parsed config shape, this is the dial-ready one with the host
/// precedence already resolved. Two types with one name across two crates in
/// the same call chain is how the wrong one gets imported.
#[derive(Debug, Clone)]
pub enum TransportLayer {
    Raw,
    WebSocket(WebSocketConfig),
    HttpUpgrade(HttpUpgradeConfig),
}

impl TransportLayer {
    pub async fn wrap(
        &self,
        stream: BoxedTransportStream,
    ) -> Result<BoxedTransportStream, TransportError> {
        match self {
            Self::Raw => Ok(stream),
            Self::WebSocket(config) => connect_websocket(stream, config).await,
            Self::HttpUpgrade(config) => connect_httpupgrade(stream, config).await,
        }
    }
}
```

In `crates/xray-transport/src/dialer.rs`:

```rust
    /// Dials through the security layer, then applies the stream transport.
    ///
    /// The candidate race and the REALITY preconnect stay entirely inside
    /// `connect_resolved`; this only layers framing on top of its result.
    pub async fn connect_stream(
        &self,
        config: &ConnectorConfig,
        transport: &TransportLayer,
        original_target: &Target,
        candidates: &[SocketAddr],
        happy_eyeballs: Option<&HappyEyeballsConfig>,
    ) -> Result<BoxedTransportStream, TransportError> {
        let stream = self
            .connect_resolved(config, original_target, candidates, happy_eyeballs)
            .await?;
        transport.wrap(stream).await
    }
```

- [ ] **Step 4: Carry the transport through the outbound**

In `crates/xray-core-rs/src/outbound.rs`, `VlessTcpOutbound` gains a `transport_layer: TransportLayer` built from the config, and the three `connect_resolved` call sites become `connect_stream`. Build it by resolving the host precedence — config `host`, else the TLS server name, else the destination address, never with a port — and mapping `early_data_bytes` onto `wait_for_response` for httpupgrade (`wait_for_response = early_data_bytes == 0`).

- [ ] **Step 5: Run the tests**

```bash
cargo test --workspace
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/xray-transport/ crates/xray-core-rs/
git commit -m "feat: dial VLESS through ws and httpupgrade transports

connect_stream layers the transport over connect_resolved, leaving the
candidate race and the REALITY preconnect untouched. Everything above —
the VLESS header, Vision, XUDP — is unchanged, because it already
operates on a BoxedTransportStream."
```

---

### Task 9: Interop against a live Xray-core

`crates/xray-core-rs/tests/local_xray_interop_tests.rs` already spawns a real Go Xray-core from the local checkout with a generated config; read it and follow its conventions. These tests are `#[ignore]`d because they need a Go toolchain — that is the established pattern for this file, and unlike the ClientHello oracle they are genuinely end-to-end, so the ignore is acceptable here.

**Files:**
- Modify: `crates/xray-core-rs/tests/local_xray_interop_tests.rs`

- [ ] **Step 1: Add the ws matrix**

Add `#[ignore]`d tests covering `ws` and `httpupgrade`, each against `security: "none"` and `security: "tls"`, plus one `ws` case with `?ed=2048` in the path so early data is exercised against the real server. Generate the Go server config with the matching `wsSettings`/`httpupgradeSettings`.

- [ ] **Step 2: Run them**

```bash
cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored
```

Expected: PASS. A failure here means the wire format diverges from Xray's — that is what this test is for, so treat any failure as a real defect rather than a test problem, and report it rather than adjusting the test.

- [ ] **Step 3: Commit**

```bash
git add crates/xray-core-rs/tests/local_xray_interop_tests.rs
git commit -m "test: interop ws and httpupgrade against a live Xray-core"
```

---

## Verification

```bash
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p xray-core-rs --test local_xray_interop_tests -- --ignored
```

The last needs a Go toolchain and the `Xray-core/` checkout; it is the only test here that proves the wire format against the reference rather than against our own reading of it.

## Documentation

`docs/config-compatibility.md` states that WebSocket and other stream transports are not supported. Rewrite that once this lands, including the compatibility matrix — REALITY is unavailable for both of these transports, and Vision requires `raw` — and the `ed` semantics, which differ between the two transports despite the shared spelling.

# Outbound HTTP Probe Design

## Goal

Let hosts optionally treat startup as successful only after `xray-rust` proves that real HTTP(S) traffic can pass through the configured outbound. This is aimed at blocked-network environments where binding local inbounds or starting a packet tunnel is not enough to mean the proxy path works.

## Scope

The first implementation adds one startup probe path:

- optional and disabled by default;
- configured by host/runtime options, not by mutating the Xray JSON model;
- accepts a custom `http://` or `https://` URL;
- uses the configured outbound path, including VLESS, TLS, REALITY, Vision, DNS, and socket protection;
- considers any HTTP status in `200..399` successful;
- fails startup on DNS, outbound open, TLS, HTTP parse, timeout, unsupported URL, or non-`2xx/3xx` response failures.

The feature does not add periodic health checks, retry policy, redirect following, ICMP ping, or a general-purpose HTTP client.

## API Shape

Add a `StartupProbeOptions` runtime configuration in `xray-core-rs`:

- `url: String`
- `timeout: Duration`
- `outbound_tag: Option<String>`

FFI exposes setters before config load or start so Apple and Android hosts can enable the probe without embedding xray-rust-specific fields in Xray JSON. A reasonable default URL can be provided by hosts, but the core treats the URL as caller-supplied when the probe is enabled.

## Outbound Selection

The probe must not use the platform network stack directly. It opens a stream through existing outbound helpers.

When `outbound_tag` is set, the probe selects that outbound directly. When it is absent, the probe uses the config's default outbound tag, falling back to the first outbound, matching existing default selection behavior.

The probe intentionally does not evaluate routing rules against the probe URL host. A regional routing rule for `google.com` should not be able to route the startup probe to `freedom` by accident when the user wants to validate the configured proxy outbound.

## Probe Flow

1. `Core::start` starts normal listeners/TUN tasks.
2. If startup probe options are absent, startup returns success as it does today.
3. If options are present, the core parses the URL and derives scheme, host, port, and path.
4. The core opens a TCP outbound stream to the URL host and port through the selected configured outbound.
5. For `https`, the core performs a TLS client handshake over that already-open outbound stream with SNI set to the URL host.
6. The core sends a minimal HTTP/1.1 `GET` with `Host` and `Connection: close`.
7. The core reads enough response bytes to parse the status line.
8. Status `200..399` succeeds. Any other result fails.
9. On failure, `Core::start` stops tasks it just started and returns a probe-specific error.

## Error Handling

Introduce a distinct core error for probe failures so FFI and UI layers can show a useful startup failure instead of a generic runtime error. The error message should include the probe URL and the failure class, but should not include secrets from outbound configuration.

Timeout wraps the entire probe, including DNS, outbound open, TLS, write, and first response bytes. A small host-provided timeout, such as five seconds, is enough for startup validation while avoiding long VPN connect hangs.

## Boundaries

`xray-core-rs` owns the probe orchestration because it already owns outbound selection and core lifecycle. `xray-transport` continues to own raw TCP/TLS/REALITY dialing. No dependency should bypass `TransportDialer`.

The HTTP request/response parser can stay intentionally small: construct one GET request and parse the first HTTP status line. The implementation should reject malformed responses instead of trying to recover.

## Testing

Tests should cover:

- probe disabled keeps current startup behavior;
- custom HTTP URL succeeds through a selected outbound when the server returns `2xx`;
- custom HTTPS URL performs TLS over the outbound stream and succeeds on `2xx/3xx`;
- non-`2xx/3xx` status fails startup;
- timeout or outbound open failure stops the core and returns a probe error;
- explicit `outbound_tag` is honored;
- absent `outbound_tag` uses default/first outbound without applying routing rules to the probe host;
- invalid or unsupported URLs are rejected with config/runtime errors before network I/O.

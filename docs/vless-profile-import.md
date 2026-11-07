# VLESS share-link import

The development Rust import API and the C ABI accept `vless://` share links as
format `vless`. The Swift and Kotlin SDKs still import VLESS links with their
own `XrayVlessURLImporter`/`XrayVlessUrlImporter`; switching them to this core
importer is a follow-up. Use the header and native library built from the same
revision; this change does not publish SDK binaries.

The C request is `{"format":"vless","text":"vless://<uuid>@server.example:443?..."}`.
It requires ABI major 1, minor >=17, `PROFILE_IMPORT` (bit 18) and
`VLESS_PROFILE_IMPORT` (bit 30). The C function, result schema and
[shared ownership/size limits](v07-profile-import.md) are unchanged. Input and
returned JSON contain the user ID; errors and profile debug descriptions are
redacted.

## Accepted subset

- `vless://<uuid>@<host>:<port>?<query>#<name>`. The scheme is
  case-insensitive. The user ID is read as Xray-core's `uuid.ParseString`
  reads it, as in VMess links: a UUID with or without its hyphens, or 1 to 30
  bytes of text, which names a version 5 UUID. Hostnames,
  IPv4 and bracketed IPv6 are accepted; the port is required (1..65535).
- The percent-decoded fragment is the profile name; without one the name is
  `host:port` (`[ipv6]:port`). `+` stays a literal plus.
- Query names match case-insensitively. Known names may not repeat; unknown
  names (such as `packetEncoding`) are ignored, as the SDK importers ignore
  them.
- `encryption` is `none` (default) or a VLESS encryption string, validated by
  the bounded VLESS encryption parser.
- `security` is `none` (default), `tls` or `reality`. TLS reads `sni` (default:
  the host), `fp`, `alpn` (comma-separated, without empty entries or spaces),
  `pcs` and `vcn`; `allowInsecure` is accepted only as `0`/`false`, and `cs`
  (cipher suites) is refused. REALITY requires `pbk`, reads `sni` (default: the
  host), `fp`, `sid` (default: empty, as Xray-core reads a missing shortId),
  `spx` and `pqv`, and accepts only `alpn=h2`, which it drops.
- `type` is `tcp`/`raw` (default), `ws`/`websocket`, `httpupgrade`, `grpc` or
  `xhttp`/`splithttp`, with the same carrier fields as the Trojan and VMess
  links: `host`, `path`, `serviceName`, `authority`, `mode`, `extra` (also
  accepted percent-encoded twice) and `heartbeatPeriod`. REALITY is refused on
  WebSocket and HTTPUpgrade; RAW accepts only `headerType=none`.
- `flow` is empty, `xtls-rprx-vision` or `xtls-rprx-vision-udp443`. Without
  VLESS encryption it requires RAW with TLS or REALITY, as Xray-core's Vision
  does.
- `fm` is Remnawave's percent-encoded `streamSettings.finalmask` object.
- A known parameter that the selected security or carrier does not use is
  refused (`pbk` with TLS, `host` on gRPC, non-empty `ech`, ...). Empty carrier
  fields and empty `pcs`, `vcn`, `cs`, `ech`, `echQuery` and `pqv` are ignored.

The imported profile is checked by the normal config parser, so its policies
apply: cleartext VLESS (no TLS, REALITY or VLESS encryption) imports only for a
private destination, and REALITY values such as `spx` follow Xray-core. The
import keeps a profile on which the parser only warns about a REALITY
fingerprint or HTTPUpgrade `?ed=` early data; XHTTP with `alpn=h3` imports only
when `fm` sets `quicParams.disableChromeParrot` to `true`, acknowledging that
QUIC runs without Chrome fingerprint shaping.

## Differences from the SDK importers

The core importer follows Xray-core where the SDK importers are looser or
stricter:

- Cleartext VLESS over XHTTP to a public address is refused; over RAW and the
  framed carriers it imports for a private destination.
- `allowInsecure=1` is refused on every carrier, XHTTP included.
- TLS gets no default `fp`: Xray-core then uses its own TLS stack, where the
  SDK importers write `chrome`.
- XHTTP with `alpn=h3` needs the `fm` acknowledgement above.
- RAW with REALITY refuses what the SDK importers drop there: `alpn` other than
  `h2`, `host`, `path`, `allowInsecure=1`, and `pcs`, `vcn` or `ech` values.
- A missing REALITY `sid` imports as the empty shortId, as in Xray-core; the
  SDK importers require it.
- `cs` is refused, `headerType` on RAW must be absent, empty or `none`, and
  `heartbeatPeriod` is read only on WebSocket; the SDK importers ignore all
  three.
- An empty `alpn`, or one with an empty entry or spaces, is refused, as the
  SDK importers refuse it on TLS.
- An ID of 1 to 30 bytes of text, or a UUID without its hyphens, imports, as
  Xray-core reads it; the SDK importers take only the canonical UUID.
- The user part is the whole ID: `uuid:password@` names no ID and is refused.
- The fragment name must fit the shared profile-name rule, at most 128 UTF-8
  bytes without control characters or bidi overrides; a longer remark fails
  with the name error, where the SDK importers keep it.
- `peer` and `insecure` are not aliases. Pasted text around a link and links
  without the `vless://` scheme are not extracted; trim them before import.

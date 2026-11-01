# SOCKS5 share-link import

The development Rust, Swift and Kotlin import APIs accept `socks://` and
`socks5://` links as format `socks`. Both schemes select SOCKS5. This adds offline
import to the existing SOCKS runtime; it does not publish new SDK binaries.
Use matching adapters, header and native library built from this source revision.

```swift
if XrayCore.ffiInfo.supportsProfileImport(.socks) {
    let imported = try XrayProfileImporter.profile(from: linkText, format: .socks)
    // Store imported.configJSON using the host's secure profile storage.
}
```

```kotlin
if (XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Socks)) {
    val imported = XrayProfileImporter.profile(linkText, XrayProfileFormat.Socks)
    // Use the existing DNS bootstrap and VPN startup path for imported.configJson.
}
```

The C request is `{"format":"socks","text":"socks5://server.example:1080"}`.
`name` and `dnsServers` retain the [shared import contract](v07-profile-import.md).
The format requires ABI major 1, minor >=13, `PROFILE_IMPORT` (bit 18) and
`SOCKS_PROFILE_IMPORT` (bit 26). Swift/Kotlin check all three before calling
native import. An older library's SOCKS outbound support is insufficient.
The C function, result schema and ownership rules are unchanged.

## Accepted syntax

- Schemes are case-insensitive. A hostname, IPv4 address or bracketed IPv6
  address and an explicit port from 1 through 65535 are required. Outer
  whitespace is trimmed; internal raw whitespace/control characters fail.
- No userinfo means no authentication. `user:password@` accepts percent-encoded
  UTF-8; split at the first literal colon before decoding so `%3A` can belong
  to a username. A fully percent-encoded pair is also accepted. Literal `+`
  stays `+`, and percent decoding happens once.
- Userinfo may instead be Base64 of UTF-8 `user:password`, using the standard
  or URL-safe alphabet, with or without padding. Percent-encoded Base64 is
  accepted. Decoded Base64 content is literal: `%40` in its password stays
  `%40`. These userinfo forms match the modern share-link forms in
  [v2rayNG](https://github.com/2dust/v2rayNG/blob/aa4b05503a504a3f2e43818e6ee8ebf1caaa3df0/V2rayNG/app/src/main/java/com/v2ray/ang/fmt/SocksFmt.kt)
  and [v2rayN](https://github.com/2dust/v2rayN/blob/57f17d5939e88c8e643ab49b90869d637765e75a/v2rayN/ServiceLib/Handler/Fmt/SocksFmt.cs).
- An entirely empty pair (`:`, `Og==` or `Og`) means no authentication, matching
  those clients' exports. Only one empty field is an error. Authenticated user
  and password must each contain 1..255 UTF-8 bytes without control characters.
  Invalid Base64/UTF-8, incomplete credentials and encoded NULs fail; they never
  fall back to an unauthenticated connection.
- One optional terminal `/` and a percent-decoded display-name fragment are
  accepted. An absent/empty fragment defaults to `SOCKS5`; `name` can override
  it. Names remain limited to 128 UTF-8 bytes without control characters or
  bidi embeddings, overrides and isolates.
- Nonempty query strings, paths, scoped IPv6, unsupported schemes (including
  `socks4` and `socks5h`) and legacy whole-authority Base64 are rejected. TLS,
  custom transports and UDP switches are not inferred from link parameters.
  Such configurations can still use the supported JSON configuration API.

Examples contain synthetic credentials only:

```text
socks://server.example:1080#Proxy
socks5://synthetic-user:synthetic-pass@[2001:db8::7]:1080
socks://c3ludGhldGljOnBhc3M=@server.example:1080
```

## Generated configuration and checks

The result contains a TUN inbound, one default `socks` outbound in flat settings
form, and `AsIs` routing. It preserves the proxy hostname for the ordinary
mobile carrier-bootstrap path. The default IPv4 FakeIP pool is `198.19.0.0/16`,
32768 entries, TTL 60; destination names reach the SOCKS server for remote DNS.
Explicit `dnsServers` selects real DNS with 1..8 validated literal IP servers;
no public resolver is inserted. The link uses plain SOCKS5 over raw TCP; its
credentials and UDP relay traffic are not encrypted by SOCKS itself.

Import performs no network lookup or connection. It validates the generated
configuration; FFI also loads it into an unstarted core. The existing 64 KiB
source and 256 KiB request/result limits, redacted errors and buffer cleanup
apply. The returned JSON contains credentials and remains caller-owned.

Parser tests cover alias/authority/credential variants, byte limits, one-time
decoding, DNS/name options and malformed inputs. FFI tests check exact buffer
sizing, loadability and redacted failures. Swift and actual host JNI tests
exercise the shared parser and old-library capability guards. The existing
`profile_import` fuzz target includes SOCKS URI and JSON seeds.

`scripts/check-socks-interop.sh` also imports links, retains their outbound,
DNS/routing and TUN configuration, adds a loopback test inbound, then transfers
data through the pinned Go SOCKS server. It covers IPv4/IPv6 proxy carriers,
plain/Base64 authentication and noauth (including `Og==`). The injected local
resolver accepts only the proxy hostname, so destination DNS must happen at
the Go server. These checks require no physical Android phone.

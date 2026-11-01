# HTTP and HTTPS proxy-link import

The development Rust, Swift and Kotlin import APIs accept HTTP CONNECT proxy
URIs as format `http`. `http://` selects plain TCP; `https://` selects TLS to
the proxy. This is offline import for the existing TCP-only HTTP/1.1 runtime.
Use adapters, header and native library built from the same revision; this
change does not publish SDK binaries.

```swift
if XrayCore.ffiInfo.supportsProfileImport(.http) {
    let imported = try XrayProfileImporter.profile(from: linkText, format: .http)
    // Store imported.configJSON in the host's secure profile store.
}
```

```kotlin
if (XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Http)) {
    val imported = XrayProfileImporter.profile(linkText, XrayProfileFormat.Http)
    // Use the existing DNS bootstrap and VPN startup path for imported.configJson.
}
```

The C request is `{"format":"http","text":"https://proxy.example:8443"}`.
Both schemes require ABI major 1, minor >=14, `PROFILE_IMPORT` (bit 18) and
`HTTP_PROFILE_IMPORT` (bit 27). Swift/Kotlin check these before native import.
The C function, result schema and [shared ownership/size limits](v07-profile-import.md)
are unchanged. Input, returned JSON and platform strings can contain credentials;
errors and profile debug descriptions are redacted.

## Accepted subset

- Schemes are case-insensitive. Hostnames, IPv4 and bracketed IPv6 are accepted.
  Our URI defaults are port 80 for HTTP and 443 for HTTPS; an explicit port
  1..65535 overrides them. These defaults are part of this import contract;
  other proxy clients can use different defaults.
- No userinfo means no authentication. `user:password@` is percent-decoded
  UTF-8, split at the first literal colon before decoding. A username alone or
  `user:@` means Basic authentication with an empty password. A username is
  required when userinfo exists: empty/partial malformed credentials never
  become noauth. Usernames cannot contain `:`; neither field permits control
  characters. Username length is 1..1024 UTF-8 bytes, password 0..1024.
- Percent decoding happens once and literal `+` stays `+`. Passwords may contain
  colons; reserved authority delimiters must be escaped. Base64 is **not**
  guessed: `Og==@` is the literal username `Og==` with an empty password.
  Legacy Base64 exports should be converted to explicit percent-encoded
  `user:password@` before import. A portless authority without `@` or `.` that
  decodes as Base64 to `…@host:port` is such an export and fails with
  `Unsupported` instead of becoming a one-label host whose name would reach DNS.
- Outer whitespace is trimmed. One terminal `/`, an empty `?`, and a
  percent-decoded display-name fragment are accepted. Missing/empty names
  default to `HTTP` or `HTTPS`; the shared `name` option can override them.
- Nonempty query strings, paths, raw whitespace/control characters, invalid
  percent encodings/UTF-8, duplicate `@`/`#`, scoped IPv6 and other schemes fail.
  TLS bypass, custom SNI, transports and headers are not inferred from query
  parameters. Advanced supported settings use the JSON configuration API.

Examples use synthetic credentials:

```text
http://proxy.example:8080#Office
https://synthetic-user:p%40ss%3Aword@proxy.example:8443#TLS
https://[2001:db8::7]
```

## Transport and DNS

The result contains a TUN inbound, one default `http` outbound and `AsIs`
routing. The proxy hostname is retained for the existing mobile carrier
bootstrap. HTTPS sets that same host as `serverName`, retains normal trust and
hostname/IP-SAN verification, and sets ALPN to `http/1.1`. Import itself does
not connect to or verify the remote server. Plain HTTP sends Basic credentials
without transport encryption. The scheme describes the proxy transport;
destination TLS, if any, remains inside the CONNECT tunnel.

Without `dnsServers`, the result uses the shared IPv4 FakeIP pool
`198.19.0.0/16` (32768 entries, TTL 60); destination names reach the proxy for
remote resolution. Explicit `dnsServers` accepts 1..8 validated literal IPs
and emits routed TCP DNS endpoints, e.g. `tcp://192.0.2.53:53` or
`tcp://[2001:db8::53]:53`. HTTP has no UDP relay, so plain UDP DNS would fail.
The selected resolvers must support TCP/53; no public resolver is inserted.
UDP application traffic, HTTP/2 CONNECT and custom headers remain unsupported.

## Validation

Parser tests cover defaults, IPv6, credentials, byte limits, one-time decoding,
TLS policy, TCP DNS and malformed inputs. FFI tests cover exact output sizing,
loadable configurations and redacted failures. Swift and host JNI tests exercise
the shared parser, DNS preflight/bootstrap and old-library capability guards.
HTTP/HTTPS URI and JSON seeds extend the existing `profile_import` fuzz target.

`scripts/check-http-interop.sh` imports both schemes and transfers data through
the pinned Go Xray-core HTTP inbound, testing Basic/noauth, wrong/missing
credentials, hostname/IP carriers and remote destination DNS. It retains the
imported outbound, DNS, routing and TUN and adds a loopback test inbound. TLS
tests inject only test trust configuration, keep hostname verification active,
and use the same HTTP/1.1 ALPN. Local tests reject wrong certificate names and
untrusted certificates before sending credentials. Existing system-connector
tests separately verify HTTP/1.1-only ALPN, including shaped TLS. No physical
Android device is required for these host tests.

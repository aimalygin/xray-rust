# v0.7 mobile profile import

The development SDK imports Hysteria 2 share links and standard WireGuard
configuration text through one Rust parser. C ABI **1.5** exposes offline import
and protocol capability discovery. Workspace/release version remains 0.6.1;
Xray-core remains pinned to v26.7.28 at
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`. This is development source support,
not a published mobile release or a claim of complete upstream feature parity.

## API and ownership

`xray_profile_import_json` takes a UTF-8 byte span containing:

```json
{"format":"hysteria2","text":"hy2://example-password@server.example#Example","name":"Example","dnsServers":[]}
```

`format` is `hysteria2` or `wireguard`. `name` and `dnsServers` are optional;
unknown/duplicate fields are errors. The result is:

```json
{"schemaVersion":1,"name":"Example","serverAddress":"server.example","configJSON":"...canonical core JSON..."}
```

Call with `buffer=NULL, buffer_len=0` to obtain the required UTF-8 byte count in
`written`. It excludes the terminating NUL; allocate `written + 1` for the second
call. A short buffer returns `BUFFER_TOO_SMALL`, reports the required count and
leaves the buffer untouched. Other errors set `written=0` and leave the buffer
untouched. Input/output spans must be disjoint, valid and stable during a call.
Use the usual initialized error slot and `xray_error_free` ownership contract.

No core handle, runtime, socket, DNS lookup, file read or command execution is
needed. Rust validates the generated JSON without diagnostics; the FFI also
constructs an unstarted core to validate typed runtime policy and cryptographic
identities, including unusable/duplicate WireGuard peer keys. The lower-level
`xray_config::profile_import` API alone performs config parsing, not the latter
runtime validation. Import does not verify a remote endpoint or certificate.

Capabilities are independent bits: `HYSTERIA2_OUTBOUND` (16),
`WIREGUARD_OUTBOUND` (17), `PROFILE_IMPORT` (18), under the
`XRAY_FFI_CAPABILITY_` prefix. Import requires ABI major 1, minor >=5, the import
bit and the selected protocol bit. Swift/Kotlin expose `supportsProfileImport`.
Compile/link the adapter, header and native binary together; checking a bit
cannot make a missing strongly linked symbol loadable in an older artifact.

```swift
import XrayMobileAdapter

if XrayCore.ffiInfo.supportsProfileImport(.hysteria2) {
    let imported = try XrayProfileImporter.profile(from: linkText, format: .hysteria2)
    let profile = imported.clientProfile(providerBundleIdentifier: "example.app.tunnel")
    // Persist profile through the host's existing secure profile store.
}
let importedWG = try XrayProfileImporter.profile(
    from: fileText, format: .wireguard, name: "Private network",
    dnsServers: ["192.0.2.53"] // Supply only when the file has no DNS field.
)
```

```kotlin
if (XrayCore.ffiInfo().supportsProfileImport(XrayProfileFormat.Wireguard)) {
    val imported = XrayProfileImporter.profile(fileText, XrayProfileFormat.Wireguard)
    // imported.configJson is ready for the existing bootstrap/core-load path.
}
```

The host reads the clipboard/file, presents format/name choices and securely
persists the returned config. Existing VLESS import remains available. This
increment adds SDK entry points, not file-picker or sample-app UI changes.
Use the [mobile bootstrap path](v07-mobile-bootstrap.md) before starting a VPN;
the result retains endpoint hostnames and needs the ordinary outer-address pins.

## Accepted source syntax

Hysteria follows the [official URI format](https://v2.hysteria.network/docs/developers/URI-Scheme/)
within the implemented runtime subset:

- `hy2://` and `hysteria2://`, percent-decoded UTF-8 auth (including user/password
  separated by a colon), a host and optional port (443 by default), optional
  terminal `/`, and a percent-decoded display-name fragment. Literal `+` stays
  `+`; percent decoding happens once. Bracketed IPv6 is supported.
- `sni` and `insecure=0`. TLS certificate verification and ALPN `h3` are retained.
  Missing SNI uses the endpoint host. Duplicate decoded keys are errors.
- `insecure=1`, certificate-pin parameters, ECH, obfuscation/Salamander,
  multi-port/hopping, bandwidth parameters and every unknown query field fail
  explicitly. Settings are never silently dropped to weaken verification or
  change the transport. Scoped IPv6 and nontrivial URL paths are unsupported.

WireGuard syntax follows [wg(8)](https://git.zx2c4.com/wireguard-tools/tree/src/man/wg.8)
and [wg-quick(8)](https://git.zx2c4.com/wireguard-tools/tree/src/man/wg-quick.8):

- One `[Interface]` followed by 1..8 `[Peer]` sections, case-insensitive field and
  section names, whitespace/CRLF and `#` comments. Address, DNS and AllowedIPs
  may repeat or contain comma-separated lists; duplicate scalar fields fail.
- Required interface `PrivateKey` and 1..2 `Address` values; optional `MTU`
  (default 1420, accepted 1280..1420). Core validation enforces address families
  and usable identities. File keys must be padded standard base64 encoding
  exactly 32 bytes, including optional `PresharedKey`.
- Every peer needs `PublicKey`, `Endpoint` with explicit port and nonempty
  `AllowedIPs`. `PersistentKeepalive` accepts 0..65535 seconds or `off` (default
  0). Order, overlapping prefixes and per-peer PSKs are preserved.
- Default/no-op values `ListenPort=0`, `FwMark=0`/`off`, `Table=auto`, and
  `SaveConfig=false` are accepted. Non-default values, hooks, custom table
  policy, unknown sections/fields and Amnezia extensions fail. Import never
  executes hooks. IPv4-mapped IPv6 prefixes and scoped endpoint literals fail.

## DNS and routing

Hysteria output has one default proxy outbound and an IPv4 FakeIP pool
(`198.19.0.0/16`, 32768 entries, TTL 60), allowing remote destination resolution.
Explicit `dnsServers` instead creates a real DNS configuration. TLS names and
auth are kept separately from the eventual bootstrap addresses.

WireGuard requires real DNS: 1..8 literal IP servers from the file's `DNS` or
the request's `dnsServers`. Supplying both is an error. No public resolver is
inserted. Search domains, hostname/URL resolvers, multicast/unspecified/scoped
IPs and mobile tunnel/DNS anchor addresses are rejected.

WireGuard output selects the proxy only for the union of `AllowedIPs` and uses
Freedom outside those ranges. `0.0.0.0/0` and `::/0` cover their respective
families; split routes remain split routes. DNS-server traffic follows those
same IP rules. `IPOnDemand` resolves domain destinations before IP matching;
there is no sniffing destination rewrite or FakeIP that could bypass the
explicit prefix policy. Addresses outside AllowedIPs, including DNS servers,
use the direct path. This is not a kill-switch profile: the host must show that
split-routing behavior when presenting an imported config.

## Limits and secrets

Source text is capped at 64 KiB; request/result JSON at 256 KiB each; display
names at 1..128 UTF-8 bytes without control characters; Hysteria auth at 4096
bytes and query entries at 16; WireGuard prefixes at 256 across all peers.
Malformed Unicode, NULs, keys, ports, CIDRs and ambiguous input fail with static
errors that never echo credentials. Kotlin rejects unpaired UTF-16 surrogates
instead of accepting the JVM encoder's replacement characters.

Imported profile descriptions/debug output are redacted. Explicit config
properties contain secrets. Rust zeroizes owned request text, percent-decoding
buffers, guarded config values and serialized config/result; JNI and SDKs clear
their owned transfer buffers on success and failure. This is best-effort
ownership cleanup, not a promise to erase all serde/JSON/framework/compiler
temporaries, immutable JVM/Swift strings or caller copies. Hosts must avoid
logging the config and use their established credential storage and input
cleanup paths.

## Verification

Shared synthetic fixtures live in `tests/fixtures/profile-import`. Parser and
FFI tests cover successful import, bounds, negative options, crypto policy,
error redaction, exact output sizing, non-overwrite and concurrent calls.
Swift tests invoke the current Rust library and load both results into a core;
Kotlin has injected-boundary tests plus optional real host-JNI integration.

```sh
cargo test --locked -p xray-config -p xray-ffi --tests
swift test --disable-sandbox --package-path platform/apple \
  --filter 'XrayProfileImporterTests|XrayPacketTunnelPumpTests|XrayMobileDNSPreflightTests|XrayPacketTunnelProviderTests'
platform/android/gradlew -p platform/android :xraymobile:testDebugUnitTest
# Requires configured JAVA_HOME and Android SDK. Builds current host Rust/JNI.
scripts/test-profile-import-jni.sh
```

`profile_import` is included in the extended pinned-nightly fuzz campaign,
with raw URI/config and JSON-request seeds. Artifact checks compile the C
signature and scan the exported native symbol. Run the same package/header
revision together; published 0.6.1 binaries do not provide the new import API.

Observed on macOS arm64, 2026-09-11 UTC: 519 config/FFI tests, 181 selected
Swift tests and all 96 Kotlin tests passed, including two actual JNI/Rust
integration tests. The standalone host-JNI script then passed its seven import
tests. Strict config/FFI Clippy, Rust formatting, C-header compilation, exported
symbol scan, mobile-toolchain/fuzz script guards and all 13 public-fixture
checks passed. A 30-second pinned-nightly fuzz run completed 419489 inputs with
no crash. Swift used a temporary debug macOS-arm64 XCFramework; JNI used the
current host library. These runs did not build or publish mobile release assets.

Host checks do not replace Apple/Android cross-compilation or physical-device
lifecycle, reconnect and memory acceptance, nor independent native-server
interoperability. Those remain v0.7 release work.

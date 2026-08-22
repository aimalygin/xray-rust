# xray-rust

Project website: [xray-rust.aimalygin.chatgpt.site](https://xray-rust.aimalygin.chatgpt.site)

`xray-rust` is a mobile/client-first Rust implementation of Xray configuration
and proxy protocols. It provides a native runtime, a C ABI, and integrations
for Apple platforms and Android. The current release focuses on an embeddable
client runtime; its supported compatibility surface is documented below.

This project is unofficial and is not affiliated with XTLS or Xray-core.

## Benchmarks

Synthetic localhost comparison against Xray-core `v26.5.9` and sing-box
`v1.13.15` with the process-level [benchmark harness](docs/benchmarks.md)
(medians across 5 runs; measured 2026-08-01 on Apple M3 Pro, macOS 26.5.2,
xray-rust `af33ae8`).

Lowest resident memory at every scale — 3.84 MiB idle and 18.3 MiB with
1000 held SOCKS flows, against 79.9 MiB for Xray-core and 46.1 MiB for
sing-box:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/memory-rss-dark.svg">
  <img alt="Peak resident set size, lower is better. Idle: xray-rust 3.84 MiB, Xray-core 28.1, sing-box 20.9. 100 idle flows: xray-rust 5.50, Xray-core 35.2, sing-box 26.4. 1000 idle flows: xray-rust 18.3, Xray-core 79.9, sing-box 46.1." src="docs/benchmarks/media/memory-rss-light.svg">
</picture>

Fastest through a full VLESS + REALITY + Vision tunnel — 14.3 Gbps at the
lowest CPU cost per GiB (770 ms vs 820/790):

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/reality-throughput-dark.svg">
  <img alt="Bulk TCP throughput through a VLESS + REALITY + Vision tunnel, higher is better: xray-rust 14.3 Gbps, Xray-core 13.7, sing-box 14.0." src="docs/benchmarks/media/reality-throughput-light.svg">
</picture>

About 4× less memory than Xray-core with real V2Fly geodata loaded:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/geo-memory-dark.svg">
  <img alt="Peak memory with real geodata loaded, lower is better: xray-rust 8.62 MiB, Xray-core 34.7 MiB." src="docs/benchmarks/media/geo-memory-light.svg">
</picture>

Latency, plain-SOCKS bulk throughput, CPU-per-GiB, and xray-rust DNS charts,
plus the full narrative and measurement caveats, are in
[benchmark results](docs/benchmarks/results.md).

## Current scope

| Area | Implemented | Important limits |
| --- | --- | --- |
| Local inbounds | SOCKS5 no-auth `CONNECT` and `UDP ASSOCIATE`, HTTP `CONNECT`, TUN | No authenticated proxy inbound or server-side Xray protocols |
| Outbounds | Freedom/direct, VLESS client over TCP, and DNS | No VMess, Trojan, Shadowsocks, WireGuard, balancers, or outbound chaining |
| Security and flow | TLS and REALITY with uTLS-shaped ClientHellos, `xtls-rprx-vision`, VLESS UDP and XUDP paths | Only the documented config subset; REALITY rejects the 14 fingerprints that carry no X25519 key share, while plain TLS accepts all 61 |
| Routing and DNS | Field rules with domain/IP/network/port matchers, `geosite`/`geoip`, Xray-style string/object DNS server selection, routed multi-address A/AAAA/CNAME resolution with global/per-server `queryStrategy` and TTL-aware cache, ordered `dns.hosts` IP arrays, one bounded per-Core fake-IP mapper, and ordered DNS-outbound Direct/Drop/Reject/Hijack policy shared by TUN, SOCKS TCP/UDP, and HTTP CONNECT; Direct supports UDP/TCP rewrite plus TCP/TLS/REALITY `streamSettings` | No `UseSystem` route probing, managed `dns.servers` DoH/DoT/DoQ, negative/stale cache, or full Xray DNS/routing parity |
| Mobile | Swift Package/Xcode sample for iOS, tvOS, and macOS; Android library and `VpnService` adapter | Signing, entitlements, VPN consent, foreground policy, and release packaging remain host-app responsibilities |

See [project status](docs/status.md) and
[configuration compatibility](docs/config-compatibility.md) for the detailed
matrix.

## Prerequisites

- Rust via `rustup`; [`rust-toolchain.toml`](rust-toolchain.toml) selects the
  exact toolchain used by the workspace.
- A C toolchain for native dependencies.
- Go only for deterministic oracle tools and optional Xray-core interoperability
  tests.
- Xcode for Apple artifacts, or JDK 17+, Android SDK 35, CMake 3.22.1, and NDK
  26.3.11579264 for Android artifacts.

## Quick start

Run the same Rust checks used by CI:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- \
  -D warnings -W clippy::perf -W clippy::suspicious
cargo test --workspace --all-targets --locked
```

For a local CLI smoke run, use the credential-free loopback example:

```sh
cargo run --locked -p xray-cli -- run \
  -config examples/freedom.json
```

The command starts a SOCKS5 listener at `127.0.0.1:1080`, routes directly
through the host network, and waits for `Ctrl-C`. It contains no proxy
credential. For VLESS, copy a synthetic fixture from
`tests/fixtures/configs/` outside the repository and replace every placeholder.
Never commit a live UUID, key, short ID, endpoint, or subscription URL.

For a self-contained data-path test that needs no external server:

```sh
cargo test --locked -p xray-core-rs \
  --test runtime_data_path_tests \
  socks_client_reaches_echo_target_through_freedom_outbound
```

## Mobile samples

Apple:

```sh
scripts/check-mobile-toolchains.sh --apple
scripts/build-apple-xcframework.sh
scripts/fetch-geodata.sh
open platform/apple/XrayClient/XrayClient.xcodeproj
```

The Xcode project consumes
`target/mobile/apple/XrayRust.xcframework` through the local Swift Package.
Choose the `XrayClient`, `XrayClientTv`, or `XrayClientMac` scheme. The
committed project builds unsigned under placeholder `org.example` identifiers;
to sign it, copy
`platform/apple/XrayClient/Config/Local.xcconfig.example` to `Local.xcconfig`
in the same directory and set your bundle prefix and Team ID there. That file
is git-ignored, so your identity stays out of the repository and Xcode leaves
nothing to commit. Register App IDs matching your prefix first — the tunnel
targets request the `packet-tunnel-provider` entitlement. The geodata download is needed by the checked-in Xcode
resource build phases; profiles that do not use geodata can omit those files in
a custom host project. See [Apple integration](platform/apple/README.md).

Android:

```sh
scripts/check-mobile-toolchains.sh --android
scripts/build-android-adapter.sh
```

This produces
`platform/android/xraymobile/build/outputs/aar/xraymobile-debug.aar`. See
[Android integration](platform/android/README.md).

## Prebuilt mobile SDK

Ready-to-integrate Apple and Android packages are published from
[`xray-rust-mobile`](https://github.com/aimalygin/xray-rust-mobile). Each mobile
release pins a reviewed core commit and includes checksums and a release
manifest that identify the corresponding source.

Add the Apple SDK with Swift Package Manager:

```swift
dependencies: [
    .package(
        url: "https://github.com/aimalygin/xray-rust-mobile.git",
        exact: "0.3.2"
    ),
]
```

The package provides the low-level `XrayMobileAdapter`, shared profile and
storage APIs in `XrayAppleShared`, and the ready-to-subclass
`XrayAppleTunnel` packet-tunnel provider. Android applications can consume
`io.github.aimalygin:xray-rust-mobile:0.3.2` from Maven Central without GitHub
credentials, or download the standalone AAR from the matching release. See the
[`xray-rust-mobile` integration guide](https://github.com/aimalygin/xray-rust-mobile#readme)
for setup details.

## Documentation

- [Status and supported features](docs/status.md)
- [Architecture](docs/architecture.md)
- [Configuration compatibility](docs/config-compatibility.md)
- [C ABI lifecycle and ownership](docs/ffi.md)
- [Verification](docs/verification.md)
- [Mobile testing](docs/mobile-testing.md)
- [Benchmark methodology](docs/benchmarks.md)
- [Benchmark results](docs/benchmarks/results.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## License

The project source is licensed under the
[Mozilla Public License 2.0](LICENSE). Downloaded geodata and other third-party
components remain under their respective licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

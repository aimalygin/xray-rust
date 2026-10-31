# xray-rust

The development compatibility reference is [Xray-core v26.10.21](docs/xray-core-v26.10.21-migration.md). Dated release and benchmark results below retain their original references.

Project website: [xray-rust.aimalygin.chatgpt.site](https://xray-rust.aimalygin.chatgpt.site)

Mobile repository: [xray-rust-mobile](https://github.com/aimalygin/xray-rust-mobile)

## Support the project

If you find this project useful, consider supporting its development with a donation:

- **TON (TON network):** UQCIpU1qagwDltuqPUZh4EuI2zXvismk6esCCTWUVphj_o4y
- **ETH (Ethereum network):** 0x96A9a65E188c439a95267a3dA6920884C530f57f
- **BTC (Bitcoin network):** bc1qxxk42z2ty8wx702sk5cammwhchl95y39kf2wdc
- **SOL (Solana network):** D4xFX2GwPniSetHZWn2XRTBaSM6m1k1wMtacr6TMVHQD

Thank you for your support!

## Benchmarks

The [2026-10-30 performance-branch report](docs/benchmarks/results/2026-10-30-perf-branch/README.md)
compares `main` at `9b06d374` with the branch at `123b9d8d` on one Apple M6,
against the same Xray v26.10.21 server and driver: **200 scenarios, five runs
per version, 2,000 accepted trials**. WebSocket uploads use 53–59% less CPU
per byte, one-flow gRPC downloads run 2.2× faster, XHTTP H3 uploads run 34–71%
faster at 23–46% less CPU, and XHTTP H1 uploads through TUN peak at up to 62%
less memory. Faster gRPC and XHTTP H3 flows also hold more data, up to 9.6 →
31.9 MiB for eight XHTTP H3 uploads through TUN, and XHTTP H1 uploads through
TUN cost 9.5% more CPU. The report explains each cost and keeps every repeat
and rejected attempt; 131/156 bulk cases change throughput by at most 5%. This
is a Rust before/after comparison; the earlier
[v26.10.21 migration comparison](docs/benchmarks/results/2026-10-27-v26.10.21-migration/README.md)
remains with its erratum. A later change on the branch shares one send budget
between XHTTP H3 uploads: 32 parallel uploads now peak at 87.7 instead of
162.1 MiB RSS and 32 duplex transfers at 78.2 instead of 140.6, at the same
throughput ([send-budget report](docs/benchmarks/results/2026-10-30-xhttp-h3-send-budget/README.md)).
On Linux, where quinn reserved 2.9 MiB of receive buffer for every XHTTP H3
connection, 32 parallel downloads now peak at 114.6 instead of 154.3 MiB at
the same throughput
([receive-buffer report](docs/benchmarks/results/2026-10-30-xhttp-h3-receive-batch/README.md)).
A vendored h3 no longer buffers downloads outside QUIC flow control: 32
downloads now peak at 95.8 instead of 112.5 MiB, and the longer they run
the more that saves ([download-memory report](docs/benchmarks/results/2026-10-31-xhttp-h3-download-memory/README.md)).

![Performance branch against main: median paired changes in throughput, CPU per GiB and peak footprint across all 156 bulk scenarios](docs/benchmarks/results/2026-10-30-perf-branch/bulk-changes.svg)

### Three-engine comparison (2026-10-30)

The synthetic localhost evidence below compares xray-rust `123b9d8` with
Xray-core `v26.10.21` (`1b1647cd9ddf0abc34b981d4611fc03bcac1ca74`) and stable
sing-box `v1.14.4` (`c005f35300ce76427dc285481ec5695f5b179cd2`). Values are
medians across five release runs on an Apple M6 with 32 GB RAM and macOS 27.0.
The [dated result group](docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/README.md)
holds all 58 scenarios (138 engine series), exact binary hashes, the stream,
XHTTP pressure and bounded-memory tables, and every omission with its reason.

For 0.7 regression checks and Hysteria2/WireGuard comparisons, see the
[0.7 performance record](docs/v07-performance.md), including the accepted
measurement tolerance, deferred RSS work and remaining comparison gaps.

Lowest resident memory at every measured idle-flow scale — 4.6 MiB idle and
22.7 MiB with 1,000 held SOCKS flows, against 78.6 MiB for Xray-core. sing-box
v1.14.4 uses 30.8 MiB idle and 37.6 MiB with 100 flows; none of its
1,000-flow runs completed on this host:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/media/memory-rss-dark.svg">
  <img alt="Peak resident set size, lower is better. Idle: xray-rust 4.6 MiB, Xray-core 27.4, sing-box 30.8. 100 idle flows: xray-rust 7.0, Xray-core 34.6, sing-box 37.6. 1000 idle flows: xray-rust 22.7, Xray-core 78.6, sing-box omitted." src="docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/media/memory-rss-light.svg">
</picture>

Through a full VLESS + REALITY + Vision tunnel, xray-rust reaches 22.1 Gbps
against Xray-core's 19.1 at 480 versus 500 CPU ms/GiB. Stable sing-box is
omitted: its REALITY client removes the X25519MLKEM768 key share that
v26.9.8 and later servers require:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/media/reality-throughput-dark.svg">
  <img alt="Bulk TCP throughput through a VLESS + REALITY + Vision tunnel, higher is better: xray-rust 22.1 Gbps and Xray-core 19.1; stable sing-box omitted at the recorded client compatibility boundary." src="docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/media/reality-throughput-light.svg">
</picture>

About 3.4× less memory than Xray-core with the pinned V2Fly geodata loaded:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/media/geo-memory-dark.svg">
  <img alt="Peak memory with real geodata loaded, lower is better: xray-rust 9.9 MiB and Xray-core 33.4 MiB." src="docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/media/geo-memory-light.svg">
</picture>

Plain TCP bulk through SOCKS is led by sing-box (100.0 Gbps against 90.4 for
xray-rust and 73.3 for Xray-core). Latency, CPU and setup charts and the full
caveats are in the [dated result group](docs/benchmarks/results/2026-10-30-v26.10.21-three-engine/README.md).
The [2026-08-31 RC4 group](docs/benchmarks/results/2026-08-31-v26.7.28/README.md),
the earlier Xray-core v26.5.9 and the xray-rust DNS charts remain available as
[historical evidence](docs/benchmarks/results.md).

## Current scope

The published 0.8.0 release includes Trojan, Shadowsocks 2022 and VMess AEAD,
with Swift/Kotlin integration. The development branch prepares 0.8.1 with an
Apple startup-probe ordering fix, additive ABI 1.12 and dependency updates. The
[implementation and acceptance record](docs/v08-implementation-plan.md)
distinguishes passing host/CI checks from remaining physical-device gates.
The [0.8 protocol comparison](docs/benchmarks/results/2026-09-30-v08-protocols/README.md)
contains 1050 successful full-client trials against Xray-core and sing-box:
RSS is lower throughout, but SS2022/VMess bulk throughput and CPU targets remain unmet.
The stable source baseline is [0.8.0](https://github.com/aimalygin/xray-rust/releases/tag/v0.8.0).
The 0.8.1 candidate is not yet published; exact-candidate release qualification
and canonical SDK artifacts remain pending.

| Area | Implemented | Important limits |
| --- | --- | --- |
| Local inbounds | SOCKS5 no-auth or RFC 1929 password `CONNECT` and `UDP ASSOCIATE`, HTTP `CONNECT`, TUN | Password-protected SOCKS UDP requires a declared client endpoint; no HTTP inbound authentication or server-side Xray protocols |
| Outbounds | Freedom/direct, Xray-compatible blackhole, VLESS, Hysteria 2, WireGuard, Trojan, Shadowsocks 2022, VMess AEAD, SOCKS5 `CONNECT` and `UDP ASSOCIATE` with optional RFC 1929 credentials, HTTP/1.1 `CONNECT` with optional Basic credentials, DNS, health-aware selector groups including bounded `leastLoad`, and validated transport-layer TCP chaining | No Shadowsocks AEAD-2017, legacy VMess authentication, SOCKS outbound Mux, HTTP/2 `CONNECT` or HTTP outbound UDP, server-side proxy protocols, or chaining outside the documented TCP subset |
| Security and flow | TLS and REALITY with uTLS-shaped ClientHellos, `xtls-rprx-vision`, VLESS UDP and XUDP paths | Only the documented config subset; REALITY rejects the 14 fingerprints that carry no X25519 key share and warns on those without the X25519MLKEM768 share v26.10.21 servers require, while plain TLS accepts all 61 |
| Routing and DNS | Field rules with domain/IP/network/port matchers, `geosite`/`geoip`, atomic rule/geodata snapshot replacement, Xray `routing.balancers` plus bounded `observatory` URL health checks and `leastLoad`, cycle-free TCP outbound graph edges, Xray-style DNS server selection including routed `tls://` DoT, routed/local HTTP/2 DoH, and provider-local `quic+local://` DoQ, routed multi-address resolution, TTL-aware positive/negative cache with bounded stale-while-revalidate, `dns.hosts`, bounded fake IP, and DNS-outbound Direct/Drop/Return/Hijack policy | Full config and outbound/balancer topology replacement still requires a new core; no UDP/protocol-layer outbound chaining, `UseSystem` route probing, per-server cache policy, or full Xray DNS/routing parity |
| Mobile | Swift Package/Xcode sample for iOS, tvOS, and macOS; Android library and `VpnService` adapter | Signing, entitlements, VPN consent, foreground policy, and release packaging remain host-app responsibilities |
| Management | Development ABI 1.12 plus Swift/Kotlin expose protocol capability discovery, shared profile import and on-demand outbound probes alongside routing-policy replacement/snapshots, typed SOCKS TCP/UDP, HTTP TCP, and TUN TCP/UDP connection inventory, addressable close, cumulative per-outbound accounting, and equivalent typed TUN diagnostic queues | Policy updates affect new flows only; inventory is live and accounting is process-lifetime cumulative; no persistent connection history |

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
cargo test --workspace --exclude xray-rust-fuzz --all-targets --locked
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
        exact: "0.5.0"
    ),
]
```

The package provides the low-level `XrayMobileAdapter`, shared profile and
storage APIs in `XrayAppleShared`, and the ready-to-subclass
`XrayAppleTunnel` packet-tunnel provider. Android applications can consume
`io.github.aimalygin:xray-rust-mobile:0.5.0` from Maven Central without GitHub
credentials, or download the standalone AAR from the matching release. See the
[`xray-rust-mobile` integration guide](https://github.com/aimalygin/xray-rust-mobile#readme)
for setup details.

## Documentation

- [Development roadmap](docs/roadmap.md)
- [Status and supported features](docs/status.md)
- [Architecture](docs/architecture.md)
- [Configuration compatibility](docs/config-compatibility.md)
- [Xray-core differences and verification gaps](docs/xray-core-differences.md)
- [Configuration contract and CLI tooling](docs/config-tooling.md)
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

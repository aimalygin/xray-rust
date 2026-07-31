# xray-rust

`xray-rust` is an experimental, client-side Rust implementation of a focused
subset of the Xray configuration and proxy protocols. It provides a native
runtime, a C ABI, and reference adapters for Apple platforms and Android.

This project is unofficial and is not affiliated with XTLS or Xray-core. It is
not a drop-in replacement for Xray-core, has not been independently security
audited, and should not yet be treated as a production-ready VPN SDK.

## Current scope

| Area | Implemented | Important limits |
| --- | --- | --- |
| Local inbounds | SOCKS5 no-auth `CONNECT` and `UDP ASSOCIATE`, HTTP `CONNECT`, TUN | No authenticated proxy inbound or server-side Xray protocols |
| Outbounds | Freedom/direct and VLESS client over TCP | No VMess, Trojan, Shadowsocks, WireGuard, balancers, or outbound chaining |
| Security and flow | TLS, REALITY, `xtls-rprx-vision`, VLESS UDP and XUDP paths | Only the documented config subset and supported REALITY fingerprints |
| Routing and DNS | Field rules, domain/IP matchers, `geosite`/`geoip`, hosts, UDP DNS, fake-IP subset | Not full Xray DNS or routing parity |
| Mobile | Swift Package/Xcode sample for iOS, tvOS, and macOS; Android library and `VpnService` adapter | Signing, entitlements, VPN consent, foreground policy, and release packaging remain host-app responsibilities |

See [project status](docs/status.md) and
[configuration compatibility](docs/config-compatibility.md) for the detailed
matrix.

## Benchmarks

Synthetic localhost comparison of `xray-rust`, Xray-core, and sing-box using
the process-level [benchmark harness](docs/benchmarks.md). Each engine runs as
a child process with an equivalent generated config while the harness samples
OS RSS/CPU counters and validates every payload byte. Bars are medians across
5 runs; whiskers span min to p95 (for latency, the whisker top is the median
run p95). Measured 2026-07-31 on Apple M3 Pro, 18 GB RAM, macOS 26.5.2 with
release builds: xray-rust `3f70759`, Xray-core `v26.5.9`, sing-box
`v1.13.15`. The routing memory chart loads real, pinned V2Fly geodata
(`geosite 20260727084448`, `geoip 202607171233`); sing-box is absent
from that chart because it does not read Xray-format `.dat` rule data.
In this run xray-rust holds the resident-memory edge at every scale: at idle
and 100 held flows by a wide margin, and at 1000 flows it now stays lowest
too — 17.9 MiB against Xray-core's 80.1 and sing-box's 46.8. Earlier
publications showed sing-box pulling level at 1000 flows; that slope was
dominated by two eagerly allocated 16 KiB relay copy buffers per flow, and
`3f70759` starts them at 4 KiB instead (they still grow to 128 KiB under
load), cutting the ×1000 peak from 41.4 MiB without moving any throughput or
latency series. With real geodata loaded xray-rust uses about 4× less memory
than Xray-core. Round-trip latency is comparable to both Go engines on the
TCP echo path (38.0 vs 35.0/32.0 µs), clearly the fastest on the plain SOCKS
UDP relay (38.0 vs 61.0/46.0 µs), and in front on the REALITY + Vision XUDP
path (85.0 vs 101/87.0 µs). On plain bulk throughput through SOCKS xray-rust
and sing-box are effectively tied — 58.8 vs 59.2 Gbps with overlapping run
ranges — both ahead of Xray-core's 50.3; bulk medians on this workload swing
with machine state between publications, but the relative order has been
stable. CPU per GiB on that workload puts xray-rust between the two (185 vs
Xray-core's 239 and sing-box's 153 ms). Through a full VLESS + REALITY +
Vision tunnel xray-rust leads on both axes: 13.0 Gbps against Xray-core's
12.4 and sing-box's 12.5, at the lowest CPU cost per GiB (840 vs 890/880 ms).
Earlier publications had xray-rust clearly slowest here (8.36 Gbps at about
1270 ms per GiB); the gap was work per byte on the tunnel's read path —
socket reads forced to TLS record boundaries plus per-read buffer zeroing
and copying — removed in `05c33ac`. Throughput is measured over the transfer window only
(first byte to last validated byte) on an 8 GiB stream (1 GiB for the tunnel
chart): a gigabyte crosses loopback in roughly 150 milliseconds,
short enough that TCP window growth and CPU frequency scaling weighed on the
result, and per-engine setup cost was otherwise amortized into the rate.
Excluding setup helps Xray-core rather than us: the harness
fixture is identical for all three engines, but Xray-core answers SOCKS
eagerly and finishes its REALITY handshake lazily, spending about 640 ms
before its first byte against roughly 90–120 ms for the other two. On the
REALITY chart the Xray-core server fixture terminating the tunnel is not
sampled, but it shares loopback CPU with the measured client.
These are microbenchmarks of local proxy paths, not wide-area VPN performance;
TUN workloads (xray-rust vs Xray-core only) are not charted here.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/memory-rss-dark.svg">
  <img alt="Peak resident set size, lower is better. Idle: xray-rust 3.56 MiB, Xray-core 27.8, sing-box 21.0. 100 idle flows: xray-rust 5.20, Xray-core 35.2, sing-box 27.2. 1000 idle flows: xray-rust 17.9, Xray-core 80.1, sing-box 46.8." src="docs/benchmarks/media/memory-rss-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/latency-dark.svg">
  <img alt="Round-trip latency medians, lower is better. tcp-freedom: xray-rust 38.0 µs, Xray-core 35.0, sing-box 32.0. udp-freedom: xray-rust 38.0 µs, Xray-core 61.0, sing-box 46.0. reality-vision-xudp: xray-rust 85.0 µs, Xray-core 101, sing-box 87.0." src="docs/benchmarks/media/latency-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/throughput-dark.svg">
  <img alt="Bulk TCP throughput through SOCKS, higher is better: xray-rust 58.8 Gbps, Xray-core 50.3, sing-box 59.2." src="docs/benchmarks/media/throughput-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/reality-throughput-dark.svg">
  <img alt="Bulk TCP throughput through a VLESS + REALITY + Vision tunnel, higher is better: xray-rust 13.0 Gbps, Xray-core 12.4, sing-box 12.5." src="docs/benchmarks/media/reality-throughput-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/cpu-per-gib-dark.svg">
  <img alt="CPU cost per GiB transferred on the plain bulk workload, lower is better: xray-rust 185 ms, Xray-core 239, sing-box 153." src="docs/benchmarks/media/cpu-per-gib-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/geo-memory-dark.svg">
  <img alt="Peak memory with real geodata loaded, lower is better: xray-rust 8.39 MiB, Xray-core 34.7 MiB." src="docs/benchmarks/media/geo-memory-light.svg">
</picture>

Reproduce with the release-build compare series and render charts with
`xray-bench chart`; the exact command chain and methodology are in
[Publishing Numbers and Charts](docs/benchmarks.md#publishing-numbers-and-charts).

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
Choose the `XrayClient`, `XrayClientTv`, or `XrayClientMac` scheme and configure
your own signing team. The geodata download is needed by the checked-in Xcode
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

## Distribution model

The repository is currently source-only. It does not publish crates, a Maven
artifact, or a downloadable Swift binary target. In particular,
`platform/apple/Package.swift` references a locally built XCFramework, so adding
this repository as a remote Swift Package is not sufficient by itself. Build
the native artifact first.

## Documentation

- [Status and supported features](docs/status.md)
- [Architecture](docs/architecture.md)
- [Configuration compatibility](docs/config-compatibility.md)
- [C ABI lifecycle and ownership](docs/ffi.md)
- [Verification](docs/verification.md)
- [Mobile testing](docs/mobile-testing.md)
- [Benchmarks](docs/benchmarks.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## License

The project source is licensed under the
[Mozilla Public License 2.0](LICENSE). Downloaded geodata and other third-party
components remain under their respective licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

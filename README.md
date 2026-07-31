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
run p95). Measured 2026-07-30 on Apple M3 Pro, 18 GB RAM, macOS 26.5.2 with
release builds: xray-rust `9e8743b`, Xray-core `v26.5.9`, sing-box
`v1.13.15`. The routing memory chart loads real, pinned V2Fly geodata
(`geosite 20260727084448`, `geoip 202607171233`); sing-box is absent
from that chart because it does not read Xray-format `.dat` rule data.
In this run xray-rust holds a large edge in resident memory at idle and at
100 held flows, falls to roughly half of Xray-core at 1000 flows while
sing-box pulls level, and uses about 4× less memory than Xray-core with real
geodata loaded. Round-trip latency is comparable to both Go engines on the TCP
echo path (38.0 vs 35.0/35.0 µs) and clearly the fastest on the plain SOCKS
UDP relay (36.0 vs 60.0/45.0 µs), while the REALITY + Vision XUDP path lands
mid-pack (89.0 vs 100/87.0 µs). On plain bulk throughput through SOCKS
sing-box leads clearly and xray-rust comes second, ahead of Xray-core: 74.5 vs
58.7 (Xray-core) and 84.1 (sing-box) Gbps. That is a real separation rather
than a tie — across five runs each the ranges do not overlap at all (xray-rust
72.6–75.1, Xray-core 56.4–59.2, sing-box 83.9–84.6 Gbps) — while CPU per GiB
on that workload puts xray-rust between the two (157 vs Xray-core's 212 and
sing-box's 140 ms). Through a full VLESS + REALITY + Vision tunnel xray-rust is
clearly the slowest: 8.36 Gbps against Xray-core's 13.2 and sing-box's 12.4.
The cost shows up in raw CPU, about 1270 ms per GiB against roughly 840
(Xray-core) and 890 (sing-box), and all three sit at roughly 1.2–1.3 cores of
CPU time over the transfer window, so the gap is work per byte in the
REALITY/Vision data path rather than a scheduling artifact. Throughput is now
measured over the transfer window only (first byte to last validated byte) on
an 8 GiB stream: a gigabyte crosses loopback in roughly 150 milliseconds,
short enough that TCP window growth and CPU frequency scaling weighed on the
result, and per-engine setup cost was otherwise amortized into the rate. These
throughput numbers are therefore not comparable with the ones this README
carried before. Excluding setup helps Xray-core rather than us: the harness
fixture is identical for all three engines, but Xray-core answers SOCKS
eagerly and finishes its REALITY handshake lazily, spending about 640 ms
before its first byte against roughly 90–120 ms for the other two. On the
REALITY chart the Xray-core server fixture terminating the tunnel is not
sampled, but it shares loopback CPU with the measured client.
These are microbenchmarks of local proxy paths, not wide-area VPN performance;
TUN workloads (xray-rust vs Xray-core only) are not charted here.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/memory-rss-dark.svg">
  <img alt="Peak resident set size, lower is better. Idle: xray-rust 3.61 MiB, Xray-core 28.0, sing-box 20.9. 100 idle flows: xray-rust 7.52, Xray-core 35.3, sing-box 27.0. 1000 idle flows: xray-rust 41.4, Xray-core 79.5, sing-box 44.4." src="docs/benchmarks/media/memory-rss-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/latency-dark.svg">
  <img alt="Round-trip latency medians, lower is better. tcp-freedom: xray-rust 38.0 µs, Xray-core 35.0, sing-box 35.0. udp-freedom: xray-rust 36.0 µs, Xray-core 60.0, sing-box 45.0. reality-vision-xudp: xray-rust 89.0 µs, Xray-core 100, sing-box 87.0." src="docs/benchmarks/media/latency-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/throughput-dark.svg">
  <img alt="Bulk TCP throughput through SOCKS, higher is better: xray-rust 74.5 Gbps, Xray-core 58.7, sing-box 84.1." src="docs/benchmarks/media/throughput-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/reality-throughput-dark.svg">
  <img alt="Bulk TCP throughput through a VLESS + REALITY + Vision tunnel, higher is better: xray-rust 8.36 Gbps, Xray-core 13.2, sing-box 12.4." src="docs/benchmarks/media/reality-throughput-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/cpu-per-gib-dark.svg">
  <img alt="CPU cost per GiB transferred on the plain bulk workload, lower is better: xray-rust 157 ms, Xray-core 212, sing-box 140." src="docs/benchmarks/media/cpu-per-gib-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/geo-memory-dark.svg">
  <img alt="Peak memory with real geodata loaded, lower is better: xray-rust 8.47 MiB, Xray-core 35.0 MiB." src="docs/benchmarks/media/geo-memory-light.svg">
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

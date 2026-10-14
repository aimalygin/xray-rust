# Android UDP timeout localization (#56), 2026-10-13

The reproduced timeout is a **macOS reference-fixture UDP port collision**. It occurs with the unchanged Android release-candidate APKs through USB TCP forwarding, without a Wi-Fi data path. The fix binds the fixture's Freedom outbound to `127.0.0.1`, matching its IPv4-only backend. No Rust runtime, JNI, Android adapter, SDK pin or wire-protocol source changes.

## Packet-level evidence

The unmodified pinned Xray reference opens its default UDP socket with Go `ListenPacket("udp", "0.0.0.0:0")`; on this host that produces a dual-stack `[::]:<ephemeral>` socket. Automatic allocation can select a port already held by an IPv4-specific listener. The backend receives the request from `127.0.0.1:<ephemeral>`, then the IPv4 reply is delivered to that listener instead of Xray's dual-stack socket.

1. Original APKs over USB: HTTP **1,920/1,920**, UDP **3,838/3,840**. The two failed outbound ports overlapped the fixture DNS listener and adb's loopback listener. No UDP backend send error was recorded. A second socket-instrumented reference run retained every failure and confirmed missing socket reads before VMess decoding on the client.
2. Controlled challenge, unmodified reference binary, 64 owned IPv4 listener sockets: HTTP **960/960**, UDP **1,907/1,920**. **All 13 timeouts were localized by nonce**: 12 replies arrived at a competing test listener; one returned to the backend itself because its port was selected as the source port. [Complete correlation](challenge-correlation.json), [Android results](usb-collision-challenge.json).
3. A standalone socket reproduction selected an overlapping dual-stack ephemeral port and delivered the response to the competing IPv4 listener. Explicit IPv4 source allocation had no overlap in 100,000 allocations. This experiment uses neither Android nor a proxy. [Result](ephemeral-collision.json), [bounded reproducer](reproduce-udp-port-alias.py).

The earlier attempt to bind an **explicit** colliding port correctly returned `EADDRINUSE`; it is preserved as a [non-reproduction](explicit-bind-nonreproduction.json). The faulty behavior concerns **automatic ephemeral allocation**, not permission to bind an explicitly occupied port.

One final check of the published standalone reproducer also captured the reply at the unrelated IPv4 socket (collision after 12,945 allocations); its IPv4 control had no collision in 100,000 allocations. [Published-source check](published-reproducer-validation.json).

## Validation

The unchanged Rust APKs completed **16,320/16,320 UDP requests** after the fixture fix: 7,680 over USB, 7,680 over Wi-Fi, and 960 to synthetic IPv6 targets over Wi-Fi. Both FileDescriptor and PacketPump passed with zero TUN drops, fatal errors or ordinary-probe failures. The 5-second deadlines and 32-worker workload were unchanged.

| Series | HTTP | UDP | Result |
| --- | ---: | ---: | --- |
| Original fixture, Rust/USB | 1,920/1,920 | 3,838/3,840 | Two retained response-side failures |
| Instrumented reference, Rust/USB | 1,920/1,920 | 3,831/3,840 | Exploratory socket tracing; listeners added late |
| Original fixture + 64 competing listeners, Rust/USB | 960/960 | 1,907/1,920 | All 13 missing responses captured at the wrong socket |
| Fixed fixture + 64 competing listeners, Rust/USB | 3,832/3,840 | 7,680/7,680 | Eight retained HTTP timeouts before reference dispatch |
| Fixed fixture + 64 competing listeners, Rust/Wi-Fi | 3,840/3,840 | 7,680/7,680 | All passed |
| Fixed fixture, synthetic IPv6, Rust/Wi-Fi | 480/480 | 960/960 | Both TUN adapters passed |

The named competing listeners belong to that fixture; other owned fixtures and host sockets also existed. These are bounded diagnostic trials, not estimates of a universal failure probability. [Totals](summary.json), [USB](usb-fixed.json), [Wi-Fi](wifi-fixed.json), [IPv6](wifi-fixed-ipv6.json).

### Additional controls: separate failure mechanisms

The eight HTTP failures above were **not erased**. Only 232 of that burst's 240 TCP requests reached reference dispatch, before the changed source binding could run. A plain TCP control on the same Android device, with no Rust, VPN, SOCKS or Xray, reproduced **15/4,096 connect timeouts to the adb reverse listener**; all 15 had no request nonce at the backend. The equivalent direct Wi-Fi control passed **4,096/4,096**. This localizes an additional failure to establishment of the USB-forwarded connection, not the fixture's UDP response path. It does not establish adb's internal root cause. [Plain TCP results](direct-transport.json).

The independent pinned Android Go/Xray control initially retained **HTTP 477/480, UDP 958/960 over USB**, and **HTTP 480/480, UDP 959/960 over Wi-Fi**. Its missing UDP nonces did not reach the backend. These failures differ from #56's backend-received/missing-response signature. [USB control](android-independent-fixed.json), [Wi-Fi control](android-independent-wifi.json).

A fixed four-round diagnostic follow-up used the unchanged Android reference binary with relay-port logging in the probe. It passed HTTP 960/960 and UDP 1,919/1,920. The failed nonce `73555c8ca1833bdb` shared **UDP relay port 54572 with another still-active SOCKS association**. Both allocations and their overlapping client lifetimes are retained in [the collision trace](socks-port-collision.json); only the other association's nonce reached the backend. The pinned SOCKS implementation creates per-association listeners through `ListenSystemPacket`, which enables `SO_REUSEPORT`. Its receive filter pins each association to one source port. A separate Android allocation control reproduced **16 overlapping allocations in 10,000 with SO_REUSEPORT**, and **0/10,000 without it**, while holding 32 listeners. These observations isolate the independent control's colliding SOCKS ingress; they are not a Rust or VMess compatibility failure. [Allocation control](android-reuseport-allocation.json), [all diagnostic exchanges](android-socks-observe.json). Upstream Xray source was not modified.

All Android bursts retain 240 HTTP requests, 480 nonce-validated UDP requests, 32 workers and a 5-second UDP receive deadline. Explicit connection closure and 20-second recovery separate bursts. The regular 60-second availability probes are recorded separately. Diagnostic listener counts and exploratory conditions are described below.

The same native library and APK hashes are verified against the 0.8 release acceptance manifest in [baseline-apks.json](baseline-apks.json). Core runtime: `fcce4be2771c1fb3f11e9503741d39a4d8df314e`; measured SDK: `12fdfa14136e57024d46ace66c84bdbf3dc1d7c7`. The repository's runtime and platform sources still match `v0.8.0`. The public SDK binaries do not need replacement for this fixture-only fix.

Reference source remains `5ca6f4b7d4dc20a881d4330e498892697627ec0c` (Xray-core 26.7.28). The unchanged macOS reference was rebuilt with Go 1.26.0. A separate diagnostic wrapper used Go 1.26.5 and the unchanged source through `UseAlternativeSystemDialer`, recording socket read/write boundaries. That wrapper is diagnostic evidence, not a canonical performance sample.

The Android reference uses Go 1.26.5 and NDK 26.3.11579264, targeting `android/arm64` with `CGO_ENABLED=1` and `aarch64-linux-android24-clang`, following the upstream build flags (`-trimpath -buildvcs=false -gcflags=all=-l=4`, linker flags `-X github.com/xtls/xray-core/core.build=5ca6f4b -s -w -buildid= -checklinkname=0`). Its digest is recorded in each independent-control plan. [Control sources and reproduction instructions](controls/README.md) include the socket observer, Android SOCKS probe, reuse-port allocation probe and plain TCP probe.

At completion the test host reported `stopped`, its fatal TUN counter was zero, and the probe reported `running=false`. All owned fixture processes were stopped and `adb reverse --list` was empty. APKs were not reinstalled or replaced.

Local validation passed 33 protocol/fixture Python tests, 13 public-fixture safety tests and 24 Gitleaks allowlist tests. The fixture regression covers both generator branches, preserved synthetic IPv6 routing and absence of server source binding in client configurations. Gitleaks 8.30.1 scanned the published report successfully; executable/library digests that resemble tokens have exact rule/path/value exceptions, with negative controls ensuring other values, paths and credentials are still detected.

## Scope and retained limitations

- The socket-instrumented exploratory run overlaps creation of the 64 diagnostic listeners late in the series. Its rate is not compared statistically with other series. The subsequent four-burst challenge begins with all 64 listeners already present and uses the unmodified reference executable. Failed attempts and the additional listener captures remain in [observed-correlation.json](observed-correlation.json).
- The fixed-fixture controller initially failed before any device traffic because the new fixture had not started. The error generated no measurements; the empty attempt is retained privately. A standalone Go control-probe build initially inherited an unrelated ancestor module and failed vendoring validation; it was rebuilt with module mode disabled because it imports only the standard library. The independent controls retain their separate TCP/UDP ingress failures described above.
- Whole-host UDP counters include unrelated traffic. They are not attributed to this issue. No other application was stopped, and no privileged packet capture, route, firewall, global sysctl or Wi-Fi change was needed.
- This is a reliability and interoperability investigation, not a calibrated 5% throughput benchmark. The fix changes only test-server source binding; production Rust/JNI/SDK bytes are unchanged. Historical performance and iPhone Hysteria limitations are not reclassified by this report.
- The original October 12 failures remain historical failed measurements. Their private packet records are unavailable in this checkout; this report localizes fresh reproductions of the same symptom rather than claiming retrospective per-packet proof for those runs.

[Private input digests](private-input-digests.json) bind the original local plans, controller events and filtered app logs. Published summaries include every completed burst, timeout and TUN sample. Credentials, configurations, APKs, device serial and LAN address are excluded.

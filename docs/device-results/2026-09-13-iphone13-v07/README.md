# iPhone 13: bounded v0.7 protocol checks

On 2026-09-13, a physical iPhone 13 (`iPhone14,5`, iOS 18.6.2 / 22G100)
passed two final runs of the Hysteria 2 and WireGuard client checks. The first
ran at 15:47:33–15:47:58 UTC; the second used the saved fixture generator and
fresh credentials. Exact times, source/binary hashes and per-run summaries are
in [manifest.json](manifest.json). Device file contents were compared with the
console events before saving [final-events.jsonl](final-events.jsonl) and
[repro-events.jsonl](repro-events.jsonl).

These are short development checks, not v0.7 release acceptance. The package
version remains 0.6.1; the checked development branch uses ABI 1.5. The app and
extension were signed Debug builds with a release Rust iOS-arm64 library,
Xcode 27.0 / 27A266a, and deployment target iOS 15.0. The source tree was dirty;
the manifest identifies the base commit and changed compiled sources.

## Results

Each run performs the following **per protocol**:

- Import a WireGuard file or Hysteria 2 URI through Swift → FFI → Rust.
- Three VPN start/stop cycles with distinct runtime identifiers.
- In each cycle, exchange exact TCP payloads of 65,536 bytes with an IPv4
  literal, an IPv6 literal and `v07-probe.test`; exchange UDP payloads of 1,392
  bytes over IPv4 and 1,372 over IPv6; query the tunnel DNS anchor.
- Close active connections through the provider, wait two seconds, assert zero
  active TCP/UDP flows, then repeat all traffic in the same tunnel.
- Sample resources after initial traffic, connection closure and recovery;
  require a nonzero physical footprint below 45 MiB and no TUN read/write loop
  exits. Stop the VPN and wait for disconnected status.

Both runs passed all 36 TCP echoes, 24 UDP echoes, 12 explicit DNS queries and
six recoveries after connection closure. There were no reported dropped packets
or TUN loop exits in the 18 samples per run.

| Sampled maximum across both final runs | WireGuard | Hysteria 2 |
| --- | ---: | ---: |
| Extension resident memory | 20.41 MiB | 21.55 MiB |
| Extension physical footprint | 4.19 MiB | 4.09 MiB |

These maxima are sparse extension samples, not continuous peaks, an Instruments
capture, or a memory-pressure/throughput benchmark. Start timing in the JSON
measures the provider reaching connected status; it does not measure a complete
protocol handshake. Each runtime returned to zero active flows after closure,
and subsequent traffic succeeded.

## Device findings and fixes

1. The first iOS Rust build failed because GotaTun compiled an unused batch-send
   helper under `-D warnings`. Restricting that helper to its Linux/Android/Windows
   callers fixes the iOS build. The third vendor patch reproduces this change;
   archive/patch/vendor verification passed. Cryptographic and socket behavior
   are unchanged.
2. With the Apple tunnel interface configured as IPv6 `/128`, WireGuard passed
   IPv4 TCP but IPv6 `NWConnection` entered `waiting` with POSIX 50 (`ENETDOWN`)
   and hit the ten-second timeout. The reference received no IPv6 TCP request.
   Changing only the virtual interface prefix to `/120` made IPv6 work, first
   in a diagnostic run and then in both final runs. This matches the existing
   workaround in [WireGuardKit's settings generator](https://git.zx2c4.com/wireguard-apple/tree/Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift).
   The default IPv6 route remains `::/0`; carrier exclusions and WireGuard inner
   addresses remain `/128`. All 133 provider and 14 DNS preflight Swift tests
   passed against the locally built macOS library.

An earlier fixture also incorrectly included an unsupported client `blackhole`
outbound; removing it corrected the test configuration. That failure is not
included in the passing runs.

## Fixture and reproduction

The iPhone uses Wi-Fi to reach a Mac LAN IPv4 address. Both inbound servers run
in a freshly built, unchanged Xray-core v26.7.28 binary at commit
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, with a matching clean Go VCS stamp.
WireGuard uses fresh keys and a PSK; Hysteria uses fresh authentication and a
pinned, one-day self-signed certificate. The reference maps documentation
destination ranges to local TCP/UDP echo and DNS services. Other destinations
are blocked. No host TUN, route changes or public test endpoints are needed.

The [fixture generator](../../../scripts/run-v07-apple-protocol-fixture.py)
creates a new private directory, accepts an explicit Mac bind address, and
removes its generated credentials on termination. It limits lifetime to ten
minutes by default. Keep the foreground process running during the device test:

```sh
GOTOOLCHAIN=go1.26.5 GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C Xray-core build -mod=readonly -trimpath \
  -o "$PWD/target/mobile/v07-reference" ./main
python3 scripts/run-v07-apple-protocol-fixture.py \
  --bind "$MAC_LAN_IPV4" --reference-binary target/mobile/v07-reference \
  --output target/mobile/v07-fixture
```

Build the local iOS-arm64 XCFramework and signed Debug `XrayClient` app from
the current source. Install it with `devicectl`, then use the app's explicit
DEBUG entry point (substitute the connected device and app bundle identifiers):

```sh
xcrun devicectl device copy to --device "$DEVICE_ID" \
  --source target/mobile/v07-fixture/v07-probe.json \
  --destination Documents/v07-probe.json --domain-type appDataContainer \
  --domain-identifier "$APP_BUNDLE_ID"
xcrun devicectl device process launch --device "$DEVICE_ID" \
  --terminate-existing --environment-variables '{"XRAY_V07_DEVICE_PROBE":"1"}' \
  --console "$APP_BUNDLE_ID"
```

After the `complete` event, copy `Documents/v07-result.json` back with
`devicectl device copy from`. The probe removes its input file and its separate
VPN manager/keychain configuration on completion. Relaunch the app without the
environment variable to return to its regular UI. Stop the fixture process.
The completed session preserved the pre-existing VPN manager and profile store.

The importer smoke check and runtime configuration check are distinct: the
runtime JSON supplies the fixture's random DNS port and certificate pin. This
does not claim that an unmodified imported share link can connect to this
private fixture, or that the application's profile-import UI was tested.

## Remaining coverage

Wi-Fi/cellular transitions, carrier IPv6, NAT64, sleep/wake, background activity,
loss/PMTU faults, high concurrency, energy and memory pressure remain untested
here. No Android device was used. Device traffic used the pinned Xray reference;
the independent native-server host gates are separate evidence. No RC, release
artifact, full Apple target matrix or remote CI result is claimed.

# v0.7 direct official WireGuard interoperability

The reference runs unmodified official
[wireguard-go 0.0.20250522](https://git.zx2c4.com/wireguard-go/tag/?h=0.0.20250522),
commit [`f333402bd9cbe0f3eeb02507bd14e23d7d639280`](https://git.zx2c4.com/wireguard-go/commit/?id=f333402bd9cbe0f3eeb02507bd14e23d7d639280),
through a [test-only Go executable](../tools/wireguard-reference/main.go).
It supplements the existing Xray-core v26.7.28 gate. Production Rust dependencies,
the patched GotaTun client engine and accepted configuration subset are unchanged.

The executable imports the official device directly, without Xray or its
configuration/outbound layers. It supplies an in-memory IP interface, loopback UDP
binding and a gVisor TCP/UDP forwarder. Authentication, encryption, handshake,
replay protection and peer source checks remain in the upstream engine. The
pinned Xray server uses the same wireguard-go revision: these runs independently
exercise integration and standard wire behavior, but do not provide diversity
between two server cryptographic implementations or constitute a crypto audit.

## Reproduction and provenance

```sh
python3 scripts/tests/verify-wireguard-reference.test.py
bash scripts/check-native-wireguard-interop.sh
# Existing baseline remains required:
bash scripts/check-wireguard-runtime.sh
```

The dedicated module pins `golang.zx2c4.com/wireguard` to
`v0.0.0-20250521234502-f333402bd9cb` and `gvisor.dev/gvisor` to
`v0.0.0-20260122175437-89a5d21be8f0`. The
[identity guard](../scripts/verify-wireguard-reference.py) checks both exact
versions, module sums and go.mod sums. It rejects module replacements, missing or
duplicate pins and any Xray dependency. Eight negative/positive guard tests cover
these checks and Go's module JSON stream.

The runner fixes Go 1.26.5, disables workspace/environment build overrides, clears
build flags and uses `-mod=readonly`. It builds the fixture, verifies the module
cache with `go mod verify`, rechecks identities and runs the fixture tests before
the live Rust suites. The mandatory `go-oracles` CI job runs this gate after the
existing engine/Xray gate. Each script clears the other reference selector;
ambiguous direct selections fail.

Only loopback UDP endpoints and loopback TCP/UDP applications are opened. The
forwarder accepts documentation destinations in `192.0.2.0/24`,
`198.51.100.0/24`, `203.0.113.0/24` and `2001:db8::/32`, redirecting them to
`127.0.0.1` at the test port. No host TUN, routes or privileged interface changes
are needed. Test keys are synthetic. IP queues hold eight packets, MTU is 1420
and the forwarder permits at most 32 concurrent TCP/UDP flows. These are fixture
bounds, not measurements of the production client's memory use.

For source-isolation tests, a local Unix datagram bridge replaces the forwarder.
The test injects an inner IP reply into the official peer, which encrypts it under
its own key. This tests the Rust client's authenticated source checks without
using its GotaTun implementation on both sides. The raw bridge runs on Unix
hosts, including the Linux CI runner and macOS local environment.

## Live coverage

Twelve scenarios run against the direct reference:

- TCP echo with a 256 KiB transfer and half-close, and UDP in both inner address
  families, with and without PSK. Maximum nonfragmented payloads are 1392 bytes
  for IPv4 and 1372 for IPv6 at MTU 1420; one extra byte is rejected by the client.
- Missing/wrong PSK, wrong client private key and wrong server public key produce
  no application delivery. Each failed client releases its flow slots; a fresh
  correct-key client succeeds without replaying failed-device pending payloads.
- Three peers with different PSKs, overlapping and identical normalized prefixes,
  mixed outer IPv4/IPv6 and distinct application replies verify peer selection.
- Every ordered pair of three peers, in both inner families, attempts a reply
  with the victim's exact flow tuple and valid checksum under the wrong peer key.
  Forged delivery is rejected and legitimate replies still work.
- Flooding an unavailable more-specific peer does not send its traffic through
  a healthy broader peer. The healthy flow progresses; the shared 16-slot UDP
  budget and shutdown reclamation hold.
- Core SOCKS/HTTP/UDP sharing and accounting, optional PSK, protected sockets,
  concurrent opens, mixed-peer bootstrap, host flow close and fresh core startup.
- Userspace TUN TCP/UDP, routed wire DNS and managed destination resolution.

The same ten adapter/core scenarios also run against Xray. The two raw isolation
scenarios keep their existing in-process GotaTun peers in that baseline and use
official wireguard-go processes in the new gate.

## Acceptance boundary

Observed on macOS arm64, 2026-09-11: all twelve direct-reference scenarios,
eight provenance guard tests and three Go fixture tests passed. The existing
baseline also passed: 89 engine tests, the bounded IP pressure probe, eight
client/lifecycle/isolation tests and ten Xray adapter/core scenarios. Go vet,
strict Clippy for WireGuard/core test targets, Rust formatting, shell syntax and
the scheduled/prerelease workflow guards passed. The CI workflow includes the
gate; remote Linux CI and physical devices have not been exercised by this local
run.

Fresh client/core startup covers one recovery path. Authenticated endpoint roaming,
explicit replay injection, timed keepalive/rekey, broader fragmentation/path-MTU
cases, server-crash recovery, mobile suspend/resume and measured resource recovery
remain release work. Existing engine tests provide additional coverage but do not
replace independent live or physical-device acceptance for those cases. Application
integration and matching mobile artifacts remain separate release steps.

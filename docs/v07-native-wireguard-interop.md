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

Sixteen scenarios run against the direct reference:

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
- Authenticated server UDP-port changes in both outer address families, with
  IPv4 and IPv6 inner flows. Replayed ciphertext and a corrupted authentication
  tag neither deliver application data nor change the selected endpoint. A
  withheld authentic packet is still accepted out of order after the bad-tag
  attempt; fresh authenticated packets move the endpoint and move it back.
- Server process termination and restart on the same address, with the same
  static keys/PSK but no retained sessions. Both existing inner UDP flows recover
  through a fresh handshake without restarting the Rust client or replacing its
  protected socket. Application probes retry every 500 ms, with a 40-second
  recovery deadline per outer family; UDP delivery during the outage is not
  guaranteed.
- One-second persistent keepalive while the application is idle, then live
  traffic across the unchanged 120-second client rekey timer. A fresh handshake
  and receiver index are required, an accepted old-session ciphertext cannot be
  delivered twice, and the original flow and protected socket remain usable.

The four lifecycle tests use a loopback UDP relay that forwards encrypted bytes
between the production client and official server. It retains at most one
pending datagram and one captured reply, plus fixed receive buffers; it does not
decrypt packets or change either engine's clock, cryptography or timers. The
rekey case has a 150-second wall-clock deadline and adds about two minutes to
the direct-reference gate. The Xray gate explicitly selects its existing test
targets so the native-only lifecycle cases cannot run with the wrong reference.

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

Observed on macOS arm64, 2026-09-13: the full direct-reference gate passed all
sixteen scenarios, including all four new lifecycle tests. Existing UDP flows
recovered after the server restart in approximately 15.5 seconds for each outer
family; the timed rekey completed in 120.4 seconds with the same client/socket.
The unchanged baseline passed 89 engine tests, the bounded IP pressure probe,
eight host client/lifecycle/isolation tests and ten Xray adapter/core scenarios.
The eight reference-provenance tests, three Go fixture tests, strict WireGuard
Clippy, formatting, shell syntax and prerelease/scheduled workflow checks passed.
These are local host results; the updated Linux CI gate and physical devices
have not been run for this increment.

The port-change tests keep the endpoint IP and address family unchanged. Client
interface changes/NAT rebinding, cross-family roaming, broader replay-window and
key-expiry boundaries, fragmentation/path-MTU cases, existing TCP behavior across
server crashes, mobile suspend/resume and measured resource recovery remain
release work. Existing engine tests provide additional coverage but do not replace
independent live or physical-device acceptance for those cases. Application
integration and matching mobile artifacts remain separate release steps.


## Carrier socket rebind increment

The gate now includes `tests/network_change.rs`. Its independent-reference case
retains an existing TCP stream and UDP session across two bursts of ten rebind
requests, checks exact TCP/UDP payloads after each burst, and verifies one new
protected socket per burst. It runs separately over IPv4 and IPv6 outer sockets;
it does not switch one peer between address families. The failure case rejects
protection of the replacement socket and requires client closure, failed flow
I/O and reclamation of the UDP budget.

Physical interface changes are checked separately in the bounded
[iPhone 17 Pro Max carrier-rebind report](device-results/2026-09-14-iphone17-wireguard-rebind/README.md).
The host cases do not emulate an actual carrier, DNS64 changes or OS interface
routing, and the phone cases open fresh application connections. Both forms of
evidence are needed; neither claims a seamless or universal handover.


### Bounded carrier drain and concurrent TCP bridge (2026-09-15)

WireGuard now replaces the protected socket set without suspending the engine
or discarding authenticated sessions and pending packets. Its receive half
accepts delayed packets through at most one retired set for three seconds;
a timer releases that set even with no further traffic. New sends use only the
current set, and received packets keep the normal authentication/replay checks.
The real-socket unit test covers an already pending receive, replies to both
ports, and idle retirement over IPv4/IPv6. The independent-reference test adds
100 ms of delay in each direction, a 450 ms outage and two spaced rebinds during
a 65,536-byte TCP transfer. It verifies exact bytes without reopening and one
handshake; both outer families completed in about 2.82 seconds after the drain
change (about 5.15 seconds with immediate socket retirement).

The shared TUN TCP bridge also keeps upload pollable alongside download, host
closure and the idle deadline. Two bounded-duplex reproductions failed before
the change: blocked upload prevented both same-flow download and host closure.
Both pass with the fix. Upload batches and their reservations stay alive across
polls; no extra worker task or unbounded queue is introduced.

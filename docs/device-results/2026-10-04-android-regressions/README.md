# Android legacy and active-flow checks — 2026-10-04

Physical Samsung SM-A145F / Android 15 API 35 / arm64, USB power and local
Wi-Fi, using the isolated `.v08` host/probe apps. Both FileDescriptor and
PacketPump are exercised. Android Wi-Fi/cellular and lock/wake remain
**owner-skipped / not tested** for v0.8.

This report separates ordinary availability/recovery requests from intentionally
interrupted requests. A request that times out after its UDP flow was cancelled
is an expected observation only if its uncancelled delayed-response control and
subsequent fresh traffic pass. Such timeouts do not count as successful traffic.

| Suite | Cases meeting all TCP/remote-close criteria | UDP cancellation cases |
| --- | ---: | ---: |
| legacy | 8/8 | 8/8 |
| v07 | 2/4 | 4/4 |
| v08 | 8/14 | 13/14 |

- `legacy`: VLESS/REALITY Vision; XHTTP H1 packet-up, H2 stream-up and H3
  stream-one, each on both TUN paths.
- `v07`: Hysteria2 and WireGuard, each on both paths. This suite name denotes
  legacy protocols, not a v0.7 binary: every phone trial uses the same v0.8
  native/adapter identities stated below.
- `v08`: Trojan TLS; SS2022 ChaCha, AES-128 and AES-256; VMess auto, AES and
  ChaCha, each on both paths. This is cancellation follow-up, not a repeat of
  the preceding resource/stress qualification.

Ordinary preflight/control/recovery traffic, including the retained pilot, records **255 HTTP
passes / 0 failures** and **254 nonce-checked UDP
passes / 1 failure**. Legacy preflight uses literal IPv4,
literal IPv6 and a fixture domain with routed DNS, two HTTP and two UDP replies
per target. These counts include the failed Trojan recovery, whose driver
raised before emitting a successful recovery record; supplemental teardown
controls and the four repeats are listed separately. New-protocol preflight here uses IPv4; earlier complete address
matrices remain in the [preceding report](../2026-10-04-android-v08/README.md).
Inner IPv6 crosses an IPv4 LAN carrier; this does not establish an IPv6 WAN path.
HTTP checks availability (204); UDP checks each fresh nonce and exact 83-byte
response to the 67-byte request. Neither measures bulk throughput or MTU limits.

## Cancellation controls

Each TCP case opens a real HTTP request at the synthetic backend and withholds
the response. The driver waits for `hold-open` before requesting either
`close-connections` or a complete VPN `disconnect`. The backend's EOF must occur
within three seconds of the command and before 4.5 seconds of total request
lifetime, ahead of the client's existing five-second read timeout. The server
itself allows twenty seconds. No-action controls hold selected requests open
for at least two seconds. These are application-to-backend observations,
including ADB dispatch and transport teardown, not isolated API latency.
Backend open/EOF and dispatch times use the same host clock. Supplemental
local error-delay fields compare device logcat epoch with host dispatch; those
clocks were not calibrated, so use them as diagnostic estimates, not precise
latency measurements. The exception type, local probe elapsed time, stopped
state and fresh traffic provide separate cancellation/recovery observations.

There are **38 TCP cancellations meeting the remote-EOF criterion**; observed backend
close delay ranges from **0.156 to 1.404 seconds**
(median 1.167). HTTP/UDP recovery passes after
each of these 38 operations. The probe may fail an interrupted HTTP request or retry its GET;
all backend opens/closes and probe observations are retained.

UDP controls delay the nonce-matched server response by three seconds, below
the client's five-second deadline. The same case must first pass without
cancellation. Then each close/stop is requested less than one second after
`udp-pending`. The response is still submitted by the backend, but the cancelled
receive must time out with zero successful UDP replies. For the close API the
core must accept at least one close request, remain running, and subsequently
accept zero requests on an idempotent close. Disconnect must reach the stopped
state. Fresh HTTP/UDP traffic must then work again. There are
**52 observations of interrupted UDP receives**. Fresh
recovery passes after 51 of these 52 primary operations; Trojan PacketPump
post-disconnect recovery fails once and is not counted as a complete case.

## WireGuard whole-VPN stop

WireGuard passes IPv4/IPv6/domain traffic and per-connection TCP cancellation
on both paths. Its two primary whole-VPN disconnect trials **fail the additional
three-second remote-EOF criterion**: the local HTTP operation fails with
`SocketException` immediately, but the remote backend sees its twenty-second
fixture timeout instead of an EOF. These primary case failures remain in the
matrix; they are not converted into passes by later controls.

[Paired stop controls](summary.json) separate local cancellation
and recovery from remote cleanup. For each path, repeat immediate VPN stop and
then compare explicitly closing the active connection before stopping. Retain
local error timing, stopped/zero-connection samples, fresh HTTP/UDP recovery
and the backend result for each operation in `wireguardStopControls`. All four
controls pass local stop and fresh two-HTTP/two-UDP recovery. In the four
complete paired controls, direct stop reaches the backend fixture timeout on
both paths. An earlier, incomplete PacketPump direct-stop trial delivers EOF
instead: this remote cleanup failure is intermittent. Close-before-disconnect delivers EOF within
three seconds on both paths. This is consistent with a shutdown-order race, without proving its complete
cause or that a runtime fix has been implemented. An initial supplemental
controller incorrectly required a timeout in its direct-stop control and
stopped when PacketPump delivered EOF instead. That incomplete trial is
retained in [wireguard-control-diagnosis.json](wireguard-control-diagnosis.json),
with the original controller and raw log; fresh PacketPump controls record
either outcome without changing the primary failures.

The [source comparison](wireguard-stop-diagnosis.json) is consistent with
`Core::stop`: it closes outbound sessions
before draining TUN tasks. WireGuard then stops its inner stack and UDP carrier,
which can prevent a final inner TCP close from reaching the remote peer. The
WireGuard client/stack source blobs and that shutdown ordering also exist in
v0.7.0. This is a source comparison, **not an Android v0.7 runtime comparison**
or proof about every cause. No native fix or unconditional remote-close guarantee
is claimed. Review this limitation separately from local recovery, UDP stress
losses and the earlier iPhone reliability failures.

## SS2022 peer teardown and local cancellation

All six SS2022 TCP primary cases (three ciphers, both TUN paths) fail the
additional three-second backend EOF criterion at the first close-API operation.
This ends those primary cases before their subsequent whole-VPN stop trial.
The six failures remain in the table, rather than being converted to passes.

Twelve supplemental local controls cover close API and whole-VPN stop for all
six combinations. They confirm an immediate local `SocketException`, the
appropriate running/stopped state, and fresh two-HTTP/two-UDP recovery. The
held backend request reaches its twenty-second fixture timeout in each trial.
All three pinned Xray-core **Go-client → Go-server** controls also retain the
backend request after closing SOCKS and terminating the client process; each
ends at the fixture timeout. Thus the backend-EOF symptom reproduces without
our core or Android adapter. These are host Go controls, not equivalent Android
Go performance or recovery measurements.

The pinned server forwards SS2022 through `singbridge.CopyConn`; its pipe
wrapper's `Close()` is a no-op and it uses an inactivity timer. This is a
plausible location for the retained upstream pipe, supported by the peer
controls, **not a complete implementation-level root-cause proof**. The controls
do not establish universal half-close behavior. See
[ss2022-teardown-diagnosis.json](ss2022-teardown-diagnosis.json). This finding is
separate from the owner-deferred SS2022 WAN UDP-loss investigation; that work
was not reopened and no reference-repository code was changed.

## Trojan UDP recovery

One primary Trojan PacketPump whole-VPN restart recovers HTTP but times out
waiting for the fresh UDP reply. Query tag `d309e831485adf70` appears at the backend; it submits
the matching 83-byte response after 3.001 seconds, while the phone reports a
five-second `SocketTimeoutException`. Submission does not prove delivery
through every transport layer. No packet-capture proof identifies the loss
location; neither MTU nor a specific client/server defect is established.

The first failure remains in the primary verdict. Four fresh-fixture repeats
in the order PacketPump, FileDescriptor, PacketPump, FileDescriptor produce
**4/4 complete passing cases**. Each repeats the
uncancelled three-second-delay control, close API, idempotent close, whole-VPN
stop and fresh recovery, retaining separate raw evidence. Passing repeats do
not resolve the original cause or establish a loss rate. See
[trojan-udp-diagnosis.json](trojan-udp-diagnosis.json) and the four
`trojan-repeat-*` directories.

## Failed attempts and limits

The first UDP pilot was incomplete because the controller's logcat parser
ignored leading whitespace and consequently found no lifecycle events. Its
failed event and raw log are retained with a [diagnosis](udp-pilot-diagnosis.json)
and the exact original controller. The corrected parser is followed by fresh
physical controls; the failed pilot is not relabeled as passed. Inspect
`failures` in [summary.json](summary.json) for primary unsuccessful invocations,
and the two controller diagnoses for incomplete attempts.

These bounded functional checks do not resolve the earlier SS2022 stress
losses, iPhone WireGuard/Trojan failures, or WAN/DF behavior. CPU/RSS samples in
the lifecycle log are diagnostic observations; no new performance or leak
threshold is claimed. The prior measured PacketPump CPU fix and RSS bounds are
separate evidence. The full shared scenario matrix, exact-candidate review,
calibrated host samples and schema-4 release archive remain open.

## Identity and replay

Installed host APK SHA-256 is
`0905fb36632afce4f9a1146607969dbd6511321cacd93c39372122c4c577f26c`;
probe APK SHA-256 is
`1b0139b2add639985b3829d7e8e7baf1a0bbd51d4f3efeeaf0bf6971f13d4298`.
Both were pulled from the device and matched against the preceding corrected
adapter campaign before these tests. No app, native library or SDK was rebuilt.
Rust/JNI retains native revision `de33998158e84c03f280f979ba2d4212072e5bc4`;
Kotlin retains the corrected adapter carried by development pin `0d78856`.
These are not freshly rebuilt binaries at the later documentation/policy head.

[build-identity.json](build-identity.json) records native/JNI/APK hashes,
original adapter sources, fixture source generations and measured controllers.
Xray-core remains v26.7.28, clean source revision
`5ca6f4b7d4dc20a881d4330e498892697627ec0c`, with binary SHA-256
`fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99`.
REALITY uses the existing `www.google.com:443` TLS decoy; application traffic
is restricted to synthetic destinations redirected to loopback fixtures.
No VPS or reference repository is modified.

Use [replay instructions](reproduce/README.md). Run
`python3 docs/device-results/2026-10-04-android-regressions/verify.py` from repository
root to verify artifact hashes, case coverage and the explicit cancellation
criteria. The report preserves failures; verifier success confirms integrity,
not complete release qualification. Cleanup is recorded separately; no merge,
tag, release or package publication is performed.

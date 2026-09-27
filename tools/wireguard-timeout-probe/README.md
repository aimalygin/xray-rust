# WireGuard timeout investigation

This loopback-only diagnostic compares the pinned upstream GotaTun 0.9.1,
the vendored GotaTun with mobile limits, and official wireguard-go. Raw engine
cases use the same injected IP boundary, synthetic keys, IPv4 outer endpoint,
IPv4/IPv6 inner UDP packets and official reference server. They exclude the
client's smoltcp/mobile adapter. A separate production-client matrix covers
IPv4 TCP, IPv4 UDP, IPv6 TCP, IPv6 UDP at cold start, restart and socket rebind.
This is a reliability investigation, not a throughput, latency or RSS benchmark.

Download the archive pinned in `vendor/gotatun/XRAY-PATCH.md`, then run:

```sh
python3 scripts/check-wireguard-timeouts.py \
  --archive /absolute/path/gotatun.tar.gz \
  --build-root /absolute/path/build \
  --report-dir /absolute/path/reports \
  --repeats 100 --engine-repeats 3
```

Use dedicated writable output directories: reference source subdirectories are
regenerated from the verified archive. Both stand-alone Rust probe lockfiles
are seeded from the main lockfile; registry versions/checksums must match it.
The report records reference binary hashes, archive identity and each lockfile.
The raw Go fixture's optional endpoint mode requires a loopback endpoint and
an injected packet bridge. No host tunnel, routes or privileged network changes
are involved.

Tests drop exactly one initiation, response, established upload or download
packet. Each request is sent once. The original five-second outcome is saved
separately from eventual handshake recovery; UDP data loss remains a timeout.
A different subsequent request checks that the client has not stalled.
Ordinary restart cycles explicitly wait 50 ms, outside the official peer's
20 ms handshake flood guard. A separate immediate-restart case keeps that edge
condition visible and retains the reference's diagnostic log.

## Optional production-adapter diagnostics

Build `xray-wireguard` with the `diagnostics` feature and set
`XRAY_WIREGUARD_DIAGNOSTICS_DIR` to an existing absolute directory **before**
starting any runtime. For an FFI build select both packages:

```sh
cargo build --locked --release -p xray-ffi -p xray-wireguard \
  --features xray-wireguard/diagnostics --target aarch64-linux-android
```

Each client retains at most 2048 numeric events and flushes one app-private
`wireguard-PID-ID.jsonl` file on shutdown. The header counts overwritten events.
No keys, addresses, plaintext, ciphertext or application payloads are stored.
Files use create-new semantics and mode 0600 on Unix. Diagnostic I/O failure
does not fail the transport. Abrupt process termination can lose the ring;
stop the runtime normally after a probe timeout to collect it. Files from
successive runs should be collected/removed by the test harness.

| Event | a | b | c |
|---|---|---|---|
| start | peer count | MTU | 0 |
| socket-protected | family index (0=v4, 1=v6) | local port | 0 |
| outer-sent / outer-received | WireGuard message type | bytes | local port |
| outer-send-error / outer-receive-error | OS error code | 0 | 0 |
| inner-to-engine / stack-received | IP version | packet bytes | 0 |
| inner-decrypted | IP version | packet bytes | remaining queue capacity |
| inner-queued | success (0/1) | remaining queue capacity | 0 |
| udp-open | flow ID | local inner port | IPv6 (0/1) |
| udp-enqueued / udp-delivered / udp-drop-* | flow ID | payload bytes | 0 |

Lifecycle markers include carrier publication, rebind request, stop and engine
shutdown. Ring allocation and all recording expressions are compiled out of
normal builds. Run resource/performance comparisons with this feature disabled.

These experiments do not establish the cause of a historical mobile timeout
without matching evidence from that failed mobile run. Collect the adapter
ring and simultaneous server echo/outer-packet metadata when reproducing it.

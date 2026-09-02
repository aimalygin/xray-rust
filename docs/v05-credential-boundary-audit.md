# v0.5 credential-boundary audit

Status: maintainer review completed for the `v0.5` release-candidate line.
This is a focused source and regression audit, not an independent security
assessment.

## Scope

The review follows credential-shaped data from the JSON configuration and C
ABI through the normalized configuration, outbound graph, VLESS request
encoder, REALITY handshake state, runtime diagnostics, and FFI errors. It also
checks the public redacted snapshots and the Apple/Android adapter error paths.

The reviewed invariants are:

- configuration and protocol `Debug` output must not expose VLESS UUIDs or
  REALITY short IDs;
- parser and FFI failures must describe the field or unsupported behavior
  without echoing a valid credential from the same document;
- access, route, probe, DNS, TUN, and health diagnostics expose only typed
  state, redacted targets, bounded labels, and redacted errors;
- ephemeral REALITY and QUIC Initial key material is cleared when its owning
  state is dropped, and FFI-owned error strings are cleared before release;
- snapshots never include raw configuration, user IDs, REALITY short IDs,
  keys, probe paths, or response bodies.

## Findings and changes

The review found two credential-formatting gaps. `VlessUser` and
`VlessRequest` inherited structural `Debug` implementations that printed the
UUID, and `RealityShortId` inherited one that printed its bytes. All three now
use explicit redacted formatting with regression tests. Because larger config,
router, and request structures delegate to these implementations, their debug
trees inherit the same protection.

FFI errors were already restricted to sanitized parser/runtime messages, but
their library-owned C string was simply deallocated. `xray_error_free` and
error replacement now clear that allocation first. The QUIC Initial sniffer
now clears the derived client secret immediately after key derivation and
clears packet-protection key, IV, and header-protection state on drop.

Existing REALITY ownership remains the stronger boundary: short IDs, local
X25519 private keys, shared secrets, authentication keys, patched ClientHello
buffers, session IDs, and verification snapshots have explicit drop-time
zeroization. Debug implementations expose only public metadata and lengths.

## Lifetime boundary and residual risk

The caller owns the input JSON buffer. The C ABI borrows it for the duration of
the load call and cannot clear caller memory; Apple and Android hosts must
discard or overwrite their source buffer according to their own credential
storage policy. The Rust parser necessarily creates temporary JSON strings;
general-purpose `serde_json` allocations do not promise zeroization.
Likewise, the explicit QUIC buffers are cleared, but temporary internal state
owned by the third-party HKDF/AES implementations has no documented
zeroization contract.

A parsed VLESS UUID is retained for the lifetime of the immutable outbound
graph because every new authenticated flow needs it. Vision streams retain a
16-byte copy while the stream can emit or validate Vision frames. These are
required-use lifetimes, not diagnostic copies. The public Rust model currently
uses `uuid::Uuid`, which has no zeroizing storage contract, so allocator or
crash-dump resistance for those retained values is not claimed. Hosts should
disable core dumps in production and destroy core handles promptly when a
profile is removed or replaced.

The public REALITY key is a server verification value rather than a client
secret. Certificate pins and ML-DSA verification keys are likewise treated as
public verification material, while short IDs and derived handshake values are
treated as secrets.

## Reproduction

The focused regressions are part of the ordinary workspace suite. Release
candidates additionally block on the complete-history fixture/Gitleaks scan,
AddressSanitizer, Miri, extended ASan fuzz campaigns, and the pinned interop
gate. See [verification](verification.md) for exact commands.

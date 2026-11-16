# 0.10.1 release preparation

Requested by the owner on 2026-11-16, after the review of the pull requests
open since 0.10.0. Publication is pending. The shared steps are in the
[release process](release-process.md); this page holds what is specific to
0.10.1.

The candidate is the 0.10.1 release commit: `main` through pull request
[#312](https://github.com/aimalygin/xray-rust/pull/312) plus the workspace
version, the lockfile, the generated configuration contract, the dated
changelog section and this document. Every later step binds to the commit and
tree it merges as.

## Scope

A patch release: four fixes by a new contributor, two fixes on top of them, two
dependency updates. No configuration field, C ABI function or header changes.

- **TLS and REALITY fingerprints** advertise their uTLS profile's whole cipher
  suite list ([#307](https://github.com/aimalygin/xray-rust/pull/307)). Up to
  0.10.0 the suites rustls does not implement were left off the wire, which
  gave every profile a cipher list no browser sends.
- **Hysteria** gives the connect attempt to a server's last or only address
  what is left of the dial's ten seconds, at most eight
  ([#309](https://github.com/aimalygin/xray-rust/pull/309)).
- **TUN** sniffs a TCP flow to an IP address for `destOverride`, as the SOCKS
  and HTTP inbounds and TUN's UDP flows already did
  ([#310](https://github.com/aimalygin/xray-rust/pull/310)).
- **`xray_core_free`** no longer waits for a system DNS lookup: the lookup runs
  on a thread outside the runtime
  ([#311](https://github.com/aimalygin/xray-rust/pull/311) found the hang;
  [#312](https://github.com/aimalygin/xray-rust/pull/312) replaced its bounded
  wait, so that freeing a handle still waits for the runtime's threads without
  a limit).
- **The SDK's VLESS importers** (`XrayVlessURLImporter`, `XrayVlessUrlImporter`)
  set `routeOnly` on the sniffing of the profiles they build. Those profiles
  enable sniffing to recover the domain of a fake IP the fake DNS no longer
  knows. With TUN now sniffing TCP flows to real addresses, a profile without
  `routeOnly` would have dialed such a flow by the name it sends: found while
  preparing this release, before any build of it left the repository.
- **Dependencies**: async-compression 0.4.52 and regex 1.13.0.

Behaviour that changes for users and hosts:

- With `sniffing` enabled and `http` or `tls` in `destOverride`, a TUN TCP flow
  to a real IP address is routed by the domain it sends, and dialed by it too
  unless `routeOnly` is set. An IP rule that matched such a flow no longer does
  unless the domain resolves into it. The flow is accepted before it is
  dialed, and a protocol in which the server speaks first waits the 250 ms
  sniffing window.
- A server that prefers a CBC or RSA key exchange suite over every AEAD suite
  a fingerprint offers now fails the handshake with
  `SelectedUnofferedCipherSuite`, where it completed on an AEAD suite.
- A Hysteria dial to a server with one address can take up to eight seconds
  before it fails, where it failed after three.
- System DNS lookups run on their own threads, at most 64 at once.
- A profile built by the SDK's VLESS importers dials a QUIC flow to a real IP
  address by that address, where it dialed it by the sniffed name. Its TCP
  flows to real addresses are dialed by address as in 0.10.0, and its LAN
  flows still take the private-address rule.

The C header and the SDK's adapters do not change. Of the Swift and Kotlin
sources only the two VLESS importers do, by the `routeOnly` line; the SDK
re-pin synchronizes them with the new core.

## Qualification

The gates are those of every 0.10 release: the full release CI on the
candidate, and the schema-5 `v010` evidence profile of
[v0.10 evidence collection](v010-release-evidence.md), validated by the
candidate's unchanged checker in `v010-release-evidence.yml`. The measurements
of the gate and the comparison against 0.9.0 are made again on the candidate;
the checker binds them to its commit and tree.

Which device runs are made again on this candidate and which are carried over
from the [0.10.0 campaign](device-results/2026-11-15-v0100-candidate/README.md)
is the owner's decision, as «Только затронутое» was for the fourth 0.10.0
candidate. It is recorded, with every known limitation the owner accepts, in
`docs/releases/v0.10.1-owner-decisions.json`, and the report directory under
`docs/device-results/` names the build each run was made on. Nothing here
relabels a run of another build as a run of this candidate.

What the changes of this release touch on a device:

| Change | Scenarios that exercise it |
| --- | --- |
| Cipher suite lists (#307) | every case that dials with a TLS or REALITY fingerprint, the REALITY and TLS cases of `legacy-regression` first of all |
| Hysteria connect time (#309) | the Hysteria2 case of `legacy-regression` |
| TUN TCP sniffing (#310) | every TUN TCP flow of a configuration with `sniffing` and `http` or `tls` in `destOverride`; a flow to a fake IP the fake DNS knows is unchanged |
| `routeOnly` in the importers' profiles | every profile imported through the SDK's VLESS importers: the `vless-link` case of `profile-import` |
| System DNS off the runtime (#311, #312) | none on the SDK's hosts, which set `XRAY_DNS_BOOTSTRAP_MODE_STATIC_ONLY` and never ask the system resolver |

The 0.10.0 known limitations stay as they are: this release fixes none of
them.

## Publication

Not started. In order, as in the [release process](release-process.md): full
CI on the candidate, the SDK pinned to the candidate commit, the evidence and
its publication on `main`, the annotated tag `v0.10.1` and its GitHub release,
then the SDK's Prepare release, tag and packages, the KMP library, and the
README install snippets.

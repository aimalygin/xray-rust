# 0.10.1 release preparation

Requested by the owner on 2026-11-16, after the review of the pull requests
open since 0.10.0. Publication is pending. The shared steps are in the
[release process](release-process.md); this page holds what is specific to
0.10.1.

The candidate is `main` through pull request
[#312](https://github.com/aimalygin/xray-rust/pull/312), with the workspace
version, the lockfile, the generated configuration contract, the dated
changelog section and this document, with the security fixes of
[#315](https://github.com/aimalygin/xray-rust/pull/315), and without the TUN
TCP sniffing of [#310](https://github.com/aimalygin/xray-rust/pull/310), which
was taken out again before the candidate (see
[Left for 0.11.0](#left-for-0110)). Every
later step binds to the commit and tree it merges as. An earlier release
commit, `264efdc982b3e1ac4af1f9e1960e560841a0d59e`, still carried #310 and is
not the candidate: nothing was tagged or published from it.

## Scope

A patch release: security fixes in the vendored QUIC and TLS stacks, three
fixes by a new contributor, one fix on top of them, two dependency updates.
No configuration field, C ABI function or header changes.

- **Security, QUIC**: the vendored quinn-proto moves from 0.11.16 to 0.11.19
  and quinn from 0.11.9 to 0.11.12, keeping the local patches
  ([#315](https://github.com/aimalygin/xray-rust/pull/315)). 0.11.16, which
  0.10.0 shipped, is affected by RUSTSEC-2026-0338, 0339, 0340, 0341, 0342,
  0523 and 0524. The last lets anyone who sees a client's first Initial answer
  with a Retry whose token makes a Hysteria, MASQUE, XHTTP H3 or DNS-over-QUIC
  client try to allocate more than 10 GiB and abort. `cargo audit` could not
  see it: the crate is a path dependency.
- **Security, TLS**: rustls is the vendored shaped-rustls fork at the commit
  0.10.0 used, with four upstream fixes (RUSTSEC-2026-0285, 0346, 0348, 0349).
  0348 let a server, or anyone answering in its place, make a client whose
  hello offers brotli certificate compression, as the Chrome profiles do,
  allocate 1 GiB before the certificate is authenticated. No ClientHello byte
  changes.
- **Supply chain**: `scripts/check-vendored-advisories.sh`, in the
  supply-chain CI job, audits the upstream release under every vendored crate
  and every git dependency against RustSec.
- **TLS and REALITY fingerprints** advertise their uTLS profile's whole cipher
  suite list ([#307](https://github.com/aimalygin/xray-rust/pull/307)). Up to
  0.10.0 the suites rustls does not implement were left off the wire, which
  gave every profile a cipher list no browser sends.
- **Hysteria** gives the connect attempt to a server's last or only address
  what is left of the dial's ten seconds, at most eight
  ([#309](https://github.com/aimalygin/xray-rust/pull/309)).
- **`xray_core_free`** no longer waits for a system DNS lookup: the lookup runs
  on a thread outside the runtime
  ([#311](https://github.com/aimalygin/xray-rust/pull/311) found the hang;
  [#312](https://github.com/aimalygin/xray-rust/pull/312) replaced its bounded
  wait, so that freeing a handle still waits for the runtime's threads without
  a limit).
- **Dependencies**: async-compression 0.4.52 and regex 1.13.0.

Behaviour that changes for users and hosts:

- A server that prefers a CBC or RSA key exchange suite over every AEAD suite
  a fingerprint offers now fails the handshake with
  `SelectedUnofferedCipherSuite`, where it completed on an AEAD suite.
- A Hysteria dial to a server with one address can take up to eight seconds
  before it fails, where it failed after three.
- System DNS lookups run on their own threads, at most 64 at once.
- A QUIC client that is not a ChromeParrot one pads its Initial datagrams to
  the connection's minimum MTU, which XHTTP H3 sets from `initialPacketSize`,
  where it padded them to 1,200 bytes, and bundles acknowledgements as
  quinn-proto 0.11.19 does. ChromeParrot handshakes keep their quic-go layout
  byte for byte.
- A server that sends a brotli-compressed certificate using brotli's
  large-window extension, or trailing bytes after a compressed certificate, is
  refused.

The SDK's adapters, the C header and the Swift and Kotlin sources do not
change. The SDK re-pin carries the new core only.

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
| QUIC stack (#315) | every QUIC carrier: Hysteria2 and XHTTP H3 in `legacy-regression`, MASQUE, their network changes (`wifi-cellular-wifi`, `xhttp-h3-network-change`), DNS over QUIC |
| TLS certificate decompression and the other rustls fixes (#315) | every TLS and REALITY handshake |
| Cipher suite lists (#307) | every case that dials with a TLS or REALITY fingerprint, the REALITY and TLS cases of `legacy-regression` first of all |
| Hysteria connect time (#309) | the Hysteria2 case of `legacy-regression` |
| System DNS off the runtime (#311, #312) | none on the SDK's hosts, which set `XRAY_DNS_BOOTSTRAP_MODE_STATIC_ONLY` and never ask the system resolver |

The 0.10.0 known limitations stay as they are: this release fixes none of
them.

## Left for 0.11.0

TUN TCP sniffing for `destOverride`
([#310](https://github.com/aimalygin/xray-rust/pull/310)) was merged with #312
and reverted before the candidate, on the owner's decision of 2026-11-16.

It changes what a configuration already in use does. With `sniffing` enabled
and `http` or `tls` in `destOverride`, a TUN TCP flow to a real IP address is
routed by the domain it sends, and dialed by that domain unless `routeOnly` is
set. The SDK's VLESS importers (`XrayVlessURLImporter`, `XrayVlessUrlImporter`)
build exactly such a configuration, without `routeOnly`, so that a flow to a
fake IP the fake DNS no longer knows recovers its domain. `XrayClientProfile`
stores the generated JSON, so a profile a host saved from 0.10.0 would, on a
core with #310, dial every TCP flow to a real address by the name it sends: an
application that connects to an address under a name it sends only as a decoy
would be taken to that name, until the link is imported again.

Setting `routeOnly` in the importers, which this release also carried for a
few hours, protects only profiles imported afterwards. Both changes therefore
wait for a release that can migrate the saved profiles as well: #310 again, the
importers' `routeOnly`, and a migration of saved importer profiles when they
are loaded.

## Publication

Not started. In order, as in the [release process](release-process.md): full
CI on the candidate, the SDK pinned to the candidate commit, the evidence and
its publication on `main`, the annotated tag `v0.10.1` and its GitHub release,
then the SDK's Prepare release, tag and packages, the KMP library, and the
README install snippets.

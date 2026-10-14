# v0.8.0 stable release preparation

The latest measured candidate is core
`fcce4be2771c1fb3f11e9503741d39a4d8df314e`, tree
`820cbdc251861d02c93ed007015e5c6109baa3c0`, with SDK
`12fdfa14136e57024d46ace66c84bdbf3dc1d7c7`. PR #42 is merged with the same
runtime tree; CI-only PR #55 and post-merge main CI are green. The
[2026-10-12 report](device-results/2026-10-12-v08-candidate/README.md) preserves
fresh device/host results, original failures and remaining work. The exact-candidate schema-4 archive passed [GitHub validation](https://github.com/aimalygin/xray-rust/actions/runs/38288094780). The immutable core tag `v0.8.0` points to that candidate; publication and canonical artifacts are still pending.

On 2026-10-11 the owner requested release and updates to issues #47/#51–53,
while explicitly deferring the reproduced iPhone Hysteria startup failure
and the unconfirmed calibrated 5% performance gate. The
[decision record](releases/v0.8.0-owner-decisions.json) preserves the exact scope.
The [latest device report](device-results/2026-10-11-iphone17-hysteria/README.md)
retains failures. No packet capture with administrator privileges was run.

The reviewed runtime base is core
`f61eddaf40bcb2144933208438f3f4791cbbabca`, tree
`21ab7af488504b190f259123df9d1588b37590b1`; the development SDK was
`ca0ba5480b4764f210cc7d16961ee00abe9dc4e7`. The owner subsequently required UDP noise (#52) and Linux TPROXY (#47) before
publishing. This is now a new runtime candidate, not a metadata-only promotion.
New candidate hashes, SDK pin and CI evidence must accompany those changes. Historical binary evidence retains its
original version and source identity.

Implemented issue scope: #51 admission and #53 Salamander/hopping, limits and
Android rebind. #52 now also includes FinalMask UDP noise for Hysteria2/XHTTP H3;
#47 adds a bounded Linux TPROXY inbound. See [the supported configuration](config-compatibility.md). Existing documented Android UID visibility,
SS2022 UDP, WireGuard and VMess performance limitations remain visible.

Publication is requested but not yet complete. CI, remaining release-evidence
requirements, core annotated tag verification, the canonical SDK artifact lock
and consumer validation still apply. Do not replace a missing result with a
pass or broaden the scoped owner decisions to unrelated cases.

On 2026-10-12 the owner separately authorized publishing 0.8.0 with
[issue #56](https://github.com/aimalygin/xray-rust/issues/56) open and its
Android VMess UDP stress limitation documented. The exact Rust candidate has
3 timeouts among 13,440 UDP attempts; an independent pinned Xray-core client
on the same phone has 1 among 960, using different SOCKS ingress and scheduling.
These failed verdicts remain failed. The cause is not established, and the
decision is not a client fix, Wi-Fi attribution, or universal no-regression claim.
Other evidence and canonical distribution requirements are unchanged.

## Immutable tag history verification

The initial `v0.8.0` tag CI secret job scans all fetched branches. Adding the
separate evidence branch introduced fourteen false positives for public file
SHA-256 fields, even though those files are absent from the tag ancestry.
The tagged scanner configuration passes the entire tag ancestry unchanged.
PR #57 adds exact value/path/rule exceptions for the evidence branch, with
positive leak controls; it does not rewrite the published tag or measured ZIP.

`Verify source tag` separately scans the complete release ancestry with the
original tagged configuration and all current branches with the tested current
policy. It verifies that every other required job of the exact tag's push CI
passed, rejecting missing, skipped, cancelled or unrelated results. Its artifact
records the original secret-job failure and both replacement scans. It never
waives a runtime test or device limitation. Publication waits for this GitHub
verification and the remaining source jobs; canonical SDK artifacts and clean
consumer checks remain separate.

# v0.7 exact-candidate release evidence

The `v0.7 release evidence` workflow validates a checksum-pinned ZIP against the
checked-out candidate commit and tree. Publication revalidates the same archive.
Mobile verifies the successful versioned workflow, repository, commit, tree and
unexpired artifact. A v0.6 archive cannot satisfy the v0.7 contract.

## Freeze and collect

Commit release metadata, generated configuration contract and all runtime/build
inputs before collection. Collect against that clean checkout and keep output
outside it. Record every failure and retry; do not substitute earlier device
reports for the candidate. The specifically reviewed 0.7.0 stable promotion
below permits only a verified metadata delta; measured identities stay unchanged.

Schema version **2** retains the structural and archive-integrity rules described
in [v0.6 evidence](v06-release-evidence.md): exact clean `candidate` identity,
one physical Apple report and one physical Android report, explicit resource
limits with zero fatal/unrecovered errors, clean release performance, artifact
SHA-256s, exact ZIP membership and bounded archive sizes. Boolean schema values,
duplicate JSON fields, unsafe paths, symlinks and mismatching hashes are rejected.
The validator remains evidence validation, not a substitute for actually running
and reviewing the reported experiments.

## Device scenarios

Every scenario must have positive `durationSeconds`, passing `trafficResult`
and `result`, and a `transitions` array containing all required checks below.
Additional named transitions are allowed; duplicate transitions are rejected.
There is no fixed-duration soak requirement.

| Platform | Required protocol scenario IDs |
| --- | --- |
| Apple | `hysteria2`, `wireguard` |
| Android | `hysteria2-file-descriptor`, `hysteria2-packet-pump`, `wireguard-file-descriptor`, `wireguard-packet-pump` |

Each protocol/path scenario must record all of:

```text
ipv4-tcp, ipv6-tcp, ipv4-udp, ipv6-udp, routed-dns,
start-stop, cancel-active-flow, reconnect, wifi-cellular-wifi,
lock-wake, resource-recovery
```

Both platforms additionally require:

- The five retained v0.6 scenarios: `vless-encryption`, `ip-on-demand`,
  `xhttp-download-session`, `cancellation`, `host-adapter-projection`, with
  their existing nonempty transition reports.
- `profile-import`: `hysteria2-link`, `wireguard-file`, `invalid-input-redaction`.
- `legacy-regression`: `vless-reality`, `xhttp-h1`, `xhttp-h2`, `xhttp-h3`.

Per-device `resource-profile`, `sanitized-log` and `transition-timeline` artifacts
must identify the source/build and show the actual checks, transition timing,
resource limits and observed recovery. Android evidence must distinguish the two
adapter paths; one path's successful traffic cannot stand in for the other.
Physical reports before the final runtime changes are development evidence only.

## Performance and known limitations

Keep the four calibrated historical gate IDs/directions and at least five fresh
samples per metric: `process-throughput`/`vless-encryption-throughput` at least
their explicit minimum, `ip-on-demand-latency`/`xhttp-memory` at most their explicit
maximum. Freeze workload definitions and thresholds before collecting samples;
include them in `build-manifest` and the complete `benchmark-raw` artifact.

The performance artifact set is exactly:

```text
benchmark-raw, build-manifest, protocol-comparisons, known-limitations
```

`protocol-comparisons` must retain the measured Hysteria2/WireGuard source and
binary identities, workloads, repeats, failures, host-quality flags and results.
Existing dated campaigns retain their original source identities; reusing their
report as context does not relabel them as fresh exact-candidate measurements.
`known-limitations` records deferred H2/TUN RSS, remaining Hysteria2 gaps,
statistical uncertainty, and the scope of device coverage. Artifact hashes bind
these reports to the evidence package; their contents still require review.

Passing this packaging gate does not declare complete external-library parity.
The user-approved Mac target remains strictly lower RSS, at most 3% worse other
performance metrics and no reliability allowance. H2/TUN RSS investigation was
explicitly deferred; the other recorded deficits have not silently become passes.
See [the retained performance reports](v07-performance.md).

## Validate and publish evidence

```sh
python3 scripts/check-v07-release-evidence.py evidence.zip "$candidate" "$tree"
bash scripts/check-release-evidence.sh evidence.zip "$candidate" "$tree"
```

Dispatch `.github/workflows/v07-release-evidence.yml` on the exact frozen source,
with an immutable HTTPS ZIP URL and lowercase SHA-256. It produces
`v07-release-evidence-<commit>` containing `v07-release-evidence.zip` and its
validation output. The workflow must exist on the default branch before dispatch.
Do not create/push a public release tag until the complete CI and evidence gates pass.
The owner selected direct stable 0.7.0 publication; no public RC is required.

The v0.6 workflow and schema remain separate for older releases. Unknown release
series fail closed in the selector; they never fall back to the old schema.

## Owner-accepted 0.7.0 evidence (schema 3)

Schema 2 remains strict. Schema 3 requires `result: accepted-with-exceptions`,
`acceptance` exactly matching the canonical
[`v0.7.0-owner-decisions.json`](releases/v0.7.0-owner-decisions.json), and a fifth
performance artifact kind `release-decisions` containing those exact bytes.

Only the four Android protocol scenarios may omit `wifi-cellular-wifi`; their
acceptance entries explicitly record it as `notTested`. Claiming that waived
transition as a pass is rejected. Apple cellular checks, all other transitions,
current traffic results, zero fatal/unrecovered errors and performance/resource
limits remain required. The investigated Android WireGuard timeout case is
accepted as a release decision, not a diagnosis or a generic packet-loss waiver.
Historical failures and diagnostics remain hashed in the archive.

For stable version 0.7.0 the CLI invokes the
[stable source validator](v07-stable-promotion.md), which pins both the complete
measured archive and the measured commit/tree. Other versions do not inherit
these exceptions. The original manifest keeps candidate `3533166` and its
accepted-with-exceptions status; the separate promotion report identifies the
final stable source and explicitly sets `newPhysicalDeviceRun: false`.

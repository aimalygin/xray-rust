# tools/shared — v0.10 copies of the 0.9.0 shared-scenario tools

Source of every copy: `docs/device-results/2026-11-02-v090-candidate/tools/` in
the candidate (7eb199bb). The `v010` profile takes its shared scenarios from the
same list as `v09` (`COMMON.REQUIRED_SCENARIOS` of `check-v06-release-evidence.py`:
`vless-encryption`, `ip-on-demand`, `xhttp-download-session`, `cancellation`,
`host-adapter-projection`), so the ids are unchanged and no tool needed a
change in what it checks. File names are kept, so `diff` against the original
shows exactly what moved.

## Copies

| File | Differs from the 0.9.0 file | Why |
| --- | --- | --- |
| `shared_fixture_v09.py` | One comment line added (line 2); `ROOT` is the campaign checkout `…/device-7eb199bb.noindex/candidate` instead of the redacted `<repo>`; `TOOLS` is `tools/shared/bin` instead of `<repo>/target/release-090/tools`. | The 0.9.0 layout. Cases, keys, transports, routing, the AsIs switch and `--only` are untouched. |
| `shared_android_v09.py` | Identical. | Reads `FIXTURE_DIR` and `PROTOCOL_FIXTURE_DIR`; no layout in it. Projection still uses the 0.9.0 protocol cases `socks-password`, `http-plain`, `shadowsocks-aead-aes-256-gcm` (from `--suite v09 --protocol v09`, which the candidate's fixture still serves). |
| `drive.py` | Candidate path of `run-v09-android-device-matrix.py`; `ANDROID_SERIAL` required (0.9.0 defaulted to the redacted serial); `PACKAGE_SUFFIX` defaults to `.v010`; docstring. | The apps are built with `-PdeviceGateApplicationIdSuffix=.v010`. Same file as `tools/drive.py`. The candidate driver's `Device` methods and `run_case(device, envelope, case, backend, change_network=False)` keep the signatures this adapter calls. |
| `device_clock.py` | Identical. | |
| `local_cancel_v09.py` | Identical. | Android `cancellation` as in 0.9.0: TCP `close-connections` and `disconnect` over the 0.9.0 protocols. |
| `udp_cancel_v09.py` | Identical. | Android delayed-UDP cancellation as in 0.9.0 (`--suite v09`, fixture `--udp-delay-seconds 3`). |
| `apply_ios_projection.py` | Identical. | Takes the tree to patch as its argument. Its anchors in `XrayProtocolDeviceProbe.swift` and `PacketTunnelProvider.swift` are present in the candidate (the provider is byte-identical to 0.9.0's `main-harness-src/PacketTunnelProvider.swift`). |
| `run_android_shared.sh` | Header comment; campaign directory, tools directory, campaign checkout and reference binary paths; Python 3.12 on `PATH`; `ANDROID_SERIAL` from the environment; `BIND` may be overridden; an existing run name is refused; the final line names the events file. | The 0.9.0 layout and the redacted serial. Same two fixtures with the same arguments (`--platform android`; `--suite v09 --protocol v09`), same 5 s wait, same collector. |

## Rebuilt helpers

| File | What | Why |
| --- | --- | --- |
| `bin/vless-keys` | `go build -mod=readonly` of the candidate's `tools/vless-encryption-oracle/main.go` inside the pinned Xray-core v26.11.9 checkout (`build-shared-bins.sh`). | `shared_fixture_v09.py` runs `TOOLS/vless-keys keypair x25519`. 0.9.0's binary was built against v26.10.21. |
| `bin/download-bridge-lan` | The same build of `tools/xhttp-download-oracle/{main,bridge}.go`. | `shared_fixture_v09.py` runs `TOOLS/download-bridge-lan bridge …` with `XRAY_FIXTURE_BIND`. The candidate's bridge already listens on that address, so 0.9.0's `download-bridge-lan-bind.patch` is not applied. |

## Not carried over

- `ios-probe-http-held-flow-and-fakedns.patch`, `ios-probe-http-held-flow.patch`,
  `download-bridge-lan-bind.patch`: in the candidate's tree
  (`docs/v09-release-evidence.md`: the bridge listens on `XRAY_FIXTURE_BIND`,
  the Apple probe honours `expectFakeDNS` and holds a flow for HTTP).
- `run_apple.sh`, `run_collector.sh`: their v0.10 copies are `../run_apple_v010.sh`
  and `../run_collector_v010.sh`, which take an absolute fixture path or a
  collector path such as `shared/local_cancel_v09.py`.
- `worktree-before-perf.patch` (a 0.9.0 working-tree record), `fixture_container.py`
  and `wan_v09.py` (0.9.0 WAN runs on the owner's VPS), `assemble_v09.py`,
  `collect_protocols_v09.py`, `summarize_protocols_v09.py`, `resources_v09.py`
  (archive and performance; `../resources_v010.py` is the v0.10 copy): not shared
  scenarios.

## Output of a copy

`../../apple/ios-projection-build-v010.patch` is `git diff` after
`apply_ios_projection.py` on a detached checkout of the candidate. Against 0.9.0's
`ios-projection-build.patch`: the `PacketTunnelProvider.swift` hunks are
identical; the probe hunks are the projection part alone, because 0.9.0's patch
also carried the held-flow and FakeDNS changes that are now in the tree.

## New here (host-only; not 0.9.0 tools, not device evidence)

- `check_shared_loopback.py`: the shared Apple fixture through the candidate's
  `check-v09-fixture-loopback.py`; `ip-on-demand` read as the probe reads
  `expectFakeDNS`; `--suite shared-asis` is the AsIs negative control.
- `check_hold_close_loopback.py`: the remote-EOF half of the Android TCP
  cancellation (`/v08-hold/<id>`, hold-close `eof` within 3 s) with the
  candidate CLI in place of the device; `--xray-core-client` runs Xray-core's
  client instead, for comparison.
- `build-shared-bins.sh`: the build of `bin/`.

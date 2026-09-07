# v0.6.0-rc.1 release evidence

Candidate: `1e713ca3e6c57be5747b4915b31e0db040a01c0c`. Tree: `69fe0a56ce5bcbd178d8326e32d15dfab660b99c`. Clean checkout.

`v06-release-evidence.zip` SHA-256: `5dab7e06b72af9a8fef1524a7271afe97ca8ff0df893c46a8ab7678921cec490`.

The bounded physical campaigns passed all five required v0.6 scenarios on iPhone 13 / iOS 18.6.2 (188 seconds) and Samsung SM-A145F / Android 15 (260 seconds). Both include verified echo traffic, IPOnDemand negative control, separate authenticated XHTTP upload/download, provider-driven connection cancellation and two native host adapter modes. Per-device memory and thread limits passed. Five fresh performance samples per metric passed on the same candidate.

Long device soak tests were omitted by owner decision on 2026-09-07. Network-switch campaigns are not included in this bounded evidence. This archive does not claim six-hour, WAN, sleep/wake or process-death coverage. Resources were measured with provider/procfs telemetry, not Instruments/Perfetto traces.

The original pre-device performance run passed before these device tests; its missing raw artifacts were restored by repeating both host collectors on the unchanged candidate after device testing. This recovery run is what the archive contains. Core code, device code and measured candidate were not changed. External test applications/drivers are documented in the local supporting evidence.

Full candidate CI: https://github.com/aimalygin/xray-rust/actions/runs/33991923429

The ZIP contains only manifest.json and the eight artifacts referenced by it. Local validation uses the frozen candidate's scripts/check-v06-release-evidence.py. No RC tag has been created at archive assembly time.

## Publication decision

On 2026-09-07 the owner explicitly authorized publication of this reviewed archive to the public aimalygin/xray-rust repository after reviewing its contents and remaining technical metadata. This supersedes the earlier local-only decision.

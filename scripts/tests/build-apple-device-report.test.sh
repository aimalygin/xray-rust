#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
builder="$repo_root/scripts/build-apple-device-report.py"
validator="$repo_root/scripts/check-mobile-device-evidence.py"
fixture_root="$(mktemp -d)"
trap 'rm -rf "$fixture_root"' EXIT

make_fixture() {
  local destination="$1"
  local mutation="${2:-valid}"
  python3 - "$repo_root" "$destination" "$mutation" <<'PY'
import datetime as dt
import json
import pathlib
import runpy
import sys

repo = pathlib.Path(sys.argv[1])
apple = pathlib.Path(sys.argv[2])
mutation = sys.argv[3]
apple.mkdir(parents=True)
policy = runpy.run_path(str(repo / "scripts/check-mobile-device-evidence.py"))
required = policy["REQUIRED_SCENARIOS"]
started = dt.datetime(2026, 9, 1, tzinfo=dt.timezone.utc)
duration = 6 * 60 * 60

def timestamp(seconds):
    return (started + dt.timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")

samples = []
for elapsed in range(0, duration + 1, 60):
    samples.append(
        {
            "elapsedSeconds": elapsed,
            "runtimeGeneration": 1,
            "residentMemoryBytes": 20_000_000,
            "threadCount": 8,
            "activeConnections": 0 if elapsed == duration else 2,
            "tunInboundPackets": elapsed + 1,
            "tunOutboundPackets": elapsed + 2,
            "fatalTunErrors": 0,
            "unrecoveredTransitions": 0,
        }
    )
(apple / "apple-device-samples.json").write_text(
    json.dumps(samples) + "\n", encoding="utf-8"
)
(apple / "resource-profile.trace.zip").write_bytes(b"trace")
(apple / "sanitized-log.txt").write_text("sanitized\n", encoding="utf-8")

events = [
    {"event": "campaign-build-start", "at": timestamp(-1)},
    {"event": "campaign-start", "at": timestamp(0)},
]
elapsed = 1
probe_sequences = {"http": 0, "udp": 0}
for scenario_id, minimum in required.items():
    attempts = 0 if mutation == "missing-scenario" and scenario_id == "airplane-mode" else minimum
    for attempt in range(1, attempts + 1):
        events.append(
            {
                "event": "scenario",
                "at": timestamp(elapsed),
                "attempt": attempt,
                "elapsedSeconds": elapsed,
                "notes": "begin controlled attempt",
                "phase": "begin",
                "scenarioId": scenario_id,
            }
        )
        elapsed += 1
        if scenario_id == "airplane-mode":
            if mutation == "missing-outage-recovery":
                for kind in ("http", "udp"):
                    probe_sequences[kind] += 1
                    events.append(
                        {
                            "event": "probe",
                            "at": timestamp(elapsed),
                            "elapsedSeconds": elapsed,
                            "kind": kind,
                            "result": "passed",
                            "sequence": probe_sequences[kind],
                        }
                    )
                    elapsed += 1
            for kind in ("http", "udp"):
                if mutation == "missing-outage-oracle" and kind == "udp":
                    continue
                events.append(
                    {
                        "event": "probe",
                        "at": timestamp(elapsed),
                        "elapsedSeconds": elapsed,
                        "errorCode": (
                            "unsafe error text"
                            if mutation == "invalid-outage-error"
                            else "offline"
                        ),
                        "kind": kind,
                        "result": "failed",
                    }
                )
                elapsed += 1
        for kind in ("http", "udp"):
            if (
                mutation in {"missing-probe-oracle", "missing-outage-recovery"}
                and scenario_id == "airplane-mode"
                and (
                    mutation == "missing-outage-recovery"
                    or kind == "udp"
                )
            ):
                continue
            probe_sequences[kind] += 1
            events.append(
                {
                    "event": "probe",
                    "at": timestamp(elapsed),
                    "elapsedSeconds": elapsed,
                    "kind": kind,
                    "result": "passed",
                    "sequence": probe_sequences[kind],
                }
            )
            elapsed += 1
        phase = (
            "failed"
            if mutation == "failed-only" and scenario_id == "airplane-mode"
            else "passed"
        )
        events.append(
            {
                "event": "scenario",
                "at": timestamp(elapsed),
                "attempt": attempt,
                "elapsedSeconds": elapsed,
                "notes": "observed expected recovery",
                "phase": phase,
                "scenarioId": scenario_id,
            }
        )
        elapsed += 1
events.append(
    {
        "event": "campaign-end",
        "at": timestamp(duration),
        "elapsedSeconds": duration,
        "result": "passed",
    }
)
with (apple / "transition-timeline.jsonl").open("w", encoding="utf-8") as output:
    for event in events:
        output.write(json.dumps(event, sort_keys=True) + "\n")

metadata = {
    "schemaVersion": 1,
    "campaignId": "apple-report-test",
    "candidate": {"revision": "a" * 40, "dirty": False},
    "rehearsal": mutation == "rehearsal",
    "startedAt": timestamp(0),
    "endedAt": timestamp(duration),
    "requestedDurationSeconds": duration,
    "observedDurationSeconds": duration,
    "sampleIntervalSeconds": 60,
    "device": {
        "physical": True,
        "model": "iPhone",
        "osVersion": "18.6",
        "architecture": "arm64",
        "identifierHash": "b" * 64,
    },
    "app": {
        "bundleIdentifier": "org.example.XrayClient",
        "version": "0.5.0",
        "build": "1",
    },
    "artifacts": {
        "samples": "apple-device-samples.json",
        "resourceProfile": "resource-profile.trace.zip",
        "sanitizedLog": "sanitized-log.txt",
        "transitionTimeline": "transition-timeline.jsonl",
        "xcresult": "apple-device.xcresult",
    },
}
(apple / "apple-run.json").write_text(
    json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
}

valid="$fixture_root/valid/apple"
make_fixture "$valid"
python3 "$builder" "$valid" --artifact-prefix apple >/dev/null

python3 - "$fixture_root/valid" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
apple = json.loads((root / "apple/apple-report.json").read_text(encoding="utf-8"))
android = json.loads(json.dumps(apple))
android["platform"] = "android"
android["device"]["architecture"] = "arm64-v8a"
android["app"]["bundleIdentifier"] = "org.example.XrayAndroid"
campaign = {
    "schemaVersion": 1,
    "campaignId": "apple-report-test",
    "candidate": {"revision": "a" * 40, "dirty": False},
    "reports": [apple, android],
}
(root / "campaign.json").write_text(
    json.dumps(campaign, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY
python3 "$validator" --candidate "$(printf 'a%.0s' {1..40})" \
  "$fixture_root/valid/campaign.json" >/dev/null

expect_failure() {
  local mutation="$1"
  local expected="$2"
  local apple="$fixture_root/$mutation/apple"
  make_fixture "$apple" "$mutation"
  local output
  if output="$(python3 "$builder" "$apple" --artifact-prefix apple 2>&1)"; then
    echo "$mutation unexpectedly produced an Apple report" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "$mutation reported an unexpected error: $output" >&2
    exit 1
  fi
}

expect_failure missing-scenario "scenario airplane-mode has 0 passing attempt"
expect_failure failed-only "scenario airplane-mode has 0 passing attempt"
expect_failure missing-probe-oracle "has no post-begin udp probe"
expect_failure missing-outage-oracle "has no post-begin udp failed probe"
expect_failure missing-outage-recovery "has no post-failure http/udp recovery probe"
expect_failure invalid-outage-error "failed probe has an invalid errorCode"
expect_failure rehearsal "only a formal schema-v1 Apple run"

echo "Apple device report builder tests passed"

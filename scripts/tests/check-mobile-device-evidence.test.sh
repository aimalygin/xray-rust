#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
validator="$repo_root/scripts/check-mobile-device-evidence.py"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

make_fixture() {
  local fixture_root="$1"
  local mutation="${2:-valid}"
  python3 - "$fixture_root" "$mutation" <<'PY'
import copy
import datetime as dt
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
mutation = sys.argv[2]
root.mkdir(parents=True)
candidate = "0123456789abcdef0123456789abcdef01234567"
duration = 6 * 60 * 60
interval = 60
scenario_attempts = {
    "repeated-connect": 20,
    "rapid-stop-during-start": 10,
    "ipv4-traffic": 1,
    "ipv6-traffic": 1,
    "happy-eyeballs-failed-preferred": 5,
    "happy-eyeballs-cancellation": 5,
    "tcp-freedom": 1,
    "tcp-vless-reality": 1,
    "udp-freedom": 1,
    "udp-vless-xudp": 1,
    "dns-failover": 5,
    "captive-network": 1,
    "airplane-mode": 3,
    "wifi-cellular": 10,
    "sleep-wake": 5,
    "memory-pressure": 3,
    "provider-service-restart": 5,
    "dns64-nat64": 1,
    "packet-loss": 1,
    "long-xhttp-h2": 1,
    "long-xhttp-h3": 1,
    "secure-profile-persistence": 1,
    "credential-redaction": 1,
    "platform-lifecycle": 1,
}


def make_artifact(platform, kind):
    path = root / "artifacts" / f"{platform}-{kind}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"sanitized {platform} {kind}\n", encoding="utf-8")
    return {
        "kind": kind,
        "path": path.relative_to(root).as_posix(),
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def make_report(platform):
    samples = []
    generation = 1
    for elapsed in range(0, duration + 1, interval):
        if elapsed == duration // 2:
            generation += 1
        generation_elapsed = elapsed if generation == 1 else elapsed - duration // 2
        samples.append(
            {
                "elapsedSeconds": elapsed,
                "runtimeGeneration": generation,
                "residentMemoryBytes": 32 * 1024 * 1024 + elapsed,
                "threadCount": 12,
                "activeConnections": 0 if elapsed == duration else 2,
                "tunInboundPackets": generation_elapsed // interval + 1,
                "tunOutboundPackets": generation_elapsed // interval + 1,
                "fatalTunErrors": 0,
                "unrecoveredTransitions": 0,
            }
        )
    started = dt.datetime(2026, 8, 31, tzinfo=dt.timezone.utc)
    ended = started + dt.timedelta(seconds=duration)
    return {
        "platform": platform,
        "device": {
            "physical": True,
            "model": "test phone",
            "osVersion": "test os",
            "architecture": "arm64" if platform == "apple" else "arm64-v8a",
            "identifierHash": hashlib.sha256(f"{platform}-device".encode()).hexdigest(),
        },
        "app": {
            "bundleIdentifier": f"org.xrayrust.{platform}",
            "version": "0.5.0-rc.1",
            "build": "1",
        },
        "startedAt": started.isoformat().replace("+00:00", "Z"),
        "endedAt": ended.isoformat().replace("+00:00", "Z"),
        "durationSeconds": duration,
        "sampleIntervalSeconds": interval,
        "samples": samples,
        "scenarios": [
            {
                "id": scenario,
                "status": "passed",
                "attempts": attempts,
                "notes": "controlled physical-device observation passed",
            }
            for scenario, attempts in scenario_attempts.items()
        ],
        "artifacts": [
            make_artifact(platform, "resource-profile"),
            make_artifact(platform, "sanitized-log"),
            make_artifact(platform, "transition-timeline"),
        ],
        "result": "passed",
    }


campaign = {
    "schemaVersion": 1,
    "campaignId": "2026-08-31-v0.5.0-rc.1",
    "candidate": {"revision": candidate, "dirty": False},
    "reports": [make_report("apple"), make_report("android")],
}

if mutation == "short-soak":
    campaign["reports"][0]["durationSeconds"] = 60
    campaign["reports"][0]["endedAt"] = "2026-08-31T00:01:00Z"
elif mutation == "virtual-device":
    campaign["reports"][0]["device"]["physical"] = False
elif mutation == "missing-scenario":
    campaign["reports"][1]["scenarios"].pop()
elif mutation == "rss-growth":
    for sample in campaign["reports"][0]["samples"][-5:]:
        sample["residentMemoryBytes"] += 32 * 1024 * 1024
elif mutation == "bad-artifact-hash":
    campaign["reports"][1]["artifacts"][0]["sha256"] = "f" * 64
elif mutation == "unknown-artifact-kind":
    campaign["reports"][1]["artifacts"][0]["kind"] = "raw-log"
elif mutation == "duplicate-artifact-kind":
    campaign["reports"][1]["artifacts"][1]["kind"] = "resource-profile"
elif mutation == "fractional-duration":
    campaign["reports"][0]["endedAt"] = "2026-08-31T06:00:00.5Z"
elif mutation == "sample-gap":
    del campaign["reports"][0]["samples"][100:102]
elif mutation == "duplicate-platform":
    duplicate = copy.deepcopy(campaign["reports"][0])
    duplicate["device"]["identifierHash"] = hashlib.sha256(b"second-apple").hexdigest()
    campaign["reports"][1] = duplicate
elif mutation != "valid":
    raise SystemExit(f"unknown fixture mutation: {mutation}")

(root / "campaign.json").write_text(
    json.dumps(campaign, indent=2) + "\n", encoding="utf-8"
)
PY
}

expect_failure() {
  local mutation="$1"
  local expected="$2"
  local root="$tmp_dir/$mutation"
  make_fixture "$root" "$mutation"
  if output="$(python3 "$validator" "$root/campaign.json" 2>&1)"; then
    fail "$mutation unexpectedly passed"
  fi
  [[ "$output" == *"$expected"* ]] || fail "$mutation reported an unexpected error: $output"
}

valid_root="$tmp_dir/valid"
make_fixture "$valid_root"
python3 "$validator" \
  --candidate 0123456789abcdef0123456789abcdef01234567 \
  "$valid_root/campaign.json" >/dev/null

if python3 "$validator" \
  --candidate fedcba9876543210fedcba9876543210fedcba98 \
  "$valid_root/campaign.json" >/dev/null 2>&1; then
  fail "candidate mismatch unexpectedly passed"
fi

expect_failure short-soak "soak minimum"
expect_failure virtual-device "physical must be true"
expect_failure missing-scenario "missing release gate"
expect_failure rss-growth "resident-memory growth"
expect_failure bad-artifact-hash "does not match"
expect_failure unknown-artifact-kind "not a supported release artifact kind"
expect_failure duplicate-artifact-kind "duplicate kind"
expect_failure fractional-duration "does not match startedAt/endedAt"
expect_failure sample-gap "sampling gap larger than the allowed bound"
expect_failure duplicate-platform "exactly one Apple and one Android"

echo "mobile device evidence validator tests passed"

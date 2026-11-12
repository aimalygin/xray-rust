#!/usr/bin/env python3
"""Validate v0.10 evidence; prior release exceptions never satisfy this gate."""
import importlib.util
import json
import statistics
import sys
import zipfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "release_evidence_common", Path(__file__).with_name("check-v06-release-evidence.py")
)
assert SPEC and SPEC.loader
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)

# Owner decision on 2026-11-11: the two new carriers take the full device
# transition set, on Apple and on both Android TUN backends.
FULL_PROTOCOLS = {"mkcp", "masque"}
PROTOCOL_TRANSITIONS = {
    "ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination",
    "routed-dns", "start-stop", "cancel-active-flow", "reconnect",
    "wifi-cellular-wifi", "lock-wake", "resource-recovery",
}
# Owner decision on 2026-11-11: the masks, XDRIVE and the VLESS reverse bridge
# take a LAN smoke set on both platforms. XDRIVE's storage runs on the fixture
# host; for "vless-reverse" the device is the bridge.
SMOKE_PROTOCOLS = {
    "xdns", "xicmp", "realm", "sudoku", "xmc", "header-custom", "xdrive", "vless-reverse",
}
SMOKE_TRANSITIONS = {
    "ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination",
    "routed-dns", "start-stop",
}
# Owner decision on 2026-11-11: Android Wi-Fi/cellular is tested this time,
# driven over adb. Android lock/wake is not decided; until the owner decides it
# stays not tested, as in v0.9, and release known limitations must say so.
ANDROID_OWNER_SKIPPED_TRANSITIONS = {"lock-wake"}
ANDROID_PROTOCOL_SCENARIOS = {
    f"{protocol}-{path}": protocol
    for protocol in FULL_PROTOCOLS
    for path in ("file-descriptor", "packet-pump")
}
# Every protocol 0.9.0 shipped. Hysteria2 and XHTTP H3 run with ChromeParrot,
# the default since 0.10; "xhttp-h3-network-change" is the rebind of #263.
LEGACY_PROTOCOLS = {
    "vless-reality", "xhttp-h1", "xhttp-h2", "xhttp-h3", "hysteria2", "wireguard",
    "trojan", "shadowsocks2022", "vmess", "socks", "http", "shadowsocks-aead",
}
LEGACY_TRANSITIONS = LEGACY_PROTOCOLS | {"xhttp-h3-network-change"}
# Every link or profile kind added since 0.9.0.
IMPORT_TRANSITIONS = {
    "vless-link", "trojan-link", "vmess-link", "hysteria2-link", "remnawave-json",
    "invalid-input-redaction",
}
SHARED_SCENARIOS = COMMON.REQUIRED_SCENARIOS | {"profile-import", "legacy-regression"}

# The full comparison the owner deferred from 0.9.0: every protocol 0.9.0
# shipped, this candidate against a build of the published v0.9.0 tag, in one
# run on one machine. The archive carries it as the "release-comparison"
# artifact, a JSON document checked for identity, completeness and honest
# verdicts. A regression does not fail the gate; hiding one does.
BASELINE = {
    "version": "0.9.0",
    "revision": "30928ad51b4a434546cf143f8e385a8746523172",
    "tree": "e55a6c3f021643bd507a611c247f2781aaabbb83",
}
# metric: (direction, candidate median as a percentage of the baseline median).
# Proposed on 2026-11-11 and awaiting the owner; see docs/v0100-release.md.
COMPARISON_BUDGETS = {
    "throughput": ("at-least", 90),
    "latency": ("at-most", 110),
    "memory": ("at-most", 110),
}
COMPARISON_MEASUREMENTS = {
    f"{protocol}-{metric}" for protocol in LEGACY_PROTOCOLS for metric in COMPARISON_BUDGETS
}
MAX_COMPARISON_BYTES = 1024 * 1024


class V010Policy(COMMON.EvidencePolicy):
    schema_version = 5
    label = "v0.10"
    unique_transitions = True
    performance_artifacts = COMMON.REQUIRED_PERFORMANCE_ARTIFACTS | {
        "protocol-comparisons", "known-limitations", "release-comparison",
    }
    measurement_comparisons = COMMON.MEASUREMENT_COMPARISONS | {
        f"{protocol}-{metric}": comparison
        for protocol in FULL_PROTOCOLS
        for metric, comparison in [
            ("throughput", "at-least"), ("latency", "at-most"), ("memory", "at-most")
        ]
    }

    @staticmethod
    def scenarios(platform: str) -> set[str]:
        if platform == "apple":
            return SHARED_SCENARIOS | FULL_PROTOCOLS | SMOKE_PROTOCOLS
        return SHARED_SCENARIOS | set(ANDROID_PROTOCOL_SCENARIOS) | SMOKE_PROTOCOLS

    @staticmethod
    def transitions(scenario: str) -> set[str]:
        if scenario in ANDROID_PROTOCOL_SCENARIOS:
            return PROTOCOL_TRANSITIONS - ANDROID_OWNER_SKIPPED_TRANSITIONS
        if scenario in FULL_PROTOCOLS:
            return PROTOCOL_TRANSITIONS
        if scenario in SMOKE_PROTOCOLS:
            return SMOKE_TRANSITIONS
        if scenario == "profile-import":
            return IMPORT_TRANSITIONS
        if scenario == "legacy-regression":
            return LEGACY_TRANSITIONS
        return set()


POLICY = V010Policy()


def comparison_verdict(metric: str, baseline: list[float], candidate: list[float]) -> str:
    direction, percent = COMPARISON_BUDGETS[metric]
    ratio = statistics.median(candidate) * 100 / statistics.median(baseline)
    within = ratio >= percent if direction == "at-least" else ratio <= percent
    return "within-budget" if within else "regression"


def validate_release_comparison(data: bytes, revision: str, tree: str, limitations: bytes) -> None:
    if len(data) > MAX_COMPARISON_BYTES:
        COMMON.fail("release-comparison exceeds 1 MiB")
    try:
        document = json.loads(data, object_pairs_hook=COMMON.reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        COMMON.fail(f"invalid release-comparison: {error}")
    label = "release-comparison"
    document = COMMON.require_object(document, label)
    COMMON.require_fields(document, {"schemaVersion", "baseline", "candidate", "measurements"}, label)
    if type(document["schemaVersion"]) is not int or document["schemaVersion"] != 1:
        COMMON.fail(f"{label}.schemaVersion must be 1")
    if document["baseline"] != BASELINE:
        COMMON.fail(f"{label}.baseline must be the published v0.9.0 revision and tree")
    if document["candidate"] != {"revision": revision, "tree": tree}:
        COMMON.fail(f"{label}.candidate does not match the release commit and tree")
    measurements = document["measurements"]
    if not isinstance(measurements, list):
        COMMON.fail(f"{label}.measurements must be an array")
    try:
        disclosed = limitations.decode()
    except UnicodeDecodeError:
        COMMON.fail("known-limitations must be UTF-8 text")
    seen: list[str] = []
    for index, raw in enumerate(measurements):
        row_label = f"{label}.measurements[{index}]"
        row = COMMON.require_object(raw, row_label)
        COMMON.require_fields(row, {"id", "unit", "baseline", "candidate", "verdict"}, row_label)
        name = COMMON.require_string(row["id"], f"{row_label}.id", 64)
        seen.append(name)
        if name not in COMPARISON_MEASUREMENTS:
            COMMON.fail(f"{row_label}.id is not a v0.9 protocol measurement: {name!r}")
        COMMON.require_string(row["unit"], f"{row_label}.unit", 32)
        samples = {}
        for side in ("baseline", "candidate"):
            values = row[side]
            if not isinstance(values, list) or len(values) < 5:
                COMMON.fail(f"{row_label}.{side} must contain at least five clean runs")
            samples[side] = [
                COMMON.require_number(value, f"{row_label}.{side}[{position}]", positive=True)
                for position, value in enumerate(values)
            ]
        expected = comparison_verdict(name.rsplit("-", 1)[1], samples["baseline"], samples["candidate"])
        if row["verdict"] != expected:
            COMMON.fail(f"{row_label}.verdict must be {expected!r} for its samples")
        # A measured regression ships only when the release says so.
        if expected == "regression" and name not in disclosed:
            COMMON.fail(f"known-limitations does not name the regression {name!r}")
    if len(seen) != len(set(seen)) or set(seen) != COMPARISON_MEASUREMENTS:
        COMMON.fail(f"{label}.measurements must be exactly {sorted(COMPARISON_MEASUREMENTS)!r}")


def validate_archive(path: Path, revision: str, tree: str) -> None:
    # Structure, digests and the device and performance gates first: after
    # this the manifest and every artifact it names are known to be intact.
    COMMON.validate_archive(path, revision, tree, POLICY)
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        paths = {item["kind"]: item["path"] for item in manifest["performance"]["artifacts"]}
        validate_release_comparison(
            archive.read(paths["release-comparison"]), revision, tree,
            archive.read(paths["known-limitations"]),
        )


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <evidence.zip> <expected-revision> <expected-tree>", file=sys.stderr)
        return 2
    try:
        validate_archive(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    except (OSError, ValueError, COMMON.ValidationError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"v0.10 evidence validated for {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate v0.11 evidence; prior release exceptions never satisfy this gate."""
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

# Owner decision on 2026-11-28 (docs/v0110-release.md): the three carriers
# whose stacks 0.11 moved take the full device transition set, on Apple and on
# both Android TUN backends. VLESS+REALITY runs over the new TLS adapter and
# the crates.io rustls fork, Hysteria2 over the crates.io Quinn fork, and
# WireGuard has the flow-limit wait and the idle device close. All three run
# through the TUN loop that no longer ticks.
FULL_PROTOCOLS = {"vless-reality", "hysteria2", "wireguard"}
PROTOCOL_TRANSITIONS = {
    "ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination",
    "routed-dns", "start-stop", "cancel-active-flow", "reconnect",
    "wifi-cellular-wifi", "lock-wake", "resource-recovery",
}
# WireGuard's device closes after five minutes with no flow. The tunnel stays
# up six minutes with no flow, then TCP and UDP of both families pass again
# over a fresh handshake. Its case sets no keepAlive, which keeps a device open.
WIREGUARD_TRANSITIONS = PROTOCOL_TRANSITIONS | {"idle-device-restart"}
# Owner decision on 2026-11-15, kept for 0.11: the Android test device has no
# cellular data, so the network change is not tested on Android. Release known
# limitations must say so.
ANDROID_OWNER_SKIPPED_TRANSITIONS = {"wifi-cellular-wifi"}
# The same Wi-Fi/cellular step on the legacy scenario's XHTTP H3 case.
ANDROID_OWNER_SKIPPED_LEGACY_TRANSITIONS = {"xhttp-h3-network-change"}
# Owner decision on 2026-11-28 («Да, добавить»): unlike 0.7 to 0.10, Android
# tests lock-wake for the full-set scenarios. The driver turns the screen off
# over adb, waits 60 seconds and wakes the phone; traffic must pass on the same
# runtime. It is not in ANDROID_OWNER_SKIPPED_TRANSITIONS.
ANDROID_PROTOCOL_SCENARIOS = {
    f"{protocol}-{path}": protocol
    for protocol in FULL_PROTOCOLS
    for path in ("file-descriptor", "packet-pump")
}
# TUN TCP sniffing (#310 through #385), on both platforms under one id. The
# Android driver runs every case on both backends.
SNIFFING_SCENARIO = "tun-sniffing"
SNIFFING_TRANSITIONS = {
    "http-host-route", "tls-sni-route", "domain-rule-refusal", "decoy-sni-address",
    "saved-profile-migration", "sniffed-name-dial",
}
# Every carrier, mask and bridge 0.10.x shipped, one smoke pass each.
# "xhttp-h3-network-change" is the rebind of #263.
V09_PROTOCOLS = {
    "vless-reality", "xhttp-h1", "xhttp-h2", "xhttp-h3", "hysteria2", "wireguard",
    "trojan", "shadowsocks2022", "vmess", "socks", "http", "shadowsocks-aead",
}
V010_CARRIERS = {"mkcp", "masque"}
V010_SMOKE = {"xdns", "xicmp", "realm", "sudoku", "xmc", "header-custom", "xdrive", "vless-reverse"}
LEGACY_PROTOCOLS = V09_PROTOCOLS | V010_CARRIERS | V010_SMOKE
LEGACY_TRANSITIONS = LEGACY_PROTOCOLS | {"xhttp-h3-network-change"}
# What profile import changed since 0.10.1.
IMPORT_TRANSITIONS = {"vmess-link-plain", "xray-json-subscription", "invalid-input-redaction"}
SHARED_SCENARIOS = COMMON.REQUIRED_SCENARIOS | {"profile-import", "legacy-regression", SNIFFING_SCENARIO}

# Every carrier 0.10.1 shipped, this candidate against a build of the
# published v0.10.1 tag, in one run on one machine. The archive carries it as
# the "release-comparison" artifact, checked for identity, completeness and
# honest verdicts. A regression does not fail the gate; hiding one does.
BASELINE = {
    "version": "0.10.1",
    "revision": "3cef7c42c2fd296afd27ab0b6435c632842e1a26",
    "tree": "d430ce5f1c106b48ba9ecc55a25455f0a201c50f",
}
COMPARISON_CARRIERS = V09_PROTOCOLS | V010_CARRIERS
# metric: (direction, candidate median as a percentage of the baseline median).
# The owner accepted these budgets for 0.10 on 2026-11-13 and for 0.11 with
# the contract on 2026-11-28.
COMPARISON_BUDGETS = {
    "throughput": ("at-least", 90),
    "latency": ("at-most", 110),
    "memory": ("at-most", 110),
}
COMPARISON_MEASUREMENTS = {
    f"{carrier}-{metric}" for carrier in COMPARISON_CARRIERS for metric in COMPARISON_BUDGETS
}
MAX_COMPARISON_BYTES = 1024 * 1024


class V011Policy(COMMON.EvidencePolicy):
    schema_version = 5
    label = "v0.11"
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
            return SHARED_SCENARIOS | FULL_PROTOCOLS
        return SHARED_SCENARIOS | set(ANDROID_PROTOCOL_SCENARIOS)

    @staticmethod
    def transitions(scenario: str) -> set[str]:
        protocol = ANDROID_PROTOCOL_SCENARIOS.get(scenario, scenario)
        if protocol == "wireguard":
            return WIREGUARD_TRANSITIONS
        if protocol in FULL_PROTOCOLS:
            return PROTOCOL_TRANSITIONS
        if scenario == SNIFFING_SCENARIO:
            return SNIFFING_TRANSITIONS
        if scenario == "profile-import":
            return IMPORT_TRANSITIONS
        if scenario == "legacy-regression":
            return LEGACY_TRANSITIONS
        return set()

    def device_transitions(self, platform: str, scenario: str) -> set[str]:
        required = self.transitions(scenario)
        if platform != "android":
            return required
        if scenario in ANDROID_PROTOCOL_SCENARIOS:
            return required - ANDROID_OWNER_SKIPPED_TRANSITIONS
        # The scenario has one id on both platforms; Apple keeps the transition.
        if scenario == "legacy-regression":
            return required - ANDROID_OWNER_SKIPPED_LEGACY_TRANSITIONS
        return required


POLICY = V011Policy()


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
        COMMON.fail(f"{label}.baseline must be the published v0.10.1 revision and tree")
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
            COMMON.fail(f"{row_label}.id is not a v0.10.1 carrier measurement: {name!r}")
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
    print(f"v0.11 evidence validated for {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Validate v0.8 evidence; prior release exceptions never satisfy this gate."""
import importlib.util
import sys
import zipfile
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "release_evidence_common", Path(__file__).with_name("check-v06-release-evidence.py")
)
assert SPEC and SPEC.loader
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)

PROTOCOLS = {"trojan", "shadowsocks2022", "vmess"}
PROTOCOL_TRANSITIONS = {
    "ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination",
    "routed-dns", "start-stop", "cancel-active-flow", "reconnect",
    "wifi-cellular-wifi", "lock-wake", "resource-recovery",
}
# Owner decision on 2026-10-04 for v0.8: these Android checks are not tested,
# not successful transitions. Retain the omission in release known limitations.
ANDROID_OWNER_SKIPPED_TRANSITIONS = {"wifi-cellular-wifi", "lock-wake"}
ANDROID_PROTOCOL_SCENARIOS = {
    f"{protocol}-{path}"
    for protocol in PROTOCOLS
    for path in ("file-descriptor", "packet-pump")
}
SHARED_SCENARIOS = COMMON.REQUIRED_SCENARIOS | {"profile-import", "legacy-regression"}


class V08Policy(COMMON.EvidencePolicy):
    schema_version = 4
    label = "v0.8"
    unique_transitions = True
    performance_artifacts = COMMON.REQUIRED_PERFORMANCE_ARTIFACTS | {
        "protocol-comparisons", "known-limitations",
    }
    measurement_comparisons = COMMON.MEASUREMENT_COMPARISONS | {
        f"{protocol}-{metric}": comparison
        for protocol in PROTOCOLS
        for metric, comparison in [
            ("throughput", "at-least"), ("latency", "at-most"), ("memory", "at-most")
        ]
    }

    @staticmethod
    def scenarios(platform: str) -> set[str]:
        if platform == "apple":
            return SHARED_SCENARIOS | PROTOCOLS
        return SHARED_SCENARIOS | ANDROID_PROTOCOL_SCENARIOS

    @staticmethod
    def transitions(scenario: str) -> set[str]:
        if scenario in ANDROID_PROTOCOL_SCENARIOS:
            return PROTOCOL_TRANSITIONS - ANDROID_OWNER_SKIPPED_TRANSITIONS
        if any(scenario == name or scenario.startswith(name + "-") for name in PROTOCOLS):
            return PROTOCOL_TRANSITIONS
        if scenario == "profile-import":
            return {"trojan-link", "shadowsocks2022-link", "vmess-link", "invalid-input-redaction"}
        if scenario == "legacy-regression":
            return {"vless-reality", "xhttp-h1", "xhttp-h2", "xhttp-h3", "hysteria2", "wireguard"}
        return set()


POLICY = V08Policy()


def validate_archive(path: Path, revision: str, tree: str) -> None:
    COMMON.validate_archive(path, revision, tree, POLICY)


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <evidence.zip> <expected-revision> <expected-tree>", file=sys.stderr)
        return 2
    try:
        validate_archive(Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    except (OSError, ValueError, COMMON.ValidationError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"v0.8 evidence validated for {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

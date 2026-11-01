#!/usr/bin/env python3
"""Validate v0.9 evidence; prior release exceptions never satisfy this gate."""
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

# Owner decision on 2026-11-01: the v0.9 client protocols take the full device
# transition set. "shadowsocks-aead" is the classic AEAD-2017 family; SS2022
# moves to the legacy regression with the rest of the v0.8 protocols.
PROTOCOLS = {"socks", "http", "shadowsocks-aead"}
PROTOCOL_TRANSITIONS = {
    "ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination",
    "routed-dns", "start-stop", "cancel-active-flow", "reconnect",
    "wifi-cellular-wifi", "lock-wake", "resource-recovery",
}
# HTTP CONNECT relays no UDP, here or in Xray-core. Owner decision on
# 2026-11-01: HTTP shows each UDP probe refused, a negative control, instead of
# claiming UDP transitions it cannot carry.
HTTP_UDP_REFUSALS = {"ipv4-udp": "ipv4-udp-refused", "ipv6-udp": "ipv6-udp-refused"}
# Owner decision on 2026-11-01 for v0.9, made again rather than inherited from
# v0.8: these Android checks are not tested, not successful transitions.
# Retain the omission in release known limitations.
ANDROID_OWNER_SKIPPED_TRANSITIONS = {"wifi-cellular-wifi", "lock-wake"}
ANDROID_PROTOCOL_SCENARIOS = {
    f"{protocol}-{path}": protocol
    for protocol in PROTOCOLS
    for path in ("file-descriptor", "packet-pump")
}


def protocol_transitions(protocol: str) -> set[str]:
    if protocol == "http":
        return {HTTP_UDP_REFUSALS.get(transition, transition) for transition in PROTOCOL_TRANSITIONS}
    return PROTOCOL_TRANSITIONS
SHARED_SCENARIOS = COMMON.REQUIRED_SCENARIOS | {"profile-import", "legacy-regression"}


class V09Policy(COMMON.EvidencePolicy):
    schema_version = 4
    label = "v0.9"
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
        return SHARED_SCENARIOS | set(ANDROID_PROTOCOL_SCENARIOS)

    @staticmethod
    def transitions(scenario: str) -> set[str]:
        if scenario in ANDROID_PROTOCOL_SCENARIOS:
            return protocol_transitions(ANDROID_PROTOCOL_SCENARIOS[scenario]) - ANDROID_OWNER_SKIPPED_TRANSITIONS
        if scenario in PROTOCOLS:
            return protocol_transitions(scenario)
        if scenario == "profile-import":
            return {"socks-link", "http-link", "shadowsocks-aead-link", "invalid-input-redaction"}
        if scenario == "legacy-regression":
            return {
                "vless-reality", "xhttp-h1", "xhttp-h2", "xhttp-h3", "hysteria2", "wireguard",
                "trojan", "shadowsocks2022", "vmess",
            }
        return set()


POLICY = V09Policy()


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
    print(f"v0.9 evidence validated for {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

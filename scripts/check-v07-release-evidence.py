#!/usr/bin/env python3
"""Validate exact-candidate v0.7 evidence without reinterpreting old v0.6 ZIPs."""
import importlib.util
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "release_evidence_common", Path(__file__).with_name("check-v06-release-evidence.py")
)
assert SPEC and SPEC.loader
COMMON = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(COMMON)

PROTOCOL_TRANSITIONS = {
    "ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "routed-dns",
    "start-stop", "cancel-active-flow", "reconnect", "wifi-cellular-wifi",
    "lock-wake", "resource-recovery",
}
SHARED_SCENARIOS = COMMON.REQUIRED_SCENARIOS | {"profile-import", "legacy-regression"}


class V07Policy(COMMON.EvidencePolicy):
    schema_version = 2
    label = "v0.7"
    unique_transitions = True
    # Keep existing calibrated performance gates. New-protocol measurements
    # and known limitations must accompany them; this is not a parity waiver.
    performance_artifacts = COMMON.REQUIRED_PERFORMANCE_ARTIFACTS | {
        "protocol-comparisons", "known-limitations",
    }

    @staticmethod
    def scenarios(platform: str) -> set[str]:
        if platform == "apple":
            return SHARED_SCENARIOS | {"hysteria2", "wireguard"}
        return SHARED_SCENARIOS | {
            "hysteria2-file-descriptor", "hysteria2-packet-pump",
            "wireguard-file-descriptor", "wireguard-packet-pump",
        }

    @staticmethod
    def transitions(scenario: str) -> set[str]:
        if scenario.startswith(("hysteria2", "wireguard")):
            return PROTOCOL_TRANSITIONS
        if scenario == "profile-import":
            return {"hysteria2-link", "wireguard-file", "invalid-input-redaction"}
        if scenario == "legacy-regression":
            return {"vless-reality", "xhttp-h1", "xhttp-h2", "xhttp-h3"}
        return set()


POLICY = V07Policy()


def validate_archive(path: Path, revision: str, tree: str) -> None:
    COMMON.validate_archive(path, revision, tree, POLICY)


if __name__ == "__main__":
    raise SystemExit(COMMON.main(POLICY))

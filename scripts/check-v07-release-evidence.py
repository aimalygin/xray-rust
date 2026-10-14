#!/usr/bin/env python3
"""Validate exact-candidate v0.7 evidence without reinterpreting old v0.6 ZIPs."""
import importlib.util
import copy
import hashlib
import json
import sys
import subprocess
import tomllib
import zipfile
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

ROOT = Path(__file__).resolve().parents[1]
OWNER_DECISIONS = ROOT / "docs/releases/v0.7.0-owner-decisions.json"
ANDROID_PROTOCOLS = V07Policy.scenarios("android") - SHARED_SCENARIOS


def accepted_scope() -> dict:
    return {
        "release": "0.7.0",
        "ownerDecisionsSha256": hashlib.sha256(OWNER_DECISIONS.read_bytes()).hexdigest(),
        "notTested": [
            {"platform": "android", "scenario": scenario, "transition": "wifi-cellular-wifi"}
            for scenario in sorted(ANDROID_PROTOCOLS)
        ],
        "acceptedCases": ["v07-android-wireguard-timeout-owner-acceptance"],
    }


class V07AcceptedPolicy(V07Policy):
    """Explicit owner acceptance; raw failed/untested outcomes stay in the ZIP."""

    schema_version = 3
    performance_artifacts = V07Policy.performance_artifacts | {"release-decisions"}

    def prepare_manifest(self, manifest: dict) -> dict:
        expected = accepted_scope()
        if manifest.get("acceptance") != expected:
            COMMON.fail("acceptance must match the exact v0.7.0 owner decisions and scope")
        if manifest.get("result") != "accepted-with-exceptions":
            COMMON.fail("schema-3 result must disclose accepted-with-exceptions")
        performance = COMMON.require_object(manifest.get("performance"), "performance")
        artifacts = performance.get("artifacts")
        if not isinstance(artifacts, list):
            COMMON.fail("performance.artifacts must be an array")
        decisions = [a for a in artifacts if isinstance(a, dict) and a.get("kind") == "release-decisions"]
        if len(decisions) != 1 or decisions[0].get("sha256") != expected["ownerDecisionsSha256"]:
            COMMON.fail("release-decisions artifact must pin the reviewed owner decision bytes")
        # A waiver cannot coexist with a fabricated successful cellular check.
        devices = manifest.get("devices")
        if not isinstance(devices, list):
            COMMON.fail("manifest.devices must be an array")
        for device in devices:
            if not isinstance(device, dict) or device.get("platform") != "android":
                continue
            scenarios = device.get("scenarios")
            if not isinstance(scenarios, list):
                COMMON.fail("android.scenarios must be an array")
            for scenario in scenarios:
                if isinstance(scenario, dict) and scenario.get("id") in ANDROID_PROTOCOLS:
                    transitions = scenario.get("transitions")
                    if isinstance(transitions, list) and "wifi-cellular-wifi" in transitions:
                        COMMON.fail("waived Android cellular check must remain not-tested")
        # Reuse structural/resource/performance checks without rewriting the archive.
        checked = copy.deepcopy(manifest)
        checked.pop("acceptance")
        checked["result"] = "pass"
        return checked

    @staticmethod
    def transitions(scenario: str) -> set[str]:
        required = V07Policy.transitions(scenario)
        if scenario in ANDROID_PROTOCOLS:
            return required - {"wifi-cellular-wifi"}
        return required


def validate_archive(path: Path, revision: str, tree: str) -> None:
    if path.stat().st_size > COMMON.MAX_ARCHIVE_BYTES:
        COMMON.fail("evidence ZIP exceeds 256 MiB")
    with zipfile.ZipFile(path) as archive:
        try:
            info = archive.getinfo("manifest.json")
        except KeyError:
            COMMON.fail("evidence ZIP is missing manifest.json")
        if info.file_size > COMMON.MAX_MANIFEST_BYTES:
            COMMON.fail("manifest.json exceeds 1 MiB")
        try:
            manifest = json.loads(archive.read(info), object_pairs_hook=COMMON.reject_duplicate_keys)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            COMMON.fail(f"invalid manifest.json: {error}")
        manifest = COMMON.require_object(manifest, "manifest")
        schema = manifest.get("schemaVersion")
    policy = V07AcceptedPolicy() if type(schema) is int and schema == 3 else POLICY
    COMMON.validate_archive(path, revision, tree, policy)


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <evidence.zip> <expected-revision> <expected-tree>", file=sys.stderr)
        return 2
    try:
        version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        if version == "0.7.0":
            spec = importlib.util.spec_from_file_location("v07_promotion", ROOT / "scripts/check-v07-stable-promotion.py")
            assert spec and spec.loader
            promotion = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(promotion)
            print(json.dumps(promotion.validate(ROOT, Path(sys.argv[1]), sys.argv[2], sys.argv[3]), indent=2))
        else:
            # Other versions never inherit the owner's 0.7.0-only exceptions.
            COMMON.validate_archive(Path(sys.argv[1]), sys.argv[2], sys.argv[3], POLICY)
            print(f"v0.7 evidence validated for {sys.argv[2]}; archive acceptance status preserved")
    except (OSError, ValueError, COMMON.ValidationError, subprocess.CalledProcessError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

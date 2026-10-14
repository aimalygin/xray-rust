from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

from scripts.tests import test_v06_release_evidence as legacy
ROOT, REVISION, TREE, V06 = legacy.ROOT, legacy.REVISION, legacy.TREE, legacy.VALIDATOR


SPEC = importlib.util.spec_from_file_location("v07_evidence", ROOT / "scripts/check-v07-release-evidence.py")
assert SPEC and SPEC.loader
V07 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V07)


class V07ReleaseEvidenceTests(unittest.TestCase):
    write_zip = legacy.V06ReleaseEvidenceTests.write_zip

    def evidence(self):
        manifest, blobs = legacy.V06ReleaseEvidenceTests.evidence(self)
        manifest["schemaVersion"] = 2
        for device in manifest["devices"]:
            template = copy.deepcopy(device["scenarios"][0])
            device["scenarios"] = []
            for scenario in sorted(V07.POLICY.scenarios(device["platform"])):
                value = copy.deepcopy(template)
                value.update(id=scenario, transitions=sorted(V07.POLICY.transitions(scenario)) or ["start-stop"])
                device["scenarios"].append(value)
        for kind in ["protocol-comparisons", "known-limitations"]:
            path = f"performance/{kind}.txt"
            blobs[path] = f"test-only {kind}".encode()
            manifest["performance"]["artifacts"].append(
                {"kind": kind, "path": path, "sha256": hashlib.sha256(blobs[path]).hexdigest()}
            )
        return manifest, blobs

    def test_valid_exact_candidate_evidence(self):
        V07.validate_archive(self.write_zip(), REVISION, TREE)

    def test_wrong_candidate_is_rejected(self):
        self.reject(lambda m, _: m["candidate"].update(revision="3" * 40), "candidate revision")

    def test_missing_device_scenario_is_rejected(self):
        self.reject(lambda m, _: m["devices"][0]["scenarios"].pop(), "scenarios must be exactly")

    def reject(self, mutation, message):
        with self.assertRaisesRegex(V07.COMMON.ValidationError, message):
            V07.validate_archive(self.write_zip(mutation), REVISION, TREE)

    def test_performance_regression_is_rejected(self):
        self.reject(lambda m, _: next(x for x in m["performance"]["measurements"] if x["comparison"]=="at-most").update(samples=[4]*5), "median exceeds")

    def test_throughput_regression_is_rejected(self):
        self.reject(lambda m, _: next(x for x in m["performance"]["measurements"] if x["comparison"]=="at-least").update(samples=[1]*5, threshold=2), "below its explicit minimum")

    def test_measurement_cannot_reverse_its_required_comparison(self):
        self.reject(lambda m, _: m["performance"]["measurements"][0].update(comparison="reversed"), "comparison must be")

    def test_unlisted_file_is_rejected(self):
        self.reject(lambda _, b: b.update({"extra.txt":b"extra"}), "file set differs")

    def test_old_v06_manifest_cannot_satisfy_v07_gate(self):
        self.reject(lambda m, _: m.update(schemaVersion=1), "schemaVersion must be 2")

    def test_boolean_schema_is_rejected(self):
        self.reject(lambda m, _: m.update(schemaVersion=True), "schemaVersion")

    def test_v07_cannot_be_accepted_by_old_gate(self):
        with self.assertRaisesRegex(V06.ValidationError, "schemaVersion must be 1"):
            V06.validate_archive(self.write_zip(), REVISION, TREE)

    def test_every_protocol_and_android_path_is_required(self):
        for platform in ["apple", "android"]:
            for scenario in V07.POLICY.scenarios(platform) - V07.SHARED_SCENARIOS:
                with self.subTest(platform=platform, scenario=scenario):
                    def omit(m, _):
                        device = next(x for x in m["devices"] if x["platform"]==platform)
                        device["scenarios"] = [x for x in device["scenarios"] if x["id"]!=scenario]
                    self.reject(omit, "scenarios must be exactly")

    def test_every_protocol_transition_is_required(self):
        for transition in V07.PROTOCOL_TRANSITIONS:
            with self.subTest(transition=transition):
                def omit(m, _):
                    next(x for x in m["devices"][0]["scenarios"] if x["id"].startswith("hysteria2"))["transitions"].remove(transition)
                self.reject(omit, "transitions must include")

    def test_duplicate_transition_cannot_stand_in_for_coverage(self):
        for scenario_id in V07.POLICY.scenarios("apple"):
            with self.subTest(scenario=scenario_id):
                def duplicate(m, _):
                    device = next(item for item in m["devices"] if item["platform"] == "apple")
                    scenario = next(
                        item for item in device["scenarios"]
                        if item["id"] == scenario_id
                    )
                    scenario["transitions"].append(scenario["transitions"][0])
                self.reject(duplicate, "without duplicates")

    def test_failed_traffic_and_unrecovered_transition_are_rejected(self):
        self.reject(lambda m, _: m["devices"][0]["scenarios"][0].update(trafficResult="fail"), "trafficResult")
        self.reject(lambda m, _: m["devices"][0]["observed"].update(unrecoveredTransitions=1), "exceeds its explicit limit")

    def test_known_limitations_must_be_delivered_and_hashed(self):
        self.reject(lambda m, _: m["performance"]["artifacts"].pop(), "kinds must be exactly")
        self.reject(lambda _, b: b.update({"performance/known-limitations.txt":b"changed"}), "checksum differs")

    def test_archive_traversal_is_rejected(self):
        self.reject(lambda _, b: b.update({"../escape":b"x"}), "normalized relative")

    def test_version_selector_does_not_fall_back_to_v06(self):
        for value, expected in [("0.6.1","v06"),("v0.6.1-rc.1","v06"),("0.7.0-rc.1","v07"),("v0.7.0","v07")]:
            result=subprocess.run(["bash",str(ROOT/"scripts/release-evidence-profile.sh"),value],capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr);self.assertEqual(result.stdout.strip(),expected)
        for value in ["", "0.7.no", "0.7.0-rc.0", "0.7.0-rc.01", "0.9.0", "v0.70.0", "0.7.0/../../x"]:
            with self.subTest(version=value):
                result=subprocess.run(["bash",str(ROOT/"scripts/release-evidence-profile.sh"),value],capture_output=True,text=True)
                self.assertNotEqual(result.returncode,0)


class V07AcceptedEvidenceTests(unittest.TestCase):
    write_zip = legacy.V06ReleaseEvidenceTests.write_zip
    reject = V07ReleaseEvidenceTests.reject

    def evidence(self):
        manifest, blobs = V07ReleaseEvidenceTests.evidence(self)
        manifest.update(schemaVersion=3, result="accepted-with-exceptions", acceptance=V07.accepted_scope())
        for device in manifest["devices"]:
            if device["platform"] == "android":
                for scenario in device["scenarios"]:
                    if scenario["id"] in V07.ANDROID_PROTOCOLS:
                        scenario["transitions"].remove("wifi-cellular-wifi")
        path = "performance/release-decisions.json"
        blobs[path] = V07.OWNER_DECISIONS.read_bytes()
        manifest["performance"]["artifacts"].append({
            "kind": "release-decisions", "path": path,
            "sha256": hashlib.sha256(blobs[path]).hexdigest(),
        })
        return manifest, blobs

    def test_explicit_acceptance_preserves_archive_result(self):
        import zipfile
        path = self.write_zip()
        V07.validate_archive(path, REVISION, TREE)
        with zipfile.ZipFile(path) as archive:
            self.assertEqual(json.loads(archive.read("manifest.json"))["result"], "accepted-with-exceptions")

    def test_cannot_hide_or_expand_acceptance(self):
        for mutation in [
            lambda m, b: m.update(result="pass"),
            lambda m, b: m.pop("acceptance"),
            lambda m, b: m["acceptance"].update(release="0.7.1"),
            lambda m, b: m["acceptance"]["acceptedCases"].append("all-udp-loss"),
            lambda m, b: m["acceptance"]["notTested"].pop(),
        ]:
            with self.subTest(mutation=mutation):
                self.reject(mutation, "acceptance|accepted-with-exceptions")

    def test_decision_artifact_must_match_reviewed_bytes(self):
        def alter(manifest, blobs):
            path = "performance/release-decisions.json"
            blobs[path] = b"unreviewed decision"
            next(a for a in manifest["performance"]["artifacts"] if a["kind"] == "release-decisions")["sha256"] = hashlib.sha256(blobs[path]).hexdigest()
        self.reject(alter, "reviewed owner decision bytes")
        self.reject(lambda m, b: b.update({"performance/release-decisions.json": b"changed"}), "checksum differs")

    def test_android_cellular_must_remain_not_tested(self):
        def fake(manifest, _):
            device = next(d for d in manifest["devices"] if d["platform"] == "android")
            next(s for s in device["scenarios"] if s["id"] in V07.ANDROID_PROTOCOLS)["transitions"].append("wifi-cellular-wifi")
        self.reject(fake, "must remain not-tested")

    def test_other_device_transitions_still_required(self):
        for platform in ["apple", "android"]:
            required = V07.PROTOCOL_TRANSITIONS - ({"wifi-cellular-wifi"} if platform == "android" else set())
            for transition in required:
                with self.subTest(platform=platform, transition=transition):
                    def omit(manifest, _):
                        device = next(d for d in manifest["devices"] if d["platform"] == platform)
                        next(s for s in device["scenarios"] if s["id"].startswith("wireguard"))["transitions"].remove(transition)
                    self.reject(omit, "transitions must include")

    def test_current_failures_and_resource_regressions_still_rejected(self):
        self.reject(lambda m, b: m["devices"][0]["scenarios"][0].update(trafficResult="fail"), "trafficResult")
        for metric, value in [("fatalErrors", 1), ("unrecoveredTransitions", 1), ("residentMemoryGrowthBytes", 2**40)]:
            with self.subTest(metric=metric):
                self.reject(lambda m, b: m["devices"][1]["observed"].update({metric: value}), "exceeds its explicit limit")

    def test_other_versions_do_not_inherit_exceptions_via_cli(self):
        import contextlib
        import io
        import tempfile
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Cargo.toml").write_text('[workspace.package]\nversion = "0.7.1"\n')
            with patch.object(V07, "ROOT", root), patch.object(V07.sys, "argv", ["validator", str(self.write_zip()), REVISION, TREE]), contextlib.redirect_stderr(io.StringIO()) as error:
                self.assertEqual(V07.main(), 1)
                self.assertIn("unexpected=['acceptance']", error.getvalue())

    def test_old_schema_does_not_inherit_exceptions(self):
        def downgrade(manifest, _):
            manifest.update(schemaVersion=2, result="pass")
            manifest.pop("acceptance")
        self.reject(downgrade, "transitions must include|kinds must be exactly")


if __name__ == "__main__":
    unittest.main()

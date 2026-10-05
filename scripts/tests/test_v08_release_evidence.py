import copy
import hashlib
import importlib.util
import subprocess
import unittest

from scripts.tests import test_v06_release_evidence as legacy

SPEC = importlib.util.spec_from_file_location("v08_evidence", legacy.ROOT / "scripts/check-v08-release-evidence.py")
assert SPEC and SPEC.loader
V08 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V08)


class V08ReleaseEvidenceTests(unittest.TestCase):
    write_zip = legacy.V06ReleaseEvidenceTests.write_zip

    def evidence(self):
        manifest, blobs = legacy.V06ReleaseEvidenceTests.evidence(self)
        manifest["schemaVersion"] = 4
        for device in manifest["devices"]:
            template = device["scenarios"][0]
            device["scenarios"] = [
                dict(copy.deepcopy(template), id=scenario,
                     transitions=sorted(V08.POLICY.transitions(scenario)) or ["start-stop"])
                for scenario in sorted(V08.POLICY.scenarios(device["platform"]))
            ]
        manifest["performance"]["measurements"] = [
            {"id": name, "unit": "test-units", "samples": [2] * 5,
             "comparison": comparison, "threshold": 1 if comparison == "at-least" else 3}
            for name, comparison in sorted(V08.POLICY.measurement_comparisons.items())
        ]
        for kind in ["protocol-comparisons", "known-limitations"]:
            path = f"performance/{kind}.txt"
            blobs[path] = f"test-only {kind}".encode()
            manifest["performance"]["artifacts"].append(
                {"kind": kind, "path": path, "sha256": hashlib.sha256(blobs[path]).hexdigest()}
            )
        return manifest, blobs

    def reject(self, mutation, message):
        with self.assertRaisesRegex(V08.COMMON.ValidationError, message):
            V08.validate_archive(self.write_zip(mutation), legacy.REVISION, legacy.TREE)

    def test_valid_exact_candidate(self):
        V08.validate_archive(self.write_zip(), legacy.REVISION, legacy.TREE)
        for version in ["0.8.0", "v0.8.0-rc.1"]:
            result = subprocess.run(["bash", str(legacy.ROOT / "scripts/release-evidence-profile.sh"), version], capture_output=True, text=True)
            self.assertEqual((result.returncode, result.stdout.strip()), (0, "v08"))

    def test_previous_schemas_and_acceptance_are_rejected(self):
        for schema in [1, 2, 3, True]:
            with self.subTest(schema=schema):
                self.reject(lambda m, _: m.update(schemaVersion=schema), "schemaVersion must be 4")
        self.reject(lambda m, _: m.update(acceptance={"release": "0.7.0"}), "fields differ")
        self.reject(lambda m, _: m.update(result="accepted-with-exceptions"), "must be 'pass'")
        self.reject(lambda m, _: m["candidate"].update(revision="3" * 40), "candidate revision")

    def test_every_protocol_path_and_transition_is_required(self):
        for platform in ["apple", "android"]:
            for name in V08.POLICY.scenarios(platform) - V08.SHARED_SCENARIOS:
                for transition in V08.PROTOCOL_TRANSITIONS:
                    if platform == "android" and transition in {"wifi-cellular-wifi", "lock-wake"}:
                        continue
                    with self.subTest(platform=platform, scenario=name, transition=transition):
                        def omit(m, _):
                            device = next(d for d in m["devices"] if d["platform"] == platform)
                            next(s for s in device["scenarios"] if s["id"] == name)["transitions"].remove(transition)
                        self.reject(omit, "transitions must include")

    def test_owner_skip_is_limited_to_android_network_and_lock(self):
        expected = {"wifi-cellular-wifi", "lock-wake"}
        for protocol in ["trojan", "shadowsocks2022", "vmess"]:
            self.assertEqual(V08.POLICY.transitions(protocol), V08.PROTOCOL_TRANSITIONS)
            for path in ["file-descriptor", "packet-pump"]:
                self.assertEqual(
                    V08.POLICY.transitions(f"{protocol}-{path}"),
                    V08.PROTOCOL_TRANSITIONS - expected,
                )
        manifest, _ = self.evidence()
        android = next(d for d in manifest["devices"] if d["platform"] == "android")
        for scenario in android["scenarios"]:
            self.assertTrue(expected.isdisjoint(scenario["transitions"]))
        V08.validate_archive(self.write_zip(), legacy.REVISION, legacy.TREE)

    def test_each_protocol_budget_is_enforced(self):
        for name in V08.POLICY.measurement_comparisons:
            with self.subTest(measurement=name):
                def regress(m, _):
                    measurement = next(v for v in m["performance"]["measurements"] if v["id"] == name)
                    measurement["samples"] = [0.5 if measurement["comparison"] == "at-least" else 4] * 5
                self.reject(regress, "median exceeds|below its explicit minimum")

    def test_incomplete_or_modified_evidence_is_rejected(self):
        self.reject(lambda m, _: m["devices"][0]["scenarios"].pop(), "scenarios must be exactly")
        self.reject(lambda m, _: m["performance"]["measurements"].pop(), "measurements must be exactly")
        self.reject(lambda _, b: b.update({"performance/known-limitations.txt": b"changed"}), "checksum differs")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import hashlib
import importlib.util
import json
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_v06_release_evidence", ROOT / "scripts/check-v06-release-evidence.py"
)
assert SPEC and SPEC.loader
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)
REVISION = "1" * 40
TREE = "2" * 40


class V06ReleaseEvidenceTests(unittest.TestCase):
    def evidence(self):
        blobs = {}

        def artifacts(prefix, kinds):
            result = []
            for kind in kinds:
                path = f"{prefix}/{kind}.txt"
                data = f"{prefix}:{kind}".encode()
                blobs[path] = data
                result.append(
                    {"kind": kind, "path": path, "sha256": hashlib.sha256(data).hexdigest()}
                )
            return result

        scenarios = [
            {
                "id": scenario,
                "durationSeconds": 1,
                "transitions": ["start-stop"],
                "trafficResult": "pass",
                "result": "pass",
            }
            for scenario in sorted(VALIDATOR.REQUIRED_SCENARIOS)
        ]
        devices = []
        for platform in sorted(VALIDATOR.REQUIRED_PLATFORMS):
            devices.append(
                {
                    "platform": platform,
                    "physical": True,
                    "model": f"{platform}-device",
                    "osVersion": "1.0",
                    "architecture": "arm64",
                    "durationSeconds": 10,
                    "scenarios": scenarios,
                    "limits": {
                        "residentMemoryGrowthBytes": 1024,
                        "threadGrowth": 2,
                        "fatalErrors": 0,
                        "unrecoveredTransitions": 0,
                    },
                    "observed": {
                        "residentMemoryGrowthBytes": 0,
                        "threadGrowth": 0,
                        "fatalErrors": 0,
                        "unrecoveredTransitions": 0,
                    },
                    "artifacts": artifacts(
                        platform, sorted(VALIDATOR.REQUIRED_DEVICE_ARTIFACTS)
                    ),
                    "result": "pass",
                }
            )
        measurements = [
            {
                "id": item,
                "unit": "units",
                "samples": [2, 2, 2, 2, 2],
                "comparison": comparison,
                "threshold": 1 if comparison == "at-least" else 3,
            }
            for item, comparison in sorted(VALIDATOR.MEASUREMENT_COMPARISONS.items())
        ]
        manifest = {
            "schemaVersion": 1,
            "candidate": {"revision": REVISION, "tree": TREE, "dirty": False},
            "devices": devices,
            "performance": {
                "profile": "release",
                "clean": True,
                "measurements": measurements,
                "artifacts": artifacts(
                    "performance", sorted(VALIDATOR.REQUIRED_PERFORMANCE_ARTIFACTS)
                ),
                "result": "pass",
            },
            "result": "pass",
        }
        return manifest, blobs

    def write_zip(self, mutate=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "evidence.zip"
        manifest, blobs = self.evidence()
        if mutate:
            mutate(manifest, blobs)
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            for name, data in blobs.items():
                archive.writestr(name, data)
        return path

    def test_valid_exact_candidate_evidence(self):
        VALIDATOR.validate_archive(self.write_zip(), REVISION, TREE)

    def test_wrong_candidate_is_rejected(self):
        path = self.write_zip(
            lambda manifest, _: manifest["candidate"].__setitem__("revision", "3" * 40)
        )
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "candidate revision"):
            VALIDATOR.validate_archive(path, REVISION, TREE)

    def test_missing_device_scenario_is_rejected(self):
        path = self.write_zip(lambda manifest, _: manifest["devices"][0]["scenarios"].pop())
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "scenarios must be exactly"):
            VALIDATOR.validate_archive(path, REVISION, TREE)

    def test_performance_regression_is_rejected(self):
        def regress_latency(manifest, _):
            measurement = next(
                item
                for item in manifest["performance"]["measurements"]
                if item["comparison"] == "at-most"
            )
            measurement.update({"samples": [4, 4, 4, 4, 4], "threshold": 3})

        path = self.write_zip(
            regress_latency
        )
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "median exceeds"):
            VALIDATOR.validate_archive(path, REVISION, TREE)

    def test_throughput_regression_is_rejected(self):
        def regress_throughput(manifest, _):
            measurement = next(
                item
                for item in manifest["performance"]["measurements"]
                if item["comparison"] == "at-least"
            )
            measurement.update({"samples": [1, 1, 1, 1, 1], "threshold": 2})

        path = self.write_zip(regress_throughput)
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "below its explicit minimum"):
            VALIDATOR.validate_archive(path, REVISION, TREE)

    def test_measurement_cannot_reverse_its_required_comparison(self):
        def reverse_comparison(manifest, _):
            measurement = next(
                item
                for item in manifest["performance"]["measurements"]
                if item["comparison"] == "at-least"
            )
            measurement["comparison"] = "at-most"

        path = self.write_zip(reverse_comparison)
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "comparison must be"):
            VALIDATOR.validate_archive(path, REVISION, TREE)

    def test_unlisted_file_is_rejected(self):
        path = self.write_zip(lambda _, blobs: blobs.__setitem__("extra.txt", b"extra"))
        with self.assertRaisesRegex(VALIDATOR.ValidationError, "file set differs"):
            VALIDATOR.validate_archive(path, REVISION, TREE)


if __name__ == "__main__":
    unittest.main()

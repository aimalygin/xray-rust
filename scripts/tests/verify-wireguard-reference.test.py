#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "reference", Path(__file__).resolve().parents[1] / "verify-wireguard-reference.py"
)
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


class ReferencePinTests(unittest.TestCase):
    def setUp(self):
        self.modules = [
            dict(zip(("Path", "Version", "Sum", "GoModSum"), (path, *pin)))
            for path, pin in reference.PINS.items()
        ]

    def test_exact_pins_pass(self):
        reference.verify_modules(self.modules)

    def test_version_and_both_checksums_are_required(self):
        for key in ("Version", "Sum", "GoModSum"):
            with self.subTest(key=key):
                modified = [dict(m) for m in self.modules]
                modified[0][key] = "wrong"
                with self.assertRaisesRegex(SystemExit, "incorrect reference identity"):
                    reference.verify_modules(modified)

    def test_replacement_is_rejected(self):
        self.modules[0]["Replace"] = {"Dir": "/tmp/local-source"}
        with self.assertRaisesRegex(SystemExit, "replacement"):
            reference.verify_modules(self.modules)

    def test_missing_pin_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "missing"):
            reference.verify_modules(self.modules[:1])

    def test_duplicate_pin_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "incorrect"):
            reference.verify_modules(self.modules + self.modules)

    def test_xray_dependency_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "must not import Xray"):
            reference.verify_modules(self.modules + [{"Path": "github.com/xtls/xray-core"}])

    def test_transitive_replacement_is_rejected(self):
        with self.assertRaisesRegex(SystemExit, "replacement"):
            reference.verify_modules(self.modules + [{"Path": "other", "Replace": {}}])

    def test_json_stream_is_parsed(self):
        import json
        text = "\n".join(json.dumps(m) for m in self.modules)
        self.assertEqual(reference.read_modules("\n" + text + " \n"), self.modules)


if __name__ == "__main__":
    unittest.main()

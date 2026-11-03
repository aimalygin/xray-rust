import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/make-release-records.py"
SPEC = importlib.util.spec_from_file_location("records", SCRIPT)
records = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(records)

# The published v0.9.0 report: its archive must stay reproducible from main.
REPORT_COMMIT = "0cabb69b85214b959033e74c542408585bbbe4e8"
REPORT_DIR = "docs/device-results/2026-11-02-v090-candidate"
REPORT_SHA256 = "17707ea710f1aff2f4c493a7c5e2a8b440b9ec0ccbf460794598cfa98181770e"


def has_commit(revision):
    return subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", f"{revision}^{{commit}}"],
                          capture_output=True).returncode == 0


class ReleaseRecordTests(unittest.TestCase):
    @unittest.skipUnless(has_commit(REPORT_COMMIT), "needs full history")
    def test_report_archive_reproduces_the_published_asset(self):
        archive = records.report_archive(REPORT_COMMIT, REPORT_DIR)
        self.assertEqual(hashlib.sha256(archive).hexdigest(), REPORT_SHA256)

    @unittest.skipUnless(has_commit(REPORT_COMMIT), "needs full history")
    def test_report_directory_must_be_dated(self):
        with self.assertRaisesRegex(ValueError, "YYYY-MM-DD"):
            records.report_archive(REPORT_COMMIT, "docs/device-results")

    def test_unbound_inputs_are_refused_before_writing(self):
        with tempfile.TemporaryDirectory() as temp:
            stv = Path(temp) / "stv.json"
            stv.write_text(json.dumps({"schemaVersion": 2, "result": "passed", "tag": "v0.0.1"}))
            out = Path(temp) / "out"
            base = [sys.executable, str(SCRIPT), "--report-commit", "HEAD",
                    "--report-dir", REPORT_DIR, "--sdk-revision", "a" * 40, "--sdk-tree", "b" * 40,
                    "--source-tag-validation", str(stv), str(out)]
            for tag in ("v0.9.0-rc.1", "0.9.0", "v0.9"):
                with self.subTest(tag=tag):
                    result = subprocess.run(base + ["--tag", tag], capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("only a stable release tag", result.stderr)
            self.assertFalse(out.exists())


if __name__ == "__main__":
    unittest.main()

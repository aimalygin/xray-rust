from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.tests import test_v06_release_evidence as evidence_fixtures


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "promotion", ROOT / "scripts/check-v06-stable-promotion.py"
)
assert SPEC and SPEC.loader
PROMOTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROMOTION)


class StablePromotionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "repo"
        self.root.mkdir()
        self.git("init", "-q")
        self.git("config", "user.name", "Release fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.write("Cargo.toml", '[workspace.package]\nversion = "0.6.0-rc.1"\n[workspace.dependencies]\nbytes = "1"\n')
        self.write("Cargo.lock", 'version = 4\n[[package]]\nname = "xray-config"\nversion = "0.6.0-rc.1"\n[[package]]\nname = "bytes"\nversion = "1.0.0"\nsource = "registry+https://example.invalid"\nchecksum = "abc"\n')
        self.write("docs/config-contract.json", '{"coreVersion":"0.6.0-rc.1","supported":["vless"]}')
        self.write("crates/xray-config/src/lib.rs", "pub const VALUE: u8 = 1;\n")
        self.write("README.md", "Candidate\n")
        self.commit()
        self.rc = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        self.git("tag", "-a", PROMOTION.RC_TAG, "-m", "candidate")
        self.tag_object = self.git("rev-parse", f"{PROMOTION.RC_TAG}^{{tag}}")
        for name in PROMOTION.VERSIONED_FILES:
            p = self.root / name
            p.write_text(p.read_text().replace("0.6.0-rc.1", "0.6.0"))
        self.write("docs/v06-stable-promotion.md", "Owner accepted RC application checks.\n")
        self.commit()
        for name, value in {"RC_COMMIT": self.rc, "RC_TREE": self.tree, "RC_TAG_OBJECT": self.tag_object}.items():
            mock = patch.object(PROMOTION, name, value)
            mock.start()
            self.addCleanup(mock.stop)

    def git(self, *args):
        return subprocess.run(["git", "-C", str(self.root), *args], check=True, capture_output=True, text=True).stdout.strip()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def validate(self, **overrides):
        return PROMOTION.validate_source(
            self.root,
            overrides.get("revision", self.git("rev-parse", "HEAD")),
            overrides.get("tree", self.git("rev-parse", "HEAD^{tree}")),
        )

    def test_metadata_only_promotion(self):
        self.assertIn("Cargo.lock", self.validate())

    def test_runtime_edit_is_rejected(self):
        self.write("crates/xray-config/src/lib.rs", "pub const VALUE: u8 = 2;\n")
        self.commit()
        with self.assertRaisesRegex(ValueError, "runtime or unapproved"):
            self.validate()

    def test_new_build_script_is_rejected(self):
        self.write("build.rs", "fn main() {}\n")
        self.commit()
        with self.assertRaisesRegex(ValueError, "runtime or unapproved"):
            self.validate()

    def test_dependency_edit_is_rejected(self):
        path = self.root / "Cargo.lock"
        path.write_text(path.read_text().replace('version = "1.0.0"', 'version = "1.1.0"'))
        self.commit()
        with self.assertRaisesRegex(ValueError, "changes dependencies"):
            self.validate()

    def test_compiler_or_manifest_edit_is_rejected(self):
        path = self.root / "Cargo.toml"
        path.write_text(path.read_text() + '[profile.release]\npanic = "abort"\n')
        self.commit()
        with self.assertRaisesRegex(ValueError, "Cargo.toml changes exceed"):
            self.validate()

    def test_config_contract_drift_is_rejected(self):
        self.write("docs/config-contract.json", '{"coreVersion":"0.6.0","supported":["vmess"]}')
        self.commit()
        with self.assertRaisesRegex(ValueError, "contract changes exceed"):
            self.validate()

    def test_dirty_checkout_is_rejected(self):
        self.write("README.md", "uncommitted\n")
        with self.assertRaisesRegex(ValueError, "dirty"):
            self.validate()

    def test_mismatched_head_or_tree_is_rejected(self):
        for overrides in [{"revision": self.rc}, {"tree": self.tree}]:
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.validate(**overrides)

    def test_moved_rc_tag_is_rejected(self):
        self.git("tag", "-f", "-a", PROMOTION.RC_TAG, "-m", "moved")
        with self.assertRaisesRegex(ValueError, "RC tag object differs"):
            self.validate()

    def test_mode_change_is_rejected(self):
        (self.root / "README.md").chmod(0o755)
        self.commit()
        with self.assertRaisesRegex(ValueError, "file mode changed"):
            self.validate()

    def test_symlink_is_rejected(self):
        (self.root / "README.md").unlink()
        (self.root / "README.md").symlink_to("Cargo.toml")
        self.commit()
        with self.assertRaisesRegex(ValueError, "not a regular file"):
            self.validate()

    def test_archive_remains_bound_to_measured_rc(self):
        manifest, blobs = evidence_fixtures.V06ReleaseEvidenceTests().evidence()
        manifest["candidate"].update(revision=self.rc, tree=self.tree)
        archive = self.root.parent / "rc.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("manifest.json", json.dumps(manifest))
            for name, blob in blobs.items():
                output.writestr(name, blob)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        revision, tree = self.git("rev-parse", "HEAD"), self.git("rev-parse", "HEAD^{tree}")
        with patch.object(PROMOTION, "RC_EVIDENCE_SHA256", digest):
            report = PROMOTION.validate(self.root, archive, revision, tree)
            self.assertEqual(report["measuredCandidate"]["revision"], self.rc)
            self.assertEqual(report["stable"]["revision"], revision)
            self.assertFalse(report["newPhysicalDeviceRun"])
            archive.write_bytes(archive.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "checksum differs"):
                PROMOTION.validate(self.root, archive, revision, tree)


if __name__ == "__main__":
    unittest.main()

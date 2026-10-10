from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from scripts.tests import test_v07_release_evidence as evidence_fixtures


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "promotion", ROOT / "scripts/check-v07-stable-promotion.py"
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
        self.write("Cargo.toml", '[workspace.package]\nversion = "0.7.0-rc.1"\n[workspace.dependencies]\nbytes = "1"\n')
        self.write("Cargo.lock", 'version = 4\n[[package]]\nname = "xray-config"\nversion = "0.7.0-rc.1"\n[[package]]\nname = "bytes"\nversion = "1.0.0"\nsource = "registry+https://example.invalid"\nchecksum = "abc"\n')
        self.write("docs/config-contract.json", '{"coreVersion":"0.7.0-rc.1","supported":["vless"]}')
        self.write("crates/xray-config/src/lib.rs", "pub const VALUE: u8 = 1;\n")
        self.write("README.md", "Candidate\n")
        for name in PROMOTION.SCANNER_POLICY_FILES:
            self.write(name, "measured scanner policy\n")
        self.commit()
        self.rc = self.git("rev-parse", "HEAD")
        self.tree = self.git("rev-parse", "HEAD^{tree}")
        for name in PROMOTION.VERSIONED_FILES:
            p = self.root / name
            p.write_text(p.read_text().replace("0.7.0-rc.1", "0.7.0"))
        self.write("docs/v07-stable-promotion.md", "Owner accepted RC application checks.\n")
        self.commit()
        for name, value in {"MEASURED_COMMIT": self.rc, "MEASURED_TREE": self.tree}.items():
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
        self.write("docs/config-contract.json", '{"coreVersion":"0.7.0","supported":["vmess"]}')
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

    def test_measured_tree_is_pinned(self):
        with patch.object(PROMOTION, "MEASURED_TREE", "0" * 40), self.assertRaisesRegex(ValueError, "measured tree differs"):
            self.validate()

    def test_ci_build_flags_cannot_change(self):
        self.write(".github/workflows/ci.yml", "unreviewed build configuration\n")
        self.commit()
        with self.assertRaises((ValueError, subprocess.CalledProcessError)):
            self.validate()

    def test_only_exact_reviewed_scanner_policy_delta_is_allowed(self):
        before = hashlib.sha256(b"measured scanner policy\n").hexdigest()
        after = hashlib.sha256(b"reviewed correction\n").hexdigest()
        expected = {name: (before, after) for name in PROMOTION.SCANNER_POLICY_FILES}
        for name in expected:
            self.write(name, "reviewed correction\n")
        self.commit()
        with patch.object(PROMOTION, "SCANNER_POLICY_FILES", expected):
            self.assertTrue(expected.keys() <= set(self.validate()))
            for name in expected:
                with self.subTest(name=name):
                    self.write(name, "disable scanning\n")
                    self.commit()
                    with self.assertRaisesRegex(ValueError, "scanner policy differs"):
                        self.validate()
                    self.write(name, "reviewed correction\n")
                    self.commit()

    def test_scanner_correction_hashes_match_published_v07_policy(self):
        # This is the immutable 0.7 promotion contract. Later development may
        # add scanner rules, but must not rewrite the accepted historical hashes.
        # Keep the source bytes locally so shallow/offline test runs work too.
        fixture = json.loads((ROOT / "scripts/tests/fixtures/v07-scanner-policy.json").read_text())
        self.assertEqual(fixture["commit"], "67969094b352f948c6b8b9e2ac75402c577cb7f7")
        self.assertEqual(set(fixture["files"]), set(PROMOTION.SCANNER_POLICY_FILES))
        for name, (_, expected) in PROMOTION.SCANNER_POLICY_FILES.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256(fixture["files"][name].encode()).hexdigest(), expected)

    def test_scanner_correction_hashes_match_published_v07_files(self):
        # These hashes constrain the historical v0.7 promotion, not future
        # development of the scanner policy. Keep the published bytes pinned.
        published = "67969094b352f948c6b8b9e2ac75402c577cb7f7"
        for name, (_, expected) in PROMOTION.SCANNER_POLICY_FILES.items():
            with self.subTest(name=name):
                content = PROMOTION.git(ROOT, "show", f"{published}:{name}")
                self.assertEqual(hashlib.sha256(content).hexdigest(), expected)

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
        manifest, blobs = evidence_fixtures.V07AcceptedEvidenceTests().evidence()
        manifest["candidate"].update(revision=self.rc, tree=self.tree)
        archive = self.root.parent / "rc.zip"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr("manifest.json", json.dumps(manifest))
            for name, blob in blobs.items():
                output.writestr(name, blob)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        revision, tree = self.git("rev-parse", "HEAD"), self.git("rev-parse", "HEAD^{tree}")
        with patch.object(PROMOTION, "EVIDENCE_SHA256", digest):
            report = PROMOTION.validate(self.root, archive, revision, tree)
            self.assertEqual(report["measuredCandidate"]["revision"], self.rc)
            self.assertEqual(report["stable"]["revision"], revision)
            self.assertFalse(report["newPhysicalDeviceRun"])
            archive.write_bytes(archive.read_bytes() + b"changed")
            with self.assertRaisesRegex(ValueError, "checksum differs"):
                PROMOTION.validate(self.root, archive, revision, tree)

    def test_workflow_propagates_validator_failure(self):
        # Run the real workflow shell with GitHub's default bash -e behavior.
        # A logging pipe must not convert a rejected archive into success.
        lines = (ROOT / ".github/workflows/v07-release-evidence.yml").read_text().splitlines()
        start = lines.index("      - name: Download and validate exact-candidate evidence")
        start = lines.index("        run: |", start) + 1
        commands = []
        for line in lines[start:]:
            if line.startswith("          "):
                commands.append(line[10:])
            elif not line:
                commands.append("")
            else:
                break
        self.write("scripts/check-v07-release-evidence.py", "raise SystemExit(17)\n")
        self.write("scripts/release-evidence-profile.sh", "echo v07\n")
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        for name, body in {
            "curl": ': > "$RUNNER_TEMP/v07-release-evidence.zip"',
            "sha256sum": "cat >/dev/null",
            "git": "printf '%040d\\n' 0",
        }.items():
            path = fake_bin / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)
        env = os.environ.copy()
        env.update(
            PATH=str(fake_bin) + os.pathsep + env["PATH"],
            RUNNER_TEMP=str(self.root),
            GITHUB_SHA="1" * 40,
            EVIDENCE_URL="https://example.invalid/evidence.zip",
            EVIDENCE_SHA256="0" * 64,
        )
        result = subprocess.run(
            ["bash", "-e", "-c", "\n".join(commands)],
            cwd=self.root, env=env, capture_output=True, text=True,
        )
        self.assertEqual(result.returncode, 17, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()

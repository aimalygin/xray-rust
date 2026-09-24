#!/usr/bin/env python3
"""Exercise the reference guard against real clean and contaminated Git trees."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "reference", Path(__file__).resolve().parents[1] / "verify-hysteria-reference.py"
)
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


class ReferenceGuardTests(unittest.TestCase):
    def git(self, *arguments):
        return subprocess.check_output(
            ["git", "-C", str(self.checkout), *arguments], text=True, stderr=subprocess.DEVNULL
        ).strip()

    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="hysteria-reference-guard-")
        self.addCleanup(directory.cleanup)
        self.checkout = Path(directory.name).resolve()
        self.git("init", "-q")
        self.git("config", "user.name", "Reference Guard Test")
        self.git("config", "user.email", "reference@example.invalid")
        (self.checkout / "main.go").write_text("package main\n")
        (self.checkout / ".gitignore").write_text("ignored.go\n")
        self.git("add", "main.go", ".gitignore")
        self.git("-c", "commit.gpgsign=false", "commit", "-qm", "synthetic reference")
        self.commit = self.git("rev-parse", "HEAD")

    def verify(self):
        reference.verify_checkout(self.checkout, self.commit)

    def test_clean_checkout_passes(self):
        self.verify()

    def test_wrong_commit_fails(self):
        with self.assertRaisesRegex(SystemExit, "expected"):
            reference.verify_checkout(self.checkout, "0" * 40)

    def test_tracked_edit_fails(self):
        (self.checkout / "main.go").write_text("package changed\n")
        with self.assertRaisesRegex(SystemExit, "tracked or staged"):
            self.verify()

    def test_staged_edit_fails_even_if_worktree_restored(self):
        (self.checkout / "main.go").write_text("package changed\n")
        self.git("add", "main.go")
        (self.checkout / "main.go").write_text("package main\n")
        with self.assertRaisesRegex(SystemExit, "tracked or staged"):
            self.verify()

    def test_untracked_go_file_fails(self):
        (self.checkout / "extra.go").write_text("package main\n")
        with self.assertRaisesRegex(SystemExit, "untracked or ignored"):
            self.verify()

    def test_ignored_go_file_fails(self):
        (self.checkout / "ignored.go").write_text("package main\n")
        with self.assertRaisesRegex(SystemExit, "untracked or ignored"):
            self.verify()

    def test_subdirectory_is_not_a_checkout(self):
        subdirectory = self.checkout / "app"
        subdirectory.mkdir()
        with self.assertRaisesRegex(SystemExit, "repository root"):
            reference.verify_checkout(subdirectory, self.commit)


if __name__ == "__main__":
    unittest.main()

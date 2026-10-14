#!/usr/bin/env python3
"""Verify v0.7.0 promotion without relabeling the measured candidate."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tomllib
import zipfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
MEASURED_COMMIT = "353316687b22c2fabbaf37ab5668dda05a972f46"
MEASURED_TREE = "f5aacb1fb5a5bbda9eac83a7330059219ce6b0ce"
EVIDENCE_SHA256 = "b10aa3e1c6c0451f0d52b0ed13b0272d805fb88cbdbebd94f7c7069cb531330b"
MEASURED_VERSION = "0.7.0-rc.1"
STABLE_VERSION = "0.7.0"

# An explicit list: new runtime files, dependencies, build scripts, adapters,
# compiler settings, and ABI changes require fresh candidate evidence.
NON_RUNTIME_FILES = {
    "README.md", "CHANGELOG.md", "docs/v07-release-evidence.md",
    "docs/v07-stable-promotion.md", "docs/releases/v0.7.0-owner-decisions.json",
    "scripts/check-v06-release-evidence.py", "scripts/check-v07-release-evidence.py",
    "scripts/check-v07-stable-promotion.py",
    "scripts/tests/test_v07_release_evidence.py",
    "scripts/tests/test_v07_stable_promotion.py",
}
# Workflow edits are checked against exact substitutions below, not generally waived.
WORKFLOW_FILES = {".github/workflows/ci.yml", "scripts/tests/check-scheduled-interop-workflow.test.sh"}
VERSIONED_FILES = {"Cargo.toml", "Cargo.lock", "docs/config-contract.json"}
# Bind the scanner-only false-positive correction to its reviewed bytes. This
# does not permit arbitrary scanner exclusions or changes to its test coverage.
SCANNER_POLICY_FILES = {
    ".gitleaks.toml": (
        "9bb942cbc4169e761957f7748975df3b8ca73d49e4549dab5a4f88bd90c8a074",
        "2bf624dfcaa4afd695c65277297ef6993965da4bb73a4f6fd7302cbeeac36bc2",
    ),
    "scripts/tests/check-gitleaks-allowlists.test.py": (
        "d2fe9de6e174bd12bef00386a3f0d83b27bda20e9ca5100642a1a0fad240ab29",
        "6600520c4ba3fd86a788f1403540a3d53c8c4d0639e33988451aa9008df6bcc1",
    ),
}

SPEC = importlib.util.spec_from_file_location(
    "rc_evidence", ROOT / "scripts/check-v07-release-evidence.py"
)
assert SPEC and SPEC.loader
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)


def git(root: pathlib.Path, *args: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True
    ).stdout


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def entries(root: pathlib.Path, revision: str) -> dict[str, tuple[str, str]]:
    result = {}
    for entry in git(root, "ls-tree", "-rz", revision).split(b"\0"):
        if entry:
            metadata, name = entry.split(b"\t", 1)
            mode, kind, oid = metadata.decode().split()
            result[name.decode()] = (mode + " " + kind, oid)
    return result


def validate_version_change(name: str, before: bytes, after: bytes) -> None:
    if name == "Cargo.toml":
        old = f'version = "{MEASURED_VERSION}"'.encode()
        new = f'version = "{STABLE_VERSION}"'.encode()
        require(before.count(old) == 1, "ambiguous workspace version")
        require(after == before.replace(old, new), "Cargo.toml changes exceed the version bump")
    elif name == "Cargo.lock":
        expected = tomllib.loads(before.decode())
        for package in expected["package"]:
            if "source" not in package and package["version"] == MEASURED_VERSION:
                require(package["name"].startswith("xray-"), "unexpected workspace package")
                package["version"] = STABLE_VERSION
        require(tomllib.loads(after.decode()) == expected, "Cargo.lock changes dependencies")
    elif name == "docs/config-contract.json":
        expected = json.loads(before)
        require(expected["coreVersion"] == MEASURED_VERSION, "unexpected contract version")
        expected["coreVersion"] = STABLE_VERSION
        require(json.loads(after) == expected, "configuration contract changes exceed the version bump")


def validate_source(root: pathlib.Path, revision: str, tree: str) -> list[str]:
    require(bool(EVIDENCE.COMMON.SHA40.fullmatch(revision)), "invalid stable commit")
    require(bool(EVIDENCE.COMMON.SHA40.fullmatch(tree)), "invalid stable tree")
    require(git(root, "rev-parse", "HEAD").decode().strip() == revision, "stable commit is not HEAD")
    require(git(root, "rev-parse", "HEAD^{tree}").decode().strip() == tree, "stable tree differs")
    require(not git(root, "status", "--porcelain", "--untracked-files=normal"), "stable checkout is dirty")
    require(git(root, "rev-parse", f"{MEASURED_COMMIT}^{{tree}}").decode().strip() == MEASURED_TREE, "measured tree differs")
    git(root, "merge-base", "--is-ancestor", MEASURED_COMMIT, revision)
    before, after = entries(root, MEASURED_COMMIT), entries(root, revision)
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    require(VERSIONED_FILES <= set(changed), "stable version metadata is incomplete")
    for name in changed:
        require(name in NON_RUNTIME_FILES | VERSIONED_FILES | WORKFLOW_FILES | SCANNER_POLICY_FILES.keys(), f"runtime or unapproved file changed: {name}")
        require(name in after, f"promotion deletes a file: {name}")
        require(after[name][0] in {"100644 blob", "100755 blob"}, f"not a regular file: {name}")
        if name in before:
            require(before[name][0] == after[name][0], f"file mode changed: {name}")
        if name in VERSIONED_FILES:
            validate_version_change(name, git(root, "show", f"{MEASURED_COMMIT}:{name}"), git(root, "show", f"{revision}:{name}"))
        if name in SCANNER_POLICY_FILES:
            require(name in before, f"scanner policy did not exist in the measured source: {name}")
            actual = tuple(hashlib.sha256(git(root, "show", f"{ref}:{name}")).hexdigest()
                           for ref in (MEASURED_COMMIT, revision))
            require(actual == SCANNER_POLICY_FILES[name], f"scanner policy differs from the reviewed correction: {name}")
        if name in WORKFLOW_FILES:
            old = git(root, "show", f"{MEASURED_COMMIT}:{name}")
            new = git(root, "show", f"{revision}:{name}")
            needle = b"python3 -m unittest scripts.tests.test_v06_release_evidence scripts.tests.test_v06_stable_promotion scripts.tests.test_v07_release_evidence\n"
            require(old.count(needle) == 1, "ambiguous CI test invocation")
            require(new == old.replace(needle, needle.rstrip(b"\n") + b" scripts.tests.test_v07_stable_promotion\n"),
                    "CI changes exceed the additional promotion tests")
    return changed


def validate(root: pathlib.Path, archive: pathlib.Path, revision: str, tree: str) -> dict:
    require(archive.stat().st_size <= EVIDENCE.COMMON.MAX_ARCHIVE_BYTES, "measured evidence exceeds size limit")
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == EVIDENCE_SHA256, "measured evidence checksum differs")
    try:
        EVIDENCE.validate_archive(archive, MEASURED_COMMIT, MEASURED_TREE)
    except EVIDENCE.COMMON.ValidationError as error:
        raise ValueError(str(error)) from error
    with zipfile.ZipFile(archive) as source:
        manifest = json.loads(source.read("manifest.json"))
    require(manifest["schemaVersion"] == 3, "v0.7.0 requires the reviewed acceptance disclosure")
    changed = validate_source(root, revision, tree)
    return {
        "schemaVersion": 1,
        "kind": "v0.7.0-stable-promotion",
        "stable": {"revision": revision, "tree": tree, "dirty": False},
        "measuredCandidate": {"revision": MEASURED_COMMIT, "tree": MEASURED_TREE},
        "measuredEvidenceSha256": EVIDENCE_SHA256,
        "changedFiles": changed,
        "runtimeAndDependenciesUnchanged": True,
        "newPhysicalDeviceRun": False,
        "longSoakRequired": False,
        "acceptance": manifest["acceptance"],
        "result": "accepted-with-exceptions",
    }


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <measured-evidence.zip> <stable-commit> <stable-tree>", file=sys.stderr)
        return 2
    try:
        report = validate(ROOT, pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    except (OSError, ValueError, subprocess.CalledProcessError, EVIDENCE.COMMON.ValidationError, zipfile.BadZipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Verify v0.6.0 promotion without relabeling the RC's device measurements."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parents[1]
RC_TAG = "v0.6.0-rc.1"
RC_TAG_OBJECT = "3578dda8475198f19d6be97f310769c36794e9e1"
RC_COMMIT = "1e713ca3e6c57be5747b4915b31e0db040a01c0c"
RC_TREE = "69fe0a56ce5bcbd178d8326e32d15dfab660b99c"
RC_EVIDENCE_SHA256 = "5dab7e06b72af9a8fef1524a7271afe97ca8ff0df893c46a8ab7678921cec490"
RC_VERSION = "0.6.0-rc.1"
STABLE_VERSION = "0.6.0"

# An explicit list: new runtime files, dependencies, build scripts, adapters,
# compiler settings, and ABI changes require fresh candidate evidence.
NON_RUNTIME_FILES = {
    "README.md",
    "CHANGELOG.md",
    "docs/roadmap.md",
    "docs/status.md",
    "docs/v06-candidate-review.md",
    "docs/v06-implementation-plan.md",
    "docs/v06-independent-security-review.md",
    "docs/v06-release-evidence.md",
    "docs/v06-stable-promotion.md",
    "docs/verification.md",
    "docs/vless-encryption-design.md",
    "docs/xhttp-download-design.md",
    "docs/config-tooling.md",
    ".github/workflows/ci.yml",
    ".github/workflows/v06-release-evidence.yml",
    "scripts/check-v06-stable-promotion.py",
    "scripts/check-v06-release-evidence.sh",
    "scripts/tests/test_v06_stable_promotion.py",
    "scripts/tests/check-prerelease-workflow.test.sh",
}
VERSIONED_FILES = {"Cargo.toml", "Cargo.lock", "docs/config-contract.json"}

SPEC = importlib.util.spec_from_file_location(
    "rc_evidence", ROOT / "scripts/check-v06-release-evidence.py"
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
        old = f'version = "{RC_VERSION}"'.encode()
        new = f'version = "{STABLE_VERSION}"'.encode()
        require(before.count(old) == 1, "ambiguous workspace version")
        require(after == before.replace(old, new), "Cargo.toml changes exceed the version bump")
    elif name == "Cargo.lock":
        expected = tomllib.loads(before.decode())
        for package in expected["package"]:
            if "source" not in package and package["version"] == RC_VERSION:
                require(package["name"].startswith("xray-"), "unexpected workspace package")
                package["version"] = STABLE_VERSION
        require(tomllib.loads(after.decode()) == expected, "Cargo.lock changes dependencies")
    elif name == "docs/config-contract.json":
        expected = json.loads(before)
        require(expected["coreVersion"] == RC_VERSION, "unexpected contract version")
        expected["coreVersion"] = STABLE_VERSION
        require(json.loads(after) == expected, "configuration contract changes exceed the version bump")


def validate_source(root: pathlib.Path, revision: str, tree: str) -> list[str]:
    require(bool(EVIDENCE.SHA40.fullmatch(revision)), "invalid stable commit")
    require(bool(EVIDENCE.SHA40.fullmatch(tree)), "invalid stable tree")
    require(git(root, "rev-parse", "HEAD").decode().strip() == revision, "stable commit is not HEAD")
    require(git(root, "rev-parse", "HEAD^{tree}").decode().strip() == tree, "stable tree differs")
    require(not git(root, "status", "--porcelain", "--untracked-files=normal"), "stable checkout is dirty")
    require(git(root, "rev-parse", f"refs/tags/{RC_TAG}^{{tag}}").decode().strip() == RC_TAG_OBJECT, "RC tag object differs")
    require(git(root, "rev-parse", f"refs/tags/{RC_TAG}^{{commit}}").decode().strip() == RC_COMMIT, "RC commit differs")
    require(git(root, "rev-parse", f"{RC_COMMIT}^{{tree}}").decode().strip() == RC_TREE, "RC tree differs")
    git(root, "merge-base", "--is-ancestor", RC_COMMIT, revision)
    before, after = entries(root, RC_COMMIT), entries(root, revision)
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    require(VERSIONED_FILES <= set(changed), "stable version metadata is incomplete")
    for name in changed:
        require(name in NON_RUNTIME_FILES | VERSIONED_FILES, f"runtime or unapproved file changed: {name}")
        require(name in after, f"promotion deletes a file: {name}")
        require(after[name][0] in {"100644 blob", "100755 blob"}, f"not a regular file: {name}")
        if name in before:
            require(before[name][0] == after[name][0], f"file mode changed: {name}")
        if name in VERSIONED_FILES:
            validate_version_change(name, git(root, "show", f"{RC_COMMIT}:{name}"), git(root, "show", f"{revision}:{name}"))
    return changed


def validate(root: pathlib.Path, archive: pathlib.Path, revision: str, tree: str) -> dict:
    require(archive.stat().st_size <= EVIDENCE.MAX_ARCHIVE_BYTES, "RC evidence exceeds size limit")
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == RC_EVIDENCE_SHA256, "published RC evidence checksum differs")
    EVIDENCE.validate_archive(archive, RC_COMMIT, RC_TREE)
    changed = validate_source(root, revision, tree)
    return {
        "schemaVersion": 1,
        "kind": "v0.6.0-stable-promotion",
        "stable": {"revision": revision, "tree": tree, "dirty": False},
        "measuredCandidate": {"revision": RC_COMMIT, "tree": RC_TREE, "tagObject": RC_TAG_OBJECT},
        "rcEvidenceSha256": RC_EVIDENCE_SHA256,
        "changedFiles": changed,
        "runtimeAndDependenciesUnchanged": True,
        "newPhysicalDeviceRun": False,
        "longSoakRequired": False,
        "result": "pass",
    }


def main() -> int:
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <published-rc-evidence.zip> <stable-commit> <stable-tree>", file=sys.stderr)
        return 2
    try:
        report = validate(ROOT, pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3])
    except (OSError, ValueError, subprocess.CalledProcessError, EVIDENCE.ValidationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

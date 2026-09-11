#!/usr/bin/env python3
"""Reject anything except the clean, independently pinned native Hysteria source."""

from pathlib import Path
import subprocess
import sys

HYSTERIA_TAG = "app/v2.12.2"
HYSTERIA_COMMIT = "619a6f856b69fb7ee6a7a379e810e68b84004605"


def verify_checkout(checkout: Path, expected_commit: str = HYSTERIA_COMMIT) -> None:
    def git(*arguments: str) -> str:
        result = subprocess.run(
            ["git", "-C", str(checkout), *arguments],
            capture_output=True, text=True, check=False,
        )
        if result.returncode:
            raise SystemExit(f"cannot inspect Hysteria reference: {result.stderr.rstrip()}")
        return result.stdout

    if Path(git("rev-parse", "--show-toplevel").strip()).resolve() != checkout.resolve():
        raise SystemExit("Hysteria reference must be a repository root")
    actual = git("rev-parse", "--verify", "HEAD^{commit}").strip()
    if actual != expected_commit:
        raise SystemExit(f"Hysteria reference is at {actual}; expected {HYSTERIA_TAG} ({expected_commit})")
    if git("status", "--porcelain=v1", "-z", "--untracked-files=no"):
        raise SystemExit("Hysteria reference has tracked or staged changes")
    # Include ignored files: an ignored Go file can change the reference binary.
    if git("ls-files", "--others", "--directory", "--no-empty-directory", "-z"):
        raise SystemExit("Hysteria reference has untracked or ignored files")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: verify-hysteria-reference.py CHECKOUT")
    verify_checkout(Path(sys.argv[1]))
    print(f"verified native Hysteria {HYSTERIA_TAG} ({HYSTERIA_COMMIT})")

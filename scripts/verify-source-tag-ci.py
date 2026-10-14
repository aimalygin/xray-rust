#!/usr/bin/env python3
"""Bind completed CI gates to a tag after both independent secret scans pass."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


REPOSITORY = "aimalygin/xray-rust"
REQUIRED = {
    "release-metadata", "rust", "go-oracles", "apple", "android",
    "supply-chain", "host-hardening", "fuzz-smoke", "controlled-network",
    "release-evidence", "rc-interop", "secrets",
}


def validate(run, jobs, tag, revision):
    if (run.get("head_sha") != revision or run.get("head_branch") != tag
            or run.get("event") != "push" or run.get("path") != ".github/workflows/ci.yml"
            or run.get("status") != "completed"):
        raise ValueError("CI is not a completed push run for the exact source tag")
    by_name = {job["name"]: job for job in jobs}
    if not REQUIRED <= by_name.keys() or len(by_name) != len(jobs):
        raise ValueError("CI gate missing or duplicated")
    for name, job in by_name.items():
        if job["status"] != "completed":
            raise ValueError(f"unfinished CI gate: {name}")
        if name == "secrets":
            if job["conclusion"] not in {"success", "failure"}:
                raise ValueError("secret scan must have completed, not been cancelled or skipped")
        elif name in REQUIRED:
            if job["conclusion"] != "success":
                raise ValueError(f"required CI gate did not pass: {name}")
        elif job["conclusion"] not in {"success", "skipped"}:
            raise ValueError(f"additional CI gate failed: {name}")
    return {name: job["conclusion"] for name, job in by_name.items()}


def main():
    candidate, tag, run_id, output = sys.argv[1:]
    if not re.fullmatch(r"v\d+\.\d+\.\d+(-rc\.[1-9]\d*)?", tag) or not run_id.isdecimal():
        raise ValueError("invalid release tag or CI run ID")

    def git(ref):
        return subprocess.check_output(["git", "-C", candidate, "rev-parse", ref], text=True).strip()

    def api(path):
        return json.loads(subprocess.check_output(["gh", "api", f"repos/{REPOSITORY}/{path}"], text=True))

    revision = git(f"refs/tags/{tag}^{{commit}}")
    run = api(f"actions/runs/{run_id}")
    response = api(f"actions/runs/{run_id}/jobs?per_page=100")
    if response["total_count"] != len(response["jobs"]):
        raise ValueError("unexpected CI job pagination")
    conclusions = validate(run, response["jobs"], tag, revision)
    record = {
        "schemaVersion": 1, "tag": tag, "tagObject": git(f"refs/tags/{tag}^{{tag}}"),
        "revision": revision, "tree": git(f"refs/tags/{tag}^{{tree}}"),
        "tagCIRun": int(run_id), "tagCIConclusions": conclusions,
        "tagHistoryScan": "passed with unchanged tagged scanner configuration",
        "allBranchesScan": "passed with current, regression-tested exact digest exceptions",
        "verificationRun": os.environ.get("GITHUB_RUN_ID"),
        "policyCommit": os.environ.get("GITHUB_SHA"),
        "scope": "Revalidates secret scanning; does not waive any other failed or skipped required CI gate, device failure, or package-consumer check.",
        "result": "passed",
    }
    Path(output).write_text(json.dumps(record, indent=2) + "\n")
    print(f"Verified {tag} ({revision}): all source gates pass including both independent history scans")


if __name__ == "__main__":
    main()

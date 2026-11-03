#!/usr/bin/env python3
"""Bind a stable release tag to the passing manual CI run on its exact commit.

The tag's own CI run scans the tag's history and revalidates its device
evidence; this script runs after both pass and records which candidate run
proved every other gate, so the tag does not repeat them.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "aimalygin/xray-rust")
WORKFLOW = ".github/workflows/ci.yml"
REQUIRED = {
    "release-metadata", "secrets", "rust", "go-oracles", "rc-interop",
    "scheduled-pinned-interop", "host-hardening", "fuzz-smoke",
    "controlled-network", "apple", "android", "supply-chain",
}
# Warning-only by design (`continue-on-error`): it follows Xray-core main,
# not the pinned compatibility reference.
INFORMATIONAL = {"xray-core-main-smoke"}


def validate(run, jobs, revision):
    if (run.get("head_sha") != revision or run.get("event") != "workflow_dispatch"
            or run.get("path") != WORKFLOW or run.get("status") != "completed"):
        raise ValueError("CI is not a completed manual run for the exact tagged commit")
    by_name = {job["name"]: job for job in jobs}
    if not REQUIRED <= by_name.keys() or len(by_name) != len(jobs):
        raise ValueError("CI gate missing or duplicated")
    for name, job in by_name.items():
        if job["status"] != "completed":
            raise ValueError(f"unfinished CI gate: {name}")
        if name in REQUIRED:
            if job["conclusion"] != "success":
                raise ValueError(f"required CI gate did not pass: {name}")
        elif name not in INFORMATIONAL and job["conclusion"] not in {"success", "skipped"}:
            raise ValueError(f"additional CI gate failed: {name}")
    return {name: job["conclusion"] for name, job in by_name.items()}


def select(runs, jobs_for, revision):
    """Return the newest passing run and its conclusions; report why others fail."""
    reasons = []
    for run in sorted(runs, key=lambda run: run["created_at"], reverse=True):
        try:
            return run, validate(run, jobs_for(run["id"]), revision)
        except ValueError as error:
            reasons.append(f"run {run['id']}: {error}")
    raise ValueError("no passing manual CI run for the tagged commit"
                     + "".join(f"\n  {reason}" for reason in reasons))


def main():
    candidate, tag, output = sys.argv[1:]
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("only a stable release tag binds to a candidate run")

    def git(ref):
        return subprocess.check_output(["git", "-C", candidate, "rev-parse", ref], text=True).strip()

    def api(path):
        return json.loads(subprocess.check_output(["gh", "api", f"repos/{REPOSITORY}/{path}"], text=True))

    def jobs_for(run_id):
        response = api(f"actions/runs/{run_id}/jobs?per_page=100")
        if response["total_count"] != len(response["jobs"]):
            raise ValueError("unexpected CI job pagination")
        return response["jobs"]

    revision = git(f"refs/tags/{tag}^{{commit}}")
    runs = api(f"actions/workflows/ci.yml/runs?event=workflow_dispatch&head_sha={revision}"
               "&status=completed&per_page=100")["workflow_runs"]
    run, conclusions = select(runs, jobs_for, revision)
    record = {
        "schemaVersion": 2, "tag": tag, "tagObject": git(f"refs/tags/{tag}^{{tag}}"),
        "revision": revision, "tree": git(f"refs/tags/{tag}^{{tree}}"),
        "candidateCIRun": run["id"], "candidateCIAttempt": run["run_attempt"],
        "candidateCIConclusions": conclusions,
        "tagCIRun": int(os.environ["GITHUB_RUN_ID"]) if os.environ.get("GITHUB_RUN_ID") else None,
        "tagCIGates": {
            "release-metadata": "tag and changelog verified",
            "secrets": "tag ancestry scanned with the tagged scanner configuration",
            "release-evidence": "exact-candidate evidence revalidated",
        },
        "scope": "Binds the tag to gates that already passed on its exact commit; does not waive "
                 "any device failure or package-consumer check.",
        "result": "passed",
    }
    Path(output).write_text(json.dumps(record, indent=2) + "\n")
    print(f"Bound {tag} ({revision}) to passing candidate CI run {run['id']}")


if __name__ == "__main__":
    main()

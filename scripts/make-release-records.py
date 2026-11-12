#!/usr/bin/env python3
"""Assemble the verified asset set of a stable core GitHub release.

Writes the source archive, the device evidence and report archives, the
source records and SHA256SUMS into an empty output directory. Every input is
bound to the annotated tag: the tag CI's `source-tag-validation` artifact,
and the owner decisions, evidence record and report published on `main`.
See docs/release-process.md.
"""

import argparse
import datetime
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile


ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "aimalygin/xray-rust"


def git(*args, binary=False):
    output = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, check=True).stdout
    return output if binary else output.decode().strip()


def report_archive(commit, report_dir):
    """Zip a committed report under `report/`, stamped with its dated directory name."""
    match = re.match(r"(\d{4})-(\d{2})-(\d{2})-", Path(report_dir).name)
    if not match:
        raise ValueError("report directory must start with its YYYY-MM-DD date")
    stamp = tuple(int(part) for part in match.groups()) + (0, 0, 0)
    datetime.date(*stamp[:3])  # rejects an impossible date
    paths = git("ls-tree", "-r", "--name-only", commit, "--", report_dir).splitlines()
    if not paths:
        raise ValueError(f"{report_dir} is empty at {commit}")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(paths):
            entry = zipfile.ZipInfo("report/" + path[len(report_dir):].lstrip("/"), stamp)
            entry.compress_type = zipfile.ZIP_DEFLATED
            entry.external_attr = 0o644 << 16
            archive.writestr(entry, git("show", f"{commit}:{path}", binary=True))
    return buffer.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--tag", required=True, help="annotated stable tag, e.g. v0.10.0")
    parser.add_argument("--report-commit", required=True,
                        help="main commit with the owner decisions, evidence record and report")
    parser.add_argument("--report-dir", required=True, help="docs/device-results/<YYYY-MM-DD-name>")
    parser.add_argument("--sdk-revision", required=True, help="measured xray-rust-mobile commit")
    parser.add_argument("--sdk-tree", required=True, help="tree of that SDK commit")
    parser.add_argument("--source-tag-validation", required=True, type=Path,
                        help="source-tag-validation.json from the tag CI run")
    parser.add_argument("output", type=Path, help="new or empty directory")
    args = parser.parse_args()

    tag = args.tag
    if not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("only a stable release tag gets these records")
    version = tag[1:]
    for name, value in (("--sdk-revision", args.sdk_revision), ("--sdk-tree", args.sdk_tree)):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError(f"{name} must be a full object ID")
    if git("cat-file", "-t", f"refs/tags/{tag}") != "tag":
        raise ValueError(f"{tag} is not an annotated tag")
    tag_object = git("rev-parse", f"refs/tags/{tag}^{{tag}}")
    commit = git("rev-parse", f"refs/tags/{tag}^{{commit}}")
    tree = git("rev-parse", f"refs/tags/{tag}^{{tree}}")
    report_commit = git("rev-parse", f"{args.report_commit}^{{commit}}")

    stv = json.loads(args.source_tag_validation.read_text())
    if (stv.get("schemaVersion"), stv.get("result"), stv.get("tag"), stv.get("tagObject"),
            stv.get("revision"), stv.get("tree")) != (2, "passed", tag, tag_object, commit, tree):
        raise ValueError("source-tag-validation.json does not bind this tag")

    def published(name):
        return git("show", f"{report_commit}:docs/releases/v{version}-{name}", binary=True)

    decisions = json.loads(published("owner-decisions.json"))
    if decisions.get("publicationRequested") is not True or decisions.get("candidateCommit") != commit:
        raise ValueError("owner decisions do not authorize publishing this commit")
    evidence = json.loads(published("device-evidence.json"))
    evidence_zip = published("device-evidence.zip")
    if (evidence.get("candidateCommit"), evidence.get("candidateTree"), evidence.get("archiveSHA256"),
            evidence.get("workflowValidation")) != (commit, tree, hashlib.sha256(evidence_zip).hexdigest(),
                                                    "passed"):
        raise ValueError("device evidence record does not bind this tag's archive")
    run = re.fullmatch(rf"https://github\.com/{REPOSITORY}/actions/runs/([1-9]\d*)",
                       evidence.get("workflowRun", ""))
    if not run:
        raise ValueError("device evidence record has no evidence workflow run")
    evidence_run = int(run.group(1))

    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError(f"{out} is not empty")
    archive_name = f"xray-rust-{version}.tar.gz"
    with (out / archive_name).open("wb") as handle:
        archive = subprocess.Popen(["git", "-C", str(ROOT), "archive", "--format=tar",
                                    f"--prefix=xray-rust-{version}/", commit], stdout=subprocess.PIPE)
        subprocess.run(["gzip", "-n"], stdin=archive.stdout, stdout=handle, check=True)
        if archive.wait() != 0:
            raise RuntimeError("git archive failed")
    (out / f"v{version}-device-evidence.zip").write_bytes(evidence_zip)
    (out / f"v{version}-device-report.zip").write_bytes(report_archive(report_commit, args.report_dir))
    (out / "source-tag-validation.json").write_text(json.dumps(stv, indent=2) + "\n")

    def sha(name):
        return hashlib.sha256((out / name).read_bytes()).hexdigest()

    limited = bool(decisions.get("knownLimitations") or decisions.get("decisions"))
    acceptance = "accepted-with-documented-limitations" if limited else "accepted"
    record = {
        "schemaVersion": 2,
        "kind": f"v{version}-exact-measured-source",
        "repository": REPOSITORY,
        "tag": tag,
        "tagObject": tag_object,
        "source": {"revision": commit, "tree": tree, "dirty": False},
        "measuredCore": {"revision": commit, "tree": tree},
        "measuredSDK": {"repository": "aimalygin/xray-rust-mobile",
                        "revision": args.sdk_revision, "tree": args.sdk_tree},
        "evidenceRun": evidence_run,
        "evidenceArchiveSha256": sha(f"v{version}-device-evidence.zip"),
        "deviceReportSha256": sha(f"v{version}-device-report.zip"),
        "deviceReportCommit": report_commit,
        "sourceArchiveSha256": sha(archive_name),
        "sourceArchiveContent": f"git archive --format=tar --prefix=xray-rust-{version}/ {tag}^{{commit}}, gzip -n",
        "sourceTagValidation": stv,
        "acceptance": {"result": acceptance, "ownerDecisions": decisions},
        "scope": "The source tag is the exact measured core revision. Scanner verification does not turn failed "
                 "device trials or unmeasured performance comparisons into passes. Canonical SDK distribution and "
                 "clean external package-consumer checks are separate.",
    }
    (out / "source-validation.json").write_text(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    (out / "release-metadata.txt").write_text("\n".join([
        f"tag={tag}", f"version={version}", f"tag_object={tag_object}", f"commit={commit}", f"tree={tree}",
        f"evidence_run={evidence_run}", f"tag_ci_run={stv['tagCIRun']}",
        f"candidate_ci_run={stv['candidateCIRun']}", f"acceptance={acceptance}"]) + "\n")
    assets = sorted(path.name for path in out.iterdir())
    (out / "SHA256SUMS").write_text("".join(f"{sha(name)}  {name}\n" for name in assets))
    print((out / "SHA256SUMS").read_text(), end="")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Freeze publication confirmations separately from the measured device archive."""
import datetime
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
def read(name):
    return json.loads((ROOT / name).read_text())
core = read("core-publication.json")
mobile = read("mobile-publication.json")
consumers = read("public-consumers/results.json")
central = read("mobile-maven-central-run.json")
release = read("mobile-stable-release-run.json")
checksum = read("mobile-checksum-ci-run.json")
assert core["published"] and mobile["published"] and mobile["immutable"]
assert consumers["swift"]["result"] == consumers["android"]["result"] == "pass"
assert central["conclusion"] == release["conclusion"] == checksum["conclusion"] == "success"
assert release["headSha"] == checksum["headSha"] == mobile["commit"]
required = ["core-publication.json", "mobile-publication.json", "mobile-release-api.json",
            "core-final-candidate-ci.json", "core-tag-ci.json", "core-versioned-evidence-run.json",
            "final-core-source-validation.json", "core-assets-roundtrip.json",
            "mobile-canonical-producer-run.json", "mobile-canonical-source-run.json",
            "mobile-stable-pin-run.json", "mobile-stable-release-run.json",
            "mobile-checksum-ci-run.json", "mobile-maven-central-run.json",
            "apple-canonical-verification.json", "apple-canonical-local-verification.log",
            "mobile-public-assets/release-manifest.json", "mobile-public-assets/SHA256SUMS",
            "core-stable-source-bundle/release-metadata.txt", "core-stable-source-bundle/SHA256SUMS",
            "public-consumers/results.json", "public-consumers/maven-expected.json", "public-consumers/commands.json",
            "public-consumers/swift-build.log", "public-consumers/android-build.log",
            "public-consumers/swift/Package.resolved", "public-consumers/README.md",
            "mobile-release-notes.md"]
files = {}
paths = [ROOT / name for name in required]
paths += sorted((ROOT / "ci-logs").glob("*.zip"))
paths += [p for p in (ROOT / "tooling").glob("*.py")]
paths += [ROOT / "tooling/verify-apple-archive-xcode27.sh"]
paths += [ROOT / "public-consumers/swift/Package.swift",
          ROOT / "public-consumers/swift/Sources/ReleaseConsumer/main.swift",
          ROOT / "public-consumers/android/settings.gradle.kts",
          ROOT / "public-consumers/android/build.gradle.kts",
          ROOT / "public-consumers/android/gradle/verification-metadata.xml",
          ROOT / "public-consumers/android/consumer/build.gradle.kts"]
paths += sorted((ROOT / "public-consumers/android/consumer/src").rglob("*"))
for path in paths:
    if path.is_dir():
        continue
    assert path.is_file() and not path.is_symlink(), path
    body = path.read_bytes()
    assert len(body) < 10_000_000, path
    if path.suffix == ".zip":
        with zipfile.ZipFile(path) as archive:
            assert archive.testzip() is None
    files[str(path.relative_to(ROOT))] = body
def digest_records(value):
    # Keep file names and their public checksums in distinct fields. A filename
    # containing "xray" followed by a checksum resembles a JFrog credential to
    # scanners. Original downloaded manifests remain unmodified in the archive.
    if isinstance(value, dict):
        if value and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v)
                         for v in value.values()):
            return [{"file": name, "sha256": digest} for name, digest in value.items()]
        return {name: digest_records(item) for name, item in value.items()}
    if isinstance(value, list):
        return [digest_records(item) for item in value]
    return value

record = {
    "schemaVersion": 1, "kind": "v0.7.0-stable-publication-confirmation",
    "createdAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "core": digest_records(core), "mobile": digest_records(mobile),
    "publicConsumers": digest_records(consumers),
    "mavenCentral": {key: central[key] for key in ("databaseId", "url", "headSha", "conclusion")},
    "measuredArchiveSha256": "b10aa3e1c6c0451f0d52b0ed13b0272d805fb88cbdbebd94f7c7069cb531330b",
    "priorAutomatedArchiveSha256": "58cc5896662addd1a5dcb93002e3be2bf8d186bf0963205f50f89b2944a81885",
    "newPhysicalDeviceRun": False,
    "knownLimitations": "Original accepted-with-exceptions evidence and owner decisions remain applicable. Android cellular handover was not tested; no root cause/product fix for the investigated rare WireGuard timeout is claimed. Deferred H2/TUN RSS and Hysteria2 comparison gaps remain documented.",
    "files": [{"path": name, "sha256": hashlib.sha256(body).hexdigest()}
              for name, body in sorted(files.items())],
    "result": "pass",
}
manifest = (json.dumps(record, indent=2) + "\n").encode()
(ROOT / "publication-confirmation.json").write_bytes(manifest)
files["manifest.json"] = manifest
output = ROOT / "v07-publication-confirmation.tar.gz"
with output.open("wb") as handle:
    with gzip.GzipFile(filename="", fileobj=handle, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, body in sorted(files.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(body)
                entry.mode = 0o644
                entry.mtime = 0
                archive.addfile(entry, io.BytesIO(body))
sha = hashlib.sha256(output.read_bytes()).hexdigest()
(ROOT / "PUBLICATION_SHA256SUMS").write_text(f"{sha}  {output.name}\n")
print(json.dumps({"archive": str(output), "sha256": sha,
                  "bytes": output.stat().st_size, "files": len(files)}, indent=2))

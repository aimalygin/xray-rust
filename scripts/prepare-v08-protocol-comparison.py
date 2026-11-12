#!/usr/bin/env python3
"""Freeze explicitly built clients and bind them to verified source metadata.

Without ``--singbox`` and ``--singbox-source`` the inputs carry no sing-box
client: enough for the ``v010`` suite, which measures the candidate against
Xray-core alone, and refused by the suites that measure all three.

The Rust builds are named either by ``--candidate-builds`` (one record of a
clean build holding both binaries) or by ``--candidate-build`` and
``--harness-build``, one ``build-isolated-release.py`` record each.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

# Must equal the device fixture's REFERENCE (Xray-core v26.11.9), which the
# comparison verifies again before measuring.
XRAY = "676eaf66f8f05d4d558ee7a74b4736623d3feeb9"
SINGBOX = "56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778"
# Xray-core v26.11.9 is built with the Go release CI uses for it.
GO_RELEASES = {"xray": "go1.27.3", "singbox": "go1.26.0"}


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build_identity(path):
    """A build record; one written by build-isolated-release.py is translated."""
    record = json.loads(path.read_text())
    if "isolated_target" not in record:
        return record
    if record["isolated_target"] is not True or record["incremental"] is not False or record["rustflags"]:
        raise ValueError(f"not a clean isolated build: {path}")
    return {"commit": record["commit"], "tree": record["tree"], "rustc": record["rustc"],
            "build_arguments": record["command"], "incremental": False, "sha256": record["sha256"]}


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("root", "candidate", "harness", "xray"):
        p.add_argument("--" + name, type=Path, required=True)
    for name in ("singbox", "singbox-source", "candidate-builds", "candidate-build"):
        p.add_argument("--" + name, type=Path)
    p.add_argument("--harness-build", type=Path, help="separate driver build identity when its source differs from the engine")
    a = p.parse_args()
    if (a.singbox is None) != (a.singbox_source is None):
        raise ValueError("--singbox and --singbox-source go together")
    if (a.candidate_builds is None) == (a.candidate_build is None) or (a.candidate_build and not a.harness_build):
        raise ValueError("name the Rust builds with --candidate-builds, or with --candidate-build and --harness-build")
    references = ("xray", "singbox") if a.singbox else ("xray",)
    if a.candidate_build:
        rust_identity = build_identity(a.candidate_build)
        recorded = rust_identity.pop("sha256")
        harness = build_identity(a.harness_build)
    else:
        build = json.loads(a.candidate_builds.read_text())
        candidate = build["builds"]["candidate"]
        recorded = candidate["binaries"]["xray-rust"]
        rust_identity = {"commit": candidate["commit"], "tree": candidate["tree"],
                         "rustc": build["rustc"], "build_arguments": build["buildArguments"],
                         "incremental": False}
        harness = build_identity(a.harness_build) if a.harness_build else {
            **rust_identity, "sha256": candidate["binaries"]["xray-bench"]}
    if sha(a.candidate) != recorded:
        raise ValueError("Rust binary differs from its recorded clean build")
    if sha(a.harness) != harness["sha256"]:
        raise ValueError("driver binary differs from its recorded clean build")
    source = expected = None
    if a.singbox:
        source = json.loads(a.singbox_source.read_text())
        expected = {"Path": "github.com/sagernet/sing-box", "Version": "v1.13.20",
                    "Sum": "h1:2PfQuwVsV3rbvvOqoJOc1K2CY5xe5b9BL/TmIlGoCPE=",
                    "GoModSum": "h1:QkfLSGwPZB5adT5zF6PL6bPKRBVkS4tCIVv/zbM9WHA="}
        if any(source[k] != value for k, value in expected.items()) or source["Origin"]["Hash"] != SINGBOX:
            raise ValueError("sing-box source pin/checksum changed")
        # Check the build's module-cache source against its checksum-verified
        # module archive; do not trust a locally modified extracted source tree.
        with zipfile.ZipFile(source["Zip"]) as archive:
            prefix = source["Path"] + "@" + source["Version"] + "/"
            for item in archive.infolist():
                if item.is_dir():
                    continue
                if not item.filename.startswith(prefix):
                    raise ValueError("unexpected module archive entry")
                relative = Path(item.filename[len(prefix):])
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("invalid module archive path")
                if (Path(source["Dir"]) / relative).read_bytes() != archive.read(item):
                    raise ValueError("modified sing-box source: " + str(relative))
    go_info = {name: subprocess.check_output(["go", "version", "-m", str(getattr(a, name).resolve())], text=True)
               for name in references}
    if f"vcs.revision={XRAY}" not in go_info["xray"] or "vcs.modified=false" not in go_info["xray"]:
        raise ValueError("Xray must identify the exact clean reference commit")
    for name, info in go_info.items():
        if GO_RELEASES[name] not in info.splitlines()[0] or "CGO_ENABLED=0" not in info:
            raise ValueError(f"{name} requires a recorded {GO_RELEASES[name]} / CGO-disabled build")
    if a.singbox and "with_utls" not in go_info["singbox"]:
        raise ValueError("sing-box must include matching TLS fingerprint support")
    root = a.root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / "bin").mkdir()
    inputs = {}
    for name in ("candidate", "harness", *references):
        path = root / "bin" / name
        shutil.copy2(getattr(a, name), path)
        inputs[name] = {"path": str(path), "sha256": sha(path)}
    inputs["candidate"].update(rust_identity)
    inputs["harness"].update({k: harness[k] for k in rust_identity})
    inputs["xray"].update(commit=XRAY, version="26.11.9", build_info=go_info["xray"])
    if a.singbox:
        inputs["singbox"].update(commit=SINGBOX, version="1.13.20", build_info=go_info["singbox"],
                                  module_identity={**expected, "Origin": source["Origin"]},
                                  module_archive_sha256=sha(Path(source["Zip"])))
    (root / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    for name, info in go_info.items():
        (root / (name + "-build.txt")).write_text(info)
    print(root / "inputs.json")


if __name__ == "__main__":
    main()

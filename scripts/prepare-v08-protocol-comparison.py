#!/usr/bin/env python3
"""Freeze explicitly built clients and bind them to verified source metadata."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

XRAY = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
SINGBOX = "56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778"


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "candidate", "harness", "xray", "singbox", "candidate-builds", "singbox-source"):
        p.add_argument("--" + name, type=Path, required=True)
    p.add_argument("--harness-build", type=Path, help="separate driver build identity when its source differs from the engine")
    a = p.parse_args()
    build = json.loads(a.candidate_builds.read_text())
    candidate = build["builds"]["candidate"]
    for path, key in ((a.candidate, "xray-rust"),):
        if sha(path) != candidate["binaries"][key]:
            raise ValueError("Rust binary differs from its recorded clean build")
    rust_identity = {"commit": candidate["commit"], "tree": candidate["tree"],
                     "rustc": build["rustc"], "build_arguments": build["buildArguments"],
                     "incremental": False}
    harness = json.loads(a.harness_build.read_text()) if a.harness_build else {
        **rust_identity, "sha256": candidate["binaries"]["xray-bench"]}
    if sha(a.harness) != harness["sha256"]:
        raise ValueError("driver binary differs from its recorded clean build")
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
               for name in ("xray", "singbox")}
    if f"vcs.revision={XRAY}" not in go_info["xray"] or "vcs.modified=false" not in go_info["xray"]:
        raise ValueError("Xray must identify the exact clean reference commit")
    for name, info in go_info.items():
        if "go1.26.0" not in info.splitlines()[0] or "CGO_ENABLED=0" not in info:
            raise ValueError("both references require recorded Go 1.26.0 / CGO-disabled builds: " + name)
    if "with_utls" not in go_info["singbox"]:
        raise ValueError("sing-box must include matching TLS fingerprint support")
    root = a.root.resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / "bin").mkdir()
    inputs = {}
    for name in ("candidate", "harness", "xray", "singbox"):
        path = root / "bin" / name
        shutil.copy2(getattr(a, name), path)
        inputs[name] = {"path": str(path), "sha256": sha(path)}
    inputs["candidate"].update(rust_identity)
    inputs["harness"].update({k: harness[k] for k in rust_identity})
    inputs["xray"].update(commit=XRAY, version="26.7.28", build_info=go_info["xray"])
    inputs["singbox"].update(commit=SINGBOX, version="1.13.20", build_info=go_info["singbox"],
                              module_identity={**expected, "Origin": source["Origin"]},
                              module_archive_sha256=sha(Path(source["Zip"])))
    (root / "inputs.json").write_text(json.dumps(inputs, indent=2) + "\n")
    for name, info in go_info.items():
        (root / (name + "-build.txt")).write_text(info)
    print(root / "inputs.json")


if __name__ == "__main__":
    main()

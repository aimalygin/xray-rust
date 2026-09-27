#!/usr/bin/env python3
"""Loopback-only WireGuard fault comparison. No host TUN, routes or real keys."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]
REV = "dab390cdf9dcfb7a6fa85dd8798db92b681ad296"
SHA = "2a2745851b2989b6d388330b3b9ccfa180ecd12260014b708e01489abae02722"


def run(command, cwd=ROOT, env=None):
    subprocess.run([str(x) for x in command], cwd=cwd, env=env, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-root", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--archive", type=Path, required=True,
                        help="Checksum-pinned upstream archive; download separately")
    parser.add_argument("--repeats", type=int, default=100)
    parser.add_argument("--engine-repeats", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 1000 or not 1 <= args.engine_repeats <= 100:
        parser.error("repeats out of bounds")
    build = args.build_root.resolve()
    reports = args.report_dir.resolve()
    build.mkdir(parents=True, exist_ok=True)
    reports.mkdir(parents=True, exist_ok=True)
    assert hashlib.sha256(args.archive.read_bytes()).hexdigest() == SHA
    source = build / ("gotatun-" + REV)
    if source.exists():
        # Never use potentially edited prior reference sources.
        shutil.rmtree(source)
    with tarfile.open(args.archive) as archive:
        archive.extractall(build, filter="data")
    pristine = build / "pristine-vendor"
    if pristine.exists():
        shutil.rmtree(pristine)
    run(["python3", ROOT / "tools/wireguard-adapter-prototype/prepare_vendor.py", source, pristine])
    env = os.environ.copy()
    for key in ["XRAY_WIREGUARD_BINARY", "GOFLAGS", "GOEXPERIMENT"]:
        env.pop(key, None)
    env.update(GOENV="off", GOWORK="off", GOTOOLCHAIN="go1.26.5", CGO_ENABLED="0")
    run(["python3", ROOT / "scripts/verify-wireguard-reference.py"], env=env)
    module = ROOT / "tools/wireguard-reference"
    run(["go", "mod", "verify"], cwd=module, env=env)
    run(["go", "test", "-mod=readonly", "./..."], cwd=module, env=env)
    binary = build / "bin/wireguard-reference"
    binary.parent.mkdir(exist_ok=True)
    run(["go", "build", "-mod=readonly", "-trimpath", "-o", binary, "."], cwd=module, env=env)
    env["NATIVE_WIREGUARD_BINARY"] = str(binary)
    binaries = {"wireguard-go": binary}
    locks = {}
    for name, vendor, patched in [("pristine", pristine, False), ("patched", ROOT / "vendor/gotatun", True)]:
        package = build / (name + "-probe")
        package.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "tools/wireguard-timeout-probe/main.rs", package / "main.rs")
        # Seed both graphs with the same workspace versions, then resolve only
        # the stand-alone probe graph offline. Save its complete lockfile.
        shutil.copyfile(ROOT / "Cargo.lock", package / "Cargo.lock")
        manifest = f'''[package]
name = "wireguard-timeout-probe"
version = "0.0.0"
edition = "2024"
[workspace]
[features]
xray-patches = []
[[bin]]
name = "wireguard-timeout-probe"
path = "main.rs"
[dependencies]
bytes = "=1.12.1"
tokio = {{ version = "=1.52.3", features = ["rt", "macros", "net"] }}
gotatun = {{ path = {json.dumps(str(vendor))}, version = "=0.9.1", default-features = false, features = ["ring", "device"] }}
'''
        (package / "Cargo.toml").write_text(manifest)
        rust_env = dict(env, CARGO_TARGET_DIR=str(build / (name + "-target")))
        # The new probe package needs a lock graph entry. Cargo preserves the
        # seeded versions; generate-lockfile would instead re-resolve them.
        command = ["cargo", "+1.96.0", "build", "--offline"]
        if patched:
            command += ["--features", "xray-patches"]
        run(command, cwd=package, env=rust_env)
        import tomllib
        pinned = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
        actual = tomllib.loads((package / "Cargo.lock").read_text())["package"]
        identities = {(p["name"], p["version"], p.get("checksum")) for p in pinned}
        for dependency in actual:
            if dependency.get("source", "").startswith("registry+"):
                assert (dependency["name"], dependency["version"], dependency.get("checksum")) in identities, dependency["name"]
        engine = build / (name + "-target/debug/wireguard-timeout-probe")
        env[name.upper() + "_GOTATUN_BINARY"] = str(engine)
        binaries["gotatun-" + name] = engine
        shutil.copyfile(package / "Cargo.lock", reports / (name + "-probe-Cargo.lock"))
        locks[name] = hashlib.sha256((package / "Cargo.lock").read_bytes()).hexdigest()
    env.update(WIREGUARD_TIMEOUT_REPORT_DIR=str(reports),
               WIREGUARD_REFERENCE_VERBOSE="1",
               WIREGUARD_TIMEOUT_REPEATS=str(args.repeats),
               WIREGUARD_ENGINE_REPEATS=str(args.engine_repeats))
    identity = {
        "baseCommit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "workingTreeChanges": subprocess.check_output(["git", "status", "--short"], cwd=ROOT, text=True),
        "gotatunArchiveSha256": SHA, "gotatunCommit": REV, "lockfiles": locks,
        "binarySha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()},
        "repeats": args.repeats, "engineRepeats": args.engine_repeats,
        "scope": "Desktop loopback diagnostics; neither mobile acceptance nor throughput/RSS benchmark",
    }
    (reports / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
    run(["cargo", "test", "--locked", "-p", "xray-wireguard", "--test", "native_timeouts",
         "--test", "native_engine_timeouts", "--", "--ignored", "--nocapture", "--test-threads=1"], env=env)


if __name__ == "__main__":
    main()

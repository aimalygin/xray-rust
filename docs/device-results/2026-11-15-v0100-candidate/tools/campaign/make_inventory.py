#!/usr/bin/env python3
"""Writes inventory.json and SHA256SUMS for the 0.10.0 device-stand builds.

Run: /opt/homebrew/bin/python3.12 -I tools/make_inventory.py   (from anywhere)
Hashes every listed artifact now; refuses to write if any path is missing or a
recorded build-time SHA-256 differs from the file on disk.
"""
import hashlib
import json
import os
import subprocess
from pathlib import Path

O = Path("<stand>")
PERF = Path("<perf>")
WT = Path("<candidate-worktree>")
XSRC = Path("<release-dir>/xray-core/src")
XCODE = {**os.environ, "DEVELOPER_DIR": "/Applications/Xcode.app/Contents/Developer"}
HOME = Path.home()

CORE = {"repository": "aimalygin/xray-rust", "commit": "7eb199bba2562659fdbf0bcde9820e016dd8530c",
        "tree": "b637ff77211f6dc1aa865779d42b0325a7c7cc86", "version": "0.10.0",
        "ciRun": 43748376213, "ciRunNote": "full CI run on the candidate, running when the stand was built (the coordinator watches it)"}
SDK = {"repository": "aimalygin/xray-rust-mobile", "commit": "ff00a94a021529ed22dc70d4650a88a27c4482ee",
       "tree": "8f837a495eb53e0c969eb4ed0801a08e8e3ab508", "pullRequest": 52, "merged": False,
       "coreEnv": "release/core.env of PR #52's head pins the core candidate by commit and tree (XRAY_RUST_REF_KIND=commit); "
                  "the PR was open when the stand was built; scripts/build-apple.sh and fetch-core.sh unchanged since main f72f1b94"}
XRAY = {"repository": "XTLS/Xray-core", "version": "v26.11.9",
        "commit": "676eaf66f8f05d4d558ee7a74b4736623d3feeb9"}
BOTH = {"core": CORE, "sdk": SDK}


def run(*args, env=None):
    return subprocess.run(args, capture_output=True, text=True, env=env, check=True).stdout.strip()


def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def rel(path):
    path = Path(path)
    try:
        return str(path.relative_to(O))
    except ValueError:
        return str(path)


def entry(path, expect=None, **extra):
    path = Path(path)
    if not path.exists():
        raise SystemExit(f"missing: {path}")
    if path.is_dir():
        contents = []
        for p in sorted(x for x in path.rglob("*") if x.is_file() and not x.is_symlink()):
            contents.append({"path": str(p.relative_to(path)), "sha256": sha(p), "bytes": p.stat().st_size})
        listing = "".join(f"{c['sha256']}  {c['path']}\n" for c in contents)
        out = {"path": rel(path), "type": "directory",
               "bytes": sum(c["bytes"] for c in contents), "fileCount": len(contents),
               "contentsSHA256": hashlib.sha256(listing.encode()).hexdigest(),
               "contentsSHA256Definition": "sha256 of the lines '<sha256>  <relative path>\\n' over every regular file, sorted by path",
               "contents": contents}
    else:
        out = {"path": rel(path), "type": "file", "sha256": sha(path), "bytes": path.stat().st_size}
        if expect and out["sha256"] != expect:
            raise SystemExit(f"{path}: sha256 {out['sha256']} != recorded {expect}")
    out.update(extra)
    return out


def tools():
    rustc = run(str(HOME / ".cargo/bin/rustc"), "+1.96.0", "-vV")
    ndk = (HOME / "Library/Android/sdk/ndk/26.3.11579264/source.properties").read_text()
    wrapper = (WT / "platform/android/gradle/wrapper/gradle-wrapper.properties").read_text()
    agp = [line.strip() for line in (WT / "platform/android/build.gradle.kts").read_text().splitlines()
           if "com.android.application" in line]
    java_home = run("/usr/libexec/java_home", "-v", "17")
    return {
        "host": run("sw_vers", "-productName") + " " + run("sw_vers", "-productVersion") + " ("
                + run("sw_vers", "-buildVersion") + "), " + run("uname", "-m"),
        "rust": rustc.splitlines()[0] + "; " + [l for l in rustc.splitlines() if l.startswith("LLVM")][0],
        "cargo": run(str(HOME / ".cargo/bin/cargo"), "+1.96.0", "-V"),
        "xcode": " ".join(run("xcodebuild", "-version", env=XCODE).split()),
        "iphoneosSDK": run("xcrun", "--sdk", "iphoneos", "--show-sdk-version", env=XCODE),
        "androidNDK": [l for l in ndk.splitlines() if l.startswith("Pkg.Revision")][0].split("=")[1].strip(),
        "gradle": [l for l in wrapper.splitlines() if l.startswith("distributionUrl")][0].split("/")[-1],
        "androidGradlePlugin": agp[0] if agp else None,
        "jdk": subprocess.run([java_home + "/bin/java", "-version"], capture_output=True, text=True).stderr.splitlines()[0],
        "go": run(str(HOME / "sdk/go1.27.3/bin/go"), "version"),
        "python": run("/opt/homebrew/bin/python3.12", "--version"),
        "docker": "Docker Desktop server " + run("docker", "version", "--format", "{{.Server.Version}}")
                  + ", image xray-h3-bench:1 (id " + [l.split()[1] for l in run(
                      "docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.ID}}").splitlines()
                      if l.startswith("xray-h3-bench:1 ")][0] + "; rustc 1.96.0, Python 3.11.2)",
    }


def main():
    for checkout, ident in ((WT, CORE), (O / "candidate", CORE)):
        assert run("git", "-C", str(checkout), "rev-parse", "HEAD") == ident["commit"], checkout
        assert run("git", "-C", str(checkout), "rev-parse", "HEAD^{tree}") == ident["tree"], checkout
    assert run("git", "-C", str(XSRC), "rev-parse", "HEAD") == XRAY["commit"]

    artifacts = []
    add = artifacts.append

    # Host binaries the loopback check used (isolated builds of the performance campaign directory, made for this candidate).
    add(entry(PERF / "bin/candidate", "d9ba9b0e70e009059804094f799e16ac0bad83a8f3975083a131c0f963eb5eef",
              role="candidate CLI (host loopback client)", builtHere=True, builtFrom={"core": CORE},
              buildRecord=str(PERF / "build/candidate.json"),
              command="python3 scripts/build-isolated-release.py --rev 7eb199bb… --name candidate --campaign "
                      + str(PERF) + "  (cargo build --locked --release -p xray-cli in a fresh export)"))
    add(entry(PERF / "xray", "799824a3005d4a5d699cfdf9634e7601a48c33028884142e0fccf783692f322d",
              role="reference Xray-core v26.11.9, macOS arm64, CGO off, Go VCS stamp (fixture server for every LAN run)",
              builtHere=True, builtFrom={"xray": XRAY}, buildRecord=str(PERF / "builds.log"),
              command="CGO_ENABLED=0 go -C <pinned Xray-core checkout> build -o " + str(PERF / "xray") + " ./main"))

    # Linux reference builds and the WAN bundle.
    xgo = ("GOENV=off GOWORK=off CGO_ENABLED=0 GOOS=linux GOARCH={arch} GOCACHE=$HOME/Library/Caches/go-build GOMODCACHE=$HOME/go/pkg/mod "
           "GOPROXY=file://$HOME/go/pkg/mod/cache/download,https://proxy.golang.org "
           "$HOME/sdk/go1.27.3/bin/go -C " + str(XSRC) + " build -trimpath -buildvcs=false -o {out} ./main")
    add(entry(O / "wan/xray-linux-amd64", role="reference Xray-core v26.11.9 for a linux/amd64 WAN fixture host (pass --reference-sha256)",
              builtHere=True, builtFrom={"xray": XRAY}, script="wan/build-wan-bundle.sh", log="wan/build-wan-bundle.log",
              command=xgo.format(arch="amd64", out="wan/xray-linux-amd64")))
    add(entry(O / "wan/xray-linux-arm64", "a5771eb2911d82692c33c17d4c84b9af37f5cfe37d306880677bfdd21d5ea65d",
              role="reference Xray-core v26.11.9 for a linux/arm64 WAN fixture host; byte-identical to loopback/xicmp-reference/xray",
              builtHere=True, builtFrom={"xray": XRAY}, script="wan/build-wan-bundle.sh", log="wan/build-wan-bundle.log",
              command=xgo.format(arch="arm64", out="wan/xray-linux-arm64")))
    add(entry(O / "wan/candidate-scripts-7eb199bb.tar", role="the candidate's scripts/ for a WAN fixture host",
              builtHere=True, builtFrom={"core": CORE}, script="wan/build-wan-bundle.sh",
              command="git archive --format=tar --prefix=xray-rust-7eb199bb/ 7eb199bb… scripts"))
    add(entry(O / "loopback/xicmp-reference/xray", "a5771eb2911d82692c33c17d4c84b9af37f5cfe37d306880677bfdd21d5ea65d",
              role="xicmp loopback server (Linux container)", builtHere=True, builtFrom={"xray": XRAY},
              script="loopback/run-xicmp-docker.sh", log="loopback/run-xicmp-docker.log",
              command=xgo.format(arch="arm64", out="loopback/xicmp-reference/xray")))
    add(entry(O / "loopback/xicmp-client/xray-rust-linux-arm64", "40a342756acdcbc925d7ef31e3624ac62ed0650f43204fb745ca7ba4eb686820",
              role="candidate CLI built in the xray-h3-bench:1 container for the xicmp loopback (not a device stand)",
              builtHere=True, builtFrom={"core": CORE}, script="loopback/run-xicmp-docker.sh", log="loopback/run-xicmp-docker.log",
              command="docker run … xray-h3-bench:1: cargo fetch --locked && cargo build --locked --release -p xray-cli "
                      "(source: git archive of 7eb199bb mounted read-only)"))

    # Apple.
    ios_env = ("CARGO_INCREMENTAL=0 IPHONEOS_DEPLOYMENT_TARGET=15.0 TVOS_DEPLOYMENT_TARGET=17.0 MACOSX_DEPLOYMENT_TARGET=11.0 "
               "SOURCE_DATE_EPOCH=1794767954 TZ=UTC LC_ALL=C DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer "
               "CARGO_TARGET_DIR=<tmp> cargo +1.96.0 build --locked --manifest-path " + str(WT / "Cargo.toml")
               + " --package xray-ffi --target aarch64-apple-ios --release")
    add(entry(O / "apple/core-xcframework/ios-device/libxray_ffi.a", "48c013331baf6dd070d3c17e4730bf8fd6bfbd1034d1839e93271b4225fac5a3",
              role="xray-ffi static library, aarch64-apple-ios, release, iOS 15.0 (unstripped cargo output)",
              builtHere=True, builtFrom=BOTH, script="apple/build-ios-ffi.sh", log="apple/build-ios-ffi.log",
              command=ios_env,
              note="Environment of xray-rust-mobile scripts/build-apple.sh (unchanged at PR #52's head ff00a94a); the SDK's scripts/fetch-core.sh with "
                   "XRAY_RUST_SOURCE=<candidate clone> verified commit, tree, Cargo.lock, header and module map against release/core.env."))
    add(entry(O / "apple/core-xcframework/XrayRust.xcframework",
              role="core-shaped XCFramework (ios-arm64 slice with Headers), the binaryTarget platform/apple/Package.swift reads "
                   "from target/mobile/apple; linked into the Debug XrayClient app",
              builtHere=True, builtFrom=BOTH, script="(inline, see README)",
              command="xcodebuild -create-xcframework -library apple/core-xcframework/ios-device/libxray_ffi.a -headers "
                      + str(WT / "crates/xray-ffi/include") + " -output apple/core-xcframework/XrayRust.xcframework"))
    add(entry(O / "apple/sdk-xcframework/ios-device/libxray_ffi.a", "4fef32f82846b4ce5f56471123dda941f98dadc3abc2ac28bd1d69da3b125137",
              role="the same library with __LLVM,__bitcode and __LLVM,__cmdline removed, as the SDK's build-apple.sh does",
              builtHere=True, builtFrom=BOTH,
              command="rust-objcopy --remove-section=__LLVM,__bitcode --remove-section=__LLVM,__cmdline <copy of the library>",
              note="rust-objcopy is the llvm-objcopy of Rust 1.96.0's rustc component; the llvm-tools component the SDK script "
                   "asks for is not installed here."))
    add(entry(O / "apple/sdk-xcframework/XrayRust.xcframework",
              role="SDK-shaped XCFramework, ios-arm64 slice only, no headers (headers belong to the SDK's XrayRustFFI target)",
              builtHere=True, builtFrom=BOTH,
              command="xcodebuild -create-xcframework -library apple/sdk-xcframework/ios-device/libxray_ffi.a "
                      "-output apple/sdk-xcframework/XrayRust.xcframework"))
    add(entry(O / "apple/XrayClient.app",
              role="Debug XrayClient harness app with the Tunnel packet-tunnel extension, signed for development "
                   "(org.texforge.XrayClient, team <signing-team>, iOS Team Provisioning Profiles created 2026-11-02, expiring 2027-11-02, "
                   "which include the 0.9.0 iPhone)",
              builtHere=True, builtFrom=BOTH, script="apple/build-xrayclient-debug.sh", log="apple/build-xrayclient-debug.log",
              command="cd " + str(WT / "platform/apple/XrayClient") + " && DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer "
                      "xcodebuild -project XrayClient.xcodeproj -scheme XrayClient -configuration Debug "
                      "-destination generic/platform=iOS -derivedDataPath apple/ios-derived "
                      "XRAY_BUNDLE_ID_PREFIX=org.texforge DEVELOPMENT_TEAM=<signing-team> build; then ditto of "
                      "Build/Products/Debug-iphoneos/XrayClient.app to apple/XrayClient.app",
              inputs={"XCFramework": str(WT / "target/mobile/apple/XrayRust.xcframework") + " (copy of apple/core-xcframework)",
                      "geodata": "platform/apple/XrayClient/dat/geoip.dat b71d1999… and geosite.dat d6787cf3… copied from the main "
                                 "checkout; both equal the pins in the candidate's scripts/fetch-geodata.sh"}))

    # Android.
    android_libs = ("ANDROID_HOME=$HOME/Library/Android/sdk CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=<tmp> OUT_DIR=android/ffi "
                    + str(WT / "scripts/build-android-libs.sh"))
    add(entry(O / "android/ffi", role="XRAY_FFI_ANDROID_DIR: include/xray_ffi.h and jniLibs/<abi>/libxray_ffi.so for arm64-v8a, "
                                      "armeabi-v7a, x86, x86_64 (release, API 24, 16 KiB pages)",
              builtHere=True, builtFrom={"core": CORE}, script="android/build-android-ffi.sh", log="android/build-android-ffi.log",
              command=android_libs))
    apks = ("JAVA_HOME=$(/usr/libexec/java_home -v 17) ANDROID_HOME=$HOME/Library/Android/sdk XRAY_FFI_ANDROID_DIR=android/ffi "
            + str(WT / "platform/android/gradlew") + " -p " + str(WT / "platform/android")
            + " :devicehost:assembleDebug :deviceprobe:assembleDebug -PdeviceGateApplicationIdSuffix=.v010 "
              "-Pandroid.builder.sdkDownload=false --dependency-verification strict --no-daemon")
    add(entry(O / "android/devicehost-debug.apk", "5e3754317b0c7507afa12c78c42ff8686ad41c26658b6a18727d79a979069f67",
              role="Device Gate, package org.xrayrust.devicehost.v010, 4 ABIs, packs android/ffi's libxray_ffi.so byte for byte; "
                   "networkChangeRebindEnabled() = true, ACCESS_NETWORK_STATE and POST_NOTIFICATIONS in the manifest",
              builtHere=True, builtFrom={"core": CORE}, script="android/build-android-apks.sh", log="android/build-android-apks.log",
              command=apks + "; copied from devicehost/build/outputs/apk/debug/"))
    add(entry(O / "android/deviceprobe-debug.apk", "3bed4695e19527209da29aec267c7664a195e2f61d310de84867e929450a3aa1",
              role="Device Probe, package org.xrayrust.deviceprobe.v010", builtHere=True, builtFrom={"core": CORE},
              script="android/build-android-apks.sh", log="android/build-android-apks.log",
              command=apks + "; copied from deviceprobe/build/outputs/apk/debug/"))

    # Shared scenarios (added 2026-11-13, second request).
    shared_go = ("cd " + str(XSRC) + " && GOENV=off GOWORK=off GOCACHE=$HOME/Library/Caches/go-build GOMODCACHE=$HOME/go/pkg/mod "
                 "GOPROXY=file://$HOME/go/pkg/mod/cache/download,https://proxy.golang.org "
                 "$HOME/sdk/go1.27.3/bin/go build -mod=readonly -o {out} {src}")
    add(entry(O / "tools/shared/bin/vless-keys", "b883ae45a4542d0fcaa5df4439ec5a06913364ed5850094edd85ffbd7aa38f86",
              role="TOOLS/vless-keys of shared_fixture_v09.py (keypair x25519 for VLESS encryption)",
              builtHere=True, builtFrom={"core": CORE, "xray": XRAY}, script="tools/shared/build-shared-bins.sh",
              log="tools/shared/build-shared-bins.log",
              command=shared_go.format(out="tools/shared/bin/vless-keys",
                                       src="<candidate>/tools/vless-encryption-oracle/main.go")))
    add(entry(O / "tools/shared/bin/download-bridge-lan", "19958bbe1a05f5d17ed30d276d255176e9927627b0fe9b2667b22160698351ac",
              role="TOOLS/download-bridge-lan of shared_fixture_v09.py (XHTTP download bridge, listens on XRAY_FIXTURE_BIND)",
              builtHere=True, builtFrom={"core": CORE, "xray": XRAY}, script="tools/shared/build-shared-bins.sh",
              log="tools/shared/build-shared-bins.log",
              command=shared_go.format(out="tools/shared/bin/download-bridge-lan",
                                       src="<candidate>/tools/xhttp-download-oracle/main.go <candidate>/tools/xhttp-download-oracle/bridge.go")))
    add(entry(O / "apple/ios-projection-build-v010.patch",
              role="the change the iOS host-adapter-projection build carries: git diff after tools/shared/apply_ios_projection.py "
                   "on a detached checkout of the candidate (Debug probe and Debug sample provider only)",
              builtHere=True, builtFrom={"core": CORE}, script="apple/build-xrayclient-projection.sh",
              command="git -C apple/projection-src diff > apple/ios-projection-build-v010.patch"))
    add(entry(O / "apple/XrayClient-projection.app",
              role="second Debug XrayClient build for the iOS host-adapter-projection runs (0.9.0's projection build): "
                   "candidate + apple/ios-projection-build-v010.patch, the same core-shaped XCFramework and geodata, the same "
                   "signing (org.texforge.XrayClient, team <signing-team>); installing it replaces the main app",
              builtHere=True, builtFrom=BOTH, script="apple/build-xrayclient-projection.sh",
              log="apple/build-xrayclient-projection.log",
              patch="apple/ios-projection-build-v010.patch",
              command="git -C candidate worktree add --detach apple/projection-src 7eb199bb…; "
                      "python3.12 -I tools/shared/apply_ios_projection.py apple/projection-src; "
                      "cd apple/projection-src/platform/apple/XrayClient && DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer "
                      "xcodebuild -project XrayClient.xcodeproj -scheme XrayClient -configuration Debug "
                      "-destination generic/platform=iOS -derivedDataPath apple/ios-projection-derived "
                      "XRAY_BUNDLE_ID_PREFIX=org.texforge DEVELOPMENT_TEAM=<signing-team> build; then ditto of the product to "
                      "apple/XrayClient-projection.app"))

    sources = [
        {"path": "candidate", "what": "git clone of the local repository, detached at the core candidate, origin removed; "
                                      "the checkout every RUNBOOK command runs from", **CORE},
        {"path": "src/sdk-ff00a94a", "what": "git archive of the SDK commit (scripts/fetch-core.sh ran from here: src/fetch-core-sdk-ff00a94a.log)", **SDK},
        {"path": str(WT), "what": "this session's detached worktree of the core candidate; Apple and Android builds ran from it", **CORE},
        {"path": "apple/projection-src", "what": "git worktree of candidate/ at the core candidate with "
                                                 "apple/ios-projection-build-v010.patch applied (uncommitted); the projection app was built from it",
         **CORE},
    ]
    loopback = []
    for suite in ("v010", "smoke-v010", "import-v010", "legacy-v010", "xhttp-h3-v010", "xicmp", "smoke-v010-from-campaign-checkout",
                  "v010-vlessenc", "smoke-v010-vlessenc", "xicmp-vlessenc"):
        out = json.loads((O / "loopback" / suite / "results.json").read_text())
        loopback.append({"suite": out["summary"]["suite"], "workDir": "loopback/" + suite,
                         "host": "Linux arm64 container (Docker Desktop VM), root" if suite.startswith("xicmp") else "macOS arm64",
                         "vlessEncryption": suite.endswith("-vlessenc"),
                         "cases": out["summary"]["cases"], "failed": out["summary"]["failed"],
                         "passedCases": [r["case"] for r in out["results"] if r["result"] == "passed"]})

    shared_loopback = []
    for name, host in (("apple-shared", "macOS arm64"), ("apple-shared-asis", "macOS arm64"),
                      ("v09-protocols", "macOS arm64"), ("hold-close-v09", "macOS arm64"),
                      ("hold-close-v010", "macOS arm64"), ("hold-close-v010-xray-client", "macOS arm64")):
        out = json.loads((O / "loopback/shared" / name / "results.json").read_text())
        rows = out.get("results") or out.get("rows")
        shared_loopback.append({"run": name, "workDir": "loopback/shared/" + name, "host": host,
                                "summary": out["summary"], "rows": rows})
    for kept in ("dry-runs",):
        check(O / "loopback/shared" / kept)

    tool_files = sorted(p for p in (O / "tools").rglob("*") if p.is_file() and "bin" not in p.relative_to(O / "tools").parts
                        and "__pycache__" not in p.parts)
    tool_files += sorted(p for d in ("apple", "android", "wan", "loopback") for p in (O / d).glob("*.sh"))
    campaign_tools = [{"path": rel(p), "sha256": sha(p), "bytes": p.stat().st_size} for p in tool_files]

    inventory = {
        "candidate": CORE["commit"],
        "scope": "0.10.0 device-campaign stands, shared-scenario tools and host loopback checks, prepared 2026-11-15 for the fourth 0.10.0 candidate; no device was used",
        "core": CORE, "sdk": SDK, "reference": XRAY,
        "tools": tools(),
        "loopback": loopback,
        "sharedScenarioHostRuns": shared_loopback,
        "sources": sources,
        "artifacts": artifacts,
        "campaignTools": campaign_tools,
    }
    (O / "inventory.json").write_text(json.dumps(inventory, indent=2) + "\n")
    lines = []
    for a in artifacts:
        if a["type"] == "file":
            lines.append(f"{a['sha256']}  {a['path']}")
        else:
            lines += [f"{c['sha256']}  {a['path']}/{c['path']}" for c in a["contents"]]
    lines += [f"{t['sha256']}  {t['path']}" for t in campaign_tools]
    (O / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    print(f"{len(artifacts)} artifacts, {len(campaign_tools)} campaign tool files, {len(lines)} hashed files")


def check(path):
    if not Path(path).exists():
        raise SystemExit(f"missing: {path}")


if __name__ == "__main__":
    main()

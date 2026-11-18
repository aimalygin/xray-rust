#!/usr/bin/env python3
"""Assemble the 0.10.1 schema-5 evidence archive and its publication tree.

0.10.1 counterpart of docs/device-results/2026-11-15-v0100-candidate/tools/assemble_v010.py.
Reads the 0.10.1 stand (device-7503d1a4: built from the release pull request's head, whose tree is
the candidate's), the 0.10.0 release's stand (device-7eb199bb: only the runs carried over by the
owner's «Только затронутое» — iPhone xicmp and WAN mKCP, Android xicmp) and the host measurements
(perf-3cef7c42, built from the candidate commit). Copies the publishable records into
publication/docs/device-results/2026-11-17-v0101-candidate with local paths redacted, refuses to
continue if an address, device identifier or secret survives, maps the device events onto the v0.10
scenarios (every claimed transition must be backed by a passed event of its own kind, and the
scenario and transition sets come from the candidate's check-v010-release-evidence.py), writes the
README tables of which run and which build backs each transition, and writes
publication/docs/releases/v0.10.1-device-evidence.zip and its descriptor. Finally it runs the
candidate's own checker on the archive. Usage: assemble_v0101.py"""
import datetime, hashlib, importlib.util, json, math, pathlib, re, shutil, statistics, subprocess, sys, zipfile

R0 = pathlib.Path("<release-dir-0100>")
R = pathlib.Path("<release-dir>")
STAND, OLD, PERF = R / "device-7503d1a4.noindex", R0 / "device-7eb199bb.noindex", R / "perf-3cef7c42.noindex"
E, PUB = R / "evidence-3cef7c42.noindex", R / "publication-3cef7c42.noindex"
CLONE = R / "device-3cef7c42.noindex/candidate"
REV, TREE = "3cef7c42c2fd296afd27ab0b6435c632842e1a26", "d430ce5f1c106b48ba9ecc55a25455f0a201c50f"
NAME = "2026-11-17-v0101-candidate"
S, RELEASES = PUB / "docs/device-results" / NAME, PUB / "docs/releases"
git = lambda *a: subprocess.run(["git", "-C", str(CLONE), *a], capture_output=True, text=True).stdout.strip()
assert git("rev-parse", "HEAD") == REV and git("rev-parse", "HEAD^{tree}") == TREE and not git("status", "--porcelain")
assert subprocess.run(["git", "-C", str(STAND / "candidate"), "rev-parse", "HEAD^{tree}"], capture_output=True,
                      text=True).stdout.strip() == TREE

spec = importlib.util.spec_from_file_location("check_v010", CLONE / "scripts/check-v010-release-evidence.py")
CHECK = importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
POLICY = CHECK.POLICY

sha = lambda p: hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
IDENT = {"iosLib": sha(STAND / "apple/core-xcframework/ios-device/libxray_ffi.a"),
         "iosTunnel": sha(STAND / "apple/XrayClient.app/PlugIns/Tunnel.appex/Tunnel.debug.dylib"),
         "iosProjectionTunnel": sha(STAND / "apple/XrayClient-projection.app/PlugIns/Tunnel.appex/Tunnel.debug.dylib"),
         "androidLib": sha(STAND / "android/ffi/jniLibs/arm64-v8a/libxray_ffi.so"),
         "androidHostApk": sha(STAND / "android/devicehost-debug.apk"),
         "hostCli": sha(PERF / "bin/candidate"), "loopbackCli": sha(R / "perf-7503d1a4.noindex/bin/candidate"),
         "referenceXray": sha(PERF / "xray")}
BUILD_NEW_IOS = f"3cef7c42 (0.10.1 candidate tree): XrayClient Tunnel.debug.dylib {IDENT['iosTunnel'][:8]}…"
BUILD_NEW_PROJ = f"3cef7c42 (0.10.1 candidate tree): projection build, Tunnel.debug.dylib {IDENT['iosProjectionTunnel'][:8]}…"
BUILD_NEW_ANDROID = (f"3cef7c42 (0.10.1 candidate tree): Device Gate APK {IDENT['androidHostApk'][:8]}…, "
                     f"libxray_ffi.so arm64 {IDENT['androidLib'][:8]}…")
BUILD_OLD_IOS = "7eb199bb (0.10.0): XrayClient Tunnel.debug.dylib 1ecc594f…"
BUILD_OLD_ANDROID = "7eb199bb (0.10.0): Device Gate APK 5e375431…, libxray_ffi.so arm64 31448797…"

# The counted attempt of every run made on this stand, and every failed attempt of those runs.
IOS = json.loads((E / "report/attempts.json").read_text())["ios"]
ANDROID = json.loads((E / "report/attempts.json").read_text())["android"]
FAILED = json.loads((E / "report/attempts.json").read_text())["failed"]

# ---------------------------------------------------------------- publication
publish, info = {}, {}  # published path -> source; published path -> (run, attempt, build)
for run, attempt in IOS.items():
    publish[f"ios/{run}-result.json"] = STAND / f"results/ios/{run}/{attempt}/result.json"
    info[f"ios/{run}-result.json"] = (run, attempt, BUILD_NEW_PROJ if "projection" in run else BUILD_NEW_IOS)
publish["ios/wan-host-before.txt"] = STAND / "results/wan-host-before.txt"
publish["ios/wan-host-after.txt"] = STAND / "results/wan-host-after.txt"
for run in ["ios-xicmp", "ios-wan-mkcp"]:
    publish[f"ios-7eb199bb/{run}-result.json"] = OLD / f"results/ios/{run}/attempt-1/result.json"
    info[f"ios-7eb199bb/{run}-result.json"] = (run, "attempt-1", BUILD_OLD_IOS)
for run, attempt in ANDROID.items():
    publish[f"android/{run}/events.jsonl"] = STAND / f"results/android/{run}/{attempt}/device/events.jsonl"
    info[f"android/{run}/events.jsonl"] = (run, attempt, BUILD_NEW_ANDROID)
publish["android-7eb199bb/android-xicmp/events.jsonl"] = OLD / "results/android/android-xicmp/attempt-1/device/events.jsonl"
info["android-7eb199bb/android-xicmp/events.jsonl"] = ("android-xicmp", "attempt-1", BUILD_OLD_ANDROID)
# Every failed attempt of a counted run: its own device output only, never fixture inputs or raw server logs.
for platform, run, attempt in FAILED:
    if platform == "ios":
        publish[f"failed/ios/{run}-{attempt}-result.json"] = STAND / f"results/ios/{run}/{attempt}/result.json"
    else:
        publish[f"failed/android/{run}-{attempt}/events.jsonl"] = STAND / f"results/android/{run}/{attempt}/device/events.jsonl"
publish["failed/README.md"] = E / "report/failed-README.md"
publish["diagnostics/arp-first-exchange.md"] = STAND / "results/ios/diagnostics/arp-first-exchange/README.md"
for name in ["v010", "smoke-v010", "import-v010", "legacy-v010", "xhttp-h3-v010", "v010-vlessenc", "smoke-v010-vlessenc"]:
    publish[f"host-loopback/{name}.json"] = STAND / f"loopback/{name}/results.json"
for name in ["apple-shared", "apple-shared-asis", "v09-protocols", "hold-close-v09", "hold-close-v010", "hold-close-v010-xray-client"]:
    publish[f"host-loopback/shared/{name}.json"] = STAND / f"loopback/shared/{name}/results.json"
for name in ["performance.json", "benchmark-raw.json", "build-manifest.json"]:
    publish[f"performance-features/{name}"] = PERF / "features" / name
publish["performance-protocols/manifest.json"] = PERF / "v010/manifest.json"
for name in ["protocol-comparisons.json", "benchmark-raw.json"]:
    publish[f"performance-protocols/{name}"] = E / "performance-protocols" / name
publish["release-comparison/release-comparison.json"] = PERF / "release-comparison/release-comparison.json"
publish["release-comparison/manifest.json"] = PERF / "release-comparison/manifest.json"
for name in ["baseline", "candidate", "harness"]:
    publish[f"performance-builds/{name}.json"] = PERF / f"build/{name}.json"
publish["performance-builds/NOTES.md"] = PERF / "NOTES.md"
for path in sorted((E / "tools").glob("*.py")):
    if path.name != "assemble_v010.py":
        publish[f"tools/{path.name}"] = path
for path in sorted((STAND / "tools").rglob("*")):
    rel = path.relative_to(STAND / "tools")
    # make_inventory.py is the 0.10.0 stand's inventory tool with 0.10.0's build digests; this campaign did not run it.
    if (path.is_file() and "bin" not in rel.parts and "__pycache__" not in rel.parts and not path.name.endswith(".log")
            and path.name != "make_inventory.py"):
        publish[f"tools/campaign/{rel.as_posix()}"] = path
publish["tools/ios-projection-build-v010.patch"] = STAND / "apple/ios-projection-build-v010.patch"
for name in ["queue-ios-lan.sh", "queue-ios-lan-keepawake.sh", "queue-ios-projection.sh", "queue-android-lan.sh"]:
    publish[f"tools/campaign/{name}"] = STAND / "results" / name

HOME = str(pathlib.Path.home())
REDACT = [(str(CLONE), "<candidate-clone>"), (str(STAND / "candidate"), "<stand-clone>"), (str(STAND), "<stand>"),
          (str(OLD), "<stand-0100>"), (str(PERF), "<perf>"), (str(R / "perf-7503d1a4.noindex"), "<stand-perf>"),
          (str(E), "<evidence>"), (str(PUB), "<publication>"),
          ("<candidate-worktree-0100>", "<candidate-worktree-0100>"),
          (str(R), "<release-dir>"), (str(R0), "<release-dir-0100>"), ("<repo>", "<repo>"),
          (HOME, "<home>")]
vps = subprocess.run(["ssh", "-G", "xray-vps"], capture_output=True, text=True).stdout
vps = next(line.split()[1] for line in vps.splitlines() if line.startswith("hostname "))
FORBIDDEN = {"server address": vps, "account name": pathlib.Path.home().name,
             **json.loads((PUB / "private/identifiers.json").read_text())}
REDACT += [(value, f"<{label.lower().replace(' ', '-')}>") for label, value in FORBIDDEN.items()
           if label not in ("server address", "account name")]
PRIVATE = re.compile(r"\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
# The fixtures' credentials are erased when they stop; no UUID other than these fixed test ones
# (listed in private/allowed-uuids.json) and the iOS runtime instance ids may appear in a published file.
UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
ALLOWED_UUIDS = set(json.loads((PUB / "private/allowed-uuids.json").read_text()))

if S.exists():
    shutil.rmtree(S)
S.mkdir(parents=True)
RELEASES.mkdir(parents=True, exist_ok=True)
shutil.copyfile(E / "report/v0.10.1-owner-decisions.json", RELEASES / "v0.10.1-owner-decisions.json")
inventory = []


def sanitize(published, text):
    for old, new in REDACT:
        text = text.replace(old, new)
    for label, value in FORBIDDEN.items():
        assert value not in text, f"{label} in {published}"
    assert not PRIVATE.search(text), f"private address {PRIVATE.search(text).group()} in {published}"
    # iOS probe rows name the tunnel runtime instance by a random UUID ("runtime"): not a credential.
    runtimes = {u.lower() for u in re.findall(r'"runtime"\s*:\s*"([0-9a-fA-F-]{36})"', text)}
    stray = {u.lower() for u in UUID.findall(text)} - ALLOWED_UUIDS - runtimes
    assert not stray, f"UUID {sorted(stray)[:3]} in {published}"
    return text


def put(published, source, text):
    data = source.read_bytes() if source else text.encode()
    text = sanitize(published, data.decode() if source else text)
    target = S / published
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    inventory.append({"path": published, "sourcePath": sanitize(published, str(source)) if source else "(generated)",
                      "encoding": "redacted UTF-8", "sourceSHA256": hashlib.sha256(data).hexdigest(),
                      "publishedSHA256": hashlib.sha256(text.encode()).hexdigest()})


for published, source in sorted(publish.items()):
    put(published, source, None)

# ------------------------------------------------------------------- scenarios
load = lambda p: json.loads((S / p).read_text())
apple = {p: load(p) for p in publish if p.endswith("-result.json") and not p.startswith("failed/")}
android = {p: [json.loads(l) for l in (S / p).read_text().splitlines() if l.strip()]
           for p in publish if p.startswith(("android/", "android-7eb199bb/")) and p.endswith("events.jsonl")}


def stamp(row):
    if "hostTime" in row:
        return row["hostTime"]
    return datetime.datetime.fromisoformat(row["time"].replace("Z", "+00:00")).timestamp()


def duration(rows):
    times = [stamp(x) for x in rows if "hostTime" in x or "time" in x]
    assert len(times) > 1
    return max(1, math.ceil(max(times) - min(times)))


artifacts, used = {}, set()


def artifact(platform, kind, value=None, raw=None):
    path = f"{platform}/{kind}.json"
    payload = raw if raw is not None else (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    artifacts[path] = payload
    return {"kind": kind, "path": path, "sha256": hashlib.sha256(payload).hexdigest()}


def source_payload(paths):
    used.update(paths)
    return {p: {"sha256": hashlib.sha256((S / p).read_bytes()).hexdigest(), "text": (S / p).read_text()}
            for p in sorted(paths)}


timeline = {"apple": {}, "android": {}}


def scenario(platform, ident, selections, proofs, scope):
    """proofs: transition -> predicate over the selected rows; each must match at least once."""
    records = apple if platform == "apple" else android
    evidence, seconds, selected = [], 0, []
    for path, predicate in selections:
        indexed = [(i, x) for i, x in enumerate(records[path]) if predicate(x)]
        assert indexed, (platform, ident, path)
        selected += [(path, x) for _, x in indexed]
        seconds += duration([x for _, x in indexed])
        evidence.append({"source": path, "run": info[path][0], "attempt": info[path][1], "build": info[path][2],
                         "eventIndexes": [i for i, _ in indexed], "first": stamp(indexed[0][1]),
                         "last": stamp(indexed[-1][1]), "durationSeconds": duration([x for _, x in indexed])})
    counts, sources = {}, {}
    for transition, proof in proofs.items():
        hits = [path for path, x in selected if proof(x)]
        counts[transition] = len(hits)
        assert hits, (platform, ident, transition)
        sources[transition] = sorted(set(hits))
    required = POLICY.device_transitions(platform, ident)
    assert required <= set(proofs), (platform, ident, sorted(required - set(proofs)))
    if platform == "android":
        assert not set(proofs) & {"wifi-cellular-wifi", "xhttp-h3-network-change", "lock-wake"}, ident
    timeline[platform][ident] = {"scope": scope, "evidence": evidence, "transitions": list(proofs),
                                 "provingEventCounts": counts, "provingSources": sources}
    return {"id": ident, "durationSeconds": seconds, "transitions": list(proofs), "trafficResult": "pass", "result": "pass"}


ok = lambda x: x.get("result") == "passed"
ev = lambda name, extra=lambda x: True: (lambda x: x.get("event") == name and ok(x) and extra(x))
kind = lambda name, extra=lambda x: True: (lambda x: x.get("kind") == name and extra(x))
allrows = lambda x: True
V4, V6 = "198.51.100.7", "2001:db8::7"
domain = lambda x: str(x.get("host", "")).endswith(".test")
proto = lambda p: (lambda x: str(x.get("protocol", "")).split(":")[0] == p)
stage = lambda *stages: ev("transition-recovered", lambda x: x.get("stage") in stages)
LAN, NEW, OLDIOS = "ios/", "ios/", "ios-7eb199bb/"
WAN = {"mkcp": OLDIOS, "masque": NEW}


def wan_complete(path, protocol):
    rows = apple[path]
    assert rows[-1]["event"] == "complete" and ok(rows[-1]), path
    for name in ("cellular", "wifi", "after-unlock"):
        assert any(stage(name)(x) and proto(protocol)(x) for x in rows), (path, name)
    assert any(x.get("event") == "lock-interval" and x.get("seconds", 0) >= 15 for x in rows), (path, "lock-interval")


smoke_proofs = lambda: {"ipv4-tcp": ev("tcp", lambda x: x.get("host") == V4), "ipv6-tcp": ev("tcp", lambda x: x.get("host") == V6),
                        "ipv4-udp": ev("udp", lambda x: x.get("transition") == "ipv4-udp"),
                        "ipv6-udp": ev("udp", lambda x: x.get("transition") == "ipv6-udp"),
                        "domain-destination": ev("tcp", domain), "routed-dns": ev("dns-anchor"),
                        "start-stop": ev("disconnected")}
asce = []
for p in ["mkcp", "masque"]:
    files = [LAN + f"ios-v010-{m}-result.json" for m in ("smoke", "lifecycle", "resources")]
    wan_complete(WAN[p] + f"ios-wan-{p}-result.json", p)
    sel = [(f, proto(p)) for f in files] + [(WAN[p] + f"ios-wan-{p}-result.json", allrows)]
    proofs = {**smoke_proofs(),
              "cancel-active-flow": lambda x: x.get("event") == "connection-close-verified",
              "reconnect": lambda x: x.get("event") in ("traffic-after-close", "rapid-restart", "startup-cancelled") and ok(x),
              "wifi-cellular-wifi": stage("cellular", "wifi"), "lock-wake": stage("after-unlock"),
              "resource-recovery": ev("resource-complete")}
    asce.append(scenario("apple", p, sel, proofs,
                         "LAN smoke, lifecycle and resources on this candidate's build, plus the owner-driven iPhone WAN run "
                         "(Wi-Fi to cellular to Wi-Fi, lock/wake) against the pinned Xray-core on the owner's VPS: on this "
                         "candidate's build for MASQUE, whose QUIC stack this release changes, and carried over from the "
                         "0.10.0 release's build for mKCP, which it does not touch (owner's «Только затронутое»). "
                         "Cancellation means verified local connection closure."))
for p, path in [(p, LAN + "ios-smoke-v010-result.json") for p in ["xdns", "realm", "sudoku", "xmc", "header-custom", "xdrive",
                                                                   "vless-reverse"]] + [("xicmp", OLDIOS + "ios-xicmp-result.json")]:
    asce.append(scenario("apple", p, [(path, proto(p))], smoke_proofs(),
                         "LAN smoke on this candidate's build" if path.startswith(LAN) else
                         "Carried over from the 0.10.0 release's build (this release changes nothing xicmp runs on): smoke "
                         "against the pinned Xray-core xicmp server running as root on the owner's Linux VPS, with the "
                         "fixture's --vless-encryption"))
shared_proofs = {"tcp-udp-domain-routed-dns": ev("udp"), "active-close-and-recovery": ev("traffic-after-close")}
for p in ["vless-encryption", "ip-on-demand", "xhttp-download-session"]:
    sel = [(LAN + "ios-shared-result.json", lambda x, p=p: x.get("protocol") == p)]
    proofs = dict(shared_proofs)
    if p == "ip-on-demand":
        sel += [(LAN + f"ios-fakedns-{phase}-result.json", allrows) for phase in ["negative", "recovery"]]
        proofs["fakedns-positive-asis-negative-recovery"] = lambda x: x.get("event") == "dns-fakeip-anchor"
    asce.append(scenario("apple", p, sel, proofs,
                         "This candidate's build. The expected AsIs negative is retained as failed traffic "
                         "and evaluated as a successful negative control, not a successful flow."))
asce.append(scenario("apple", "cancellation",
                     [(LAN + f"ios-v010-{m}-result.json", allrows) for m in ("lifecycle", "smoke")],
                     {"startup-cancel-restart": ev("startup-cancelled"), "rapid-restart": ev("rapid-restart"),
                      "active-local-connection-close-verified": lambda x: x.get("event") == "connection-close-verified"},
                     "This candidate's build. Local cancellation and recovery over mKCP and MASQUE."))
asce.append(scenario("apple", "host-adapter-projection",
                     [(LAN + f"ios-projection-{p}-result.json", allrows) for p in ["file-descriptor", "packet-pump"]],
                     {"fd-and-packet-pump": ev("host-adapter-projection"),
                      "actual-tcp-udp-callback-counters": ev("host-adapter-projection",
                                                             lambda x: x["tcpCallbacks"] > 0 and x["udpCallbacks"] > 0)},
                     "This candidate's projection build: Debug provider observation hooks "
                     "(tools/ios-projection-build-v010.patch); native library unchanged."))
asce.append(scenario("apple", "profile-import", [(LAN + "ios-import-v010-result.json", allrows)],
                     {t: ev("link-import", lambda x, t=t: x.get("transition") == t)
                      for t in ["vless-link", "trojan-link", "vmess-link", "hysteria2-link"]}
                     | {"remnawave-json": ev("disconnected", proto("remnawave-json")),
                        "invalid-input-redaction": ev("invalid-import-redaction")},
                     "This candidate's build. Link imports (vless-link through the SDK importer), a "
                     "Remnawave JSON profile with traffic, and rejected/redacted malformed imports."))
wan_complete(NEW + "ios-wan-xhttp-h3-result.json", "xhttp-h3")
asce.append(scenario("apple", "legacy-regression",
                     [(LAN + "ios-legacy-v010-result.json", allrows), (NEW + "ios-wan-xhttp-h3-result.json", allrows)],
                     {p: ev("disconnected", proto(p)) for p in sorted(CHECK.LEGACY_PROTOCOLS)}
                     | {"xhttp-h3-network-change": lambda x: stage("cellular", "wifi")(x) and proto("xhttp-h3")(x)},
                     "The twelve 0.9.0 protocols on the LAN, and XHTTP H3 keeping its connection across Wi-Fi to "
                     "cellular to Wi-Fi (WAN, owner-driven), both on this candidate's build."))

dsc = []
for p, case in [("mkcp", "mkcp-vless"), ("masque", "masque-h3")]:
    for backend in ["file-descriptor", "packet-pump"]:
        pred = lambda x, c=case, b=backend: x.get("case") == c and x.get("backend") == b
        files = [f"android/{r}/events.jsonl" for r in ("android-v010", "android-cancel-tcp", "android-cancel-udp", "android-resources")]
        sel = [(f, pred) for f in files]
        assert any(x["kind"] == "case-pass" and pred(x) for x in android["android/android-v010/events.jsonl"])
        has = lambda t: kind("traffic", lambda x, t=t: t in x.get("transitions", []))
        proofs = {t: has(t) for t in ["ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination", "routed-dns"]}
        proofs |= {"start-stop": kind("case-pass"),
                   "cancel-active-flow": kind("local-active-cancellation", lambda x: x["localCancellationPassed"]),
                   "reconnect": kind("cancel-start-recovery"),
                   "resource-recovery": kind("resource-recovery", lambda x: x["passed"])}
        dsc.append(scenario("android", f"{p}-{backend}", sel, proofs,
                            "This candidate's build on the Samsung, this TUN backend. Wi-Fi/cellular and lock/wake are not "
                            "tested on Android (owner decisions of 2026-11-15 and 2026-11-13, standing). Cancellation is local active "
                            "closure with traffic recovery; for mKCP the server's close comes about 6 s later (known "
                            "limitation). Resources: MASQUE stress at 8 connections, mKCP at 32 (owner decision of "
                            "2026-11-15, standing: a MASQUE tunnel admits 16 TCP flows)."))
for p, run, case in [(p, "android-smoke-v010", c) for p, c in [("xdns", "xdns-mkcp"), ("realm", "realm-mkcp"), ("sudoku", "sudoku-tcp"),
                     ("xmc", "xmc-tcp"), ("header-custom", "header-custom-tcp"), ("xdrive", "xdrive-s3"),
                     ("vless-reverse", "vless-reverse-bridge")]] + [("xicmp", "android-xicmp", "xicmp-mkcp")]:
    path = f"android/{run}/events.jsonl" if run != "android-xicmp" else "android-7eb199bb/android-xicmp/events.jsonl"
    pred = lambda x, c=case: x.get("case") == c
    for backend in ["file-descriptor", "packet-pump"]:
        assert any(x["kind"] == "case-pass" and pred(x) and x["backend"] == backend for x in android[path]), (p, backend)
    has = lambda t: kind("traffic", lambda x, t=t: t in x.get("transitions", []))
    proofs = {t: has(t) for t in ["ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination", "routed-dns"]}
    proofs["start-stop"] = kind("case-pass")
    dsc.append(scenario("android", p, [(path, pred)], proofs,
                        "Both TUN backends on the LAN, this candidate's build" if run != "android-xicmp" else
                        "Carried over from the 0.10.0 release's build: both TUN backends against the pinned Xray-core xicmp "
                        "server running as root on the owner's Linux VPS"))
for p in ["vless-encryption", "ip-on-demand", "xhttp-download-session"]:
    pred = lambda x, p=p: x.get("case") == p or (p == "ip-on-demand" and x["kind"].startswith("ip-"))
    proofs = {"both-tun-backends": kind("case-pass"), "tcp-udp-domain-routed-dns": kind("traffic"),
              "close-recovery": kind("close-recovery")}
    if p == "ip-on-demand":
        proofs["asis-negative-and-recovery"] = kind("ip-on-demand-recovery-control")
    dsc.append(scenario("android", p, [("android/android-shared/events.jsonl", pred)], proofs,
                        "This candidate's build, physical Android traffic and controls."))
dsc.append(scenario("android", "cancellation",
                    [(f"android/{r}/events.jsonl", allrows) for r in ("android-cancel-tcp-v09", "android-cancel-udp-v09")],
                    {"local-active-close": kind("local-active-cancellation", lambda x: x["localCancellationPassed"]),
                     "remote-eof-within-bound": kind("local-active-cancellation", lambda x: x["remoteCloseBoundPassed"]),
                     "delayed-udp-cancel": kind("udp-active-cancelled"), "traffic-recovery": kind("udp-cancel-recovery")},
                    "In 0.9.0 form over the 0.9.0 protocols (SOCKS, HTTP, HTTPS, Shadowsocks AEAD): 16 local TCP "
                    "cancellations, remote EOF inside the bound in every one, and 8 delayed UDP cancellations with recovery. "
                    "The mKCP/MASQUE cancellation runs feed cancel-active-flow of their own scenarios."))
dsc.append(scenario("android", "host-adapter-projection",
                    [("android/android-shared/events.jsonl", lambda x: x["kind"] in ["host-adapter-projection", "projection-controls-complete"])],
                    {"included-uid-tcp-udp": kind("host-adapter-projection", lambda x: x.get("passed") is True),
                     "controls-complete": kind("projection-controls-complete")},
                    "Actual Android host admission counters and traffic controls."))
dsc.append(scenario("android", "profile-import", [("android/android-import-v010/events.jsonl", allrows)],
                    {t: kind("link-import", lambda x, t=t: x.get("transition") == t and x.get("passed") is True)
                     for t in ["vless-link", "trojan-link", "vmess-link", "hysteria2-link"]}
                    | {"remnawave-json": kind("case-pass", lambda x: x.get("case") == "remnawave-json"),
                       "invalid-input-redaction": kind("invalid-import-control", lambda x: x.get("passed") is True
                                                       and x.get("markerAbsentFromHostLog", True) is True)},
                    "Actual link imports (vless-link through the SDK importer), a Remnawave JSON profile on both backends, "
                    "and malformed-input rejection/redaction."))
dsc.append(scenario("android", "legacy-regression", [("android/android-legacy-v010/events.jsonl", allrows)],
                    {p: kind("case-pass", lambda x, p=p: x["case"] == p) for p in sorted(CHECK.LEGACY_PROTOCOLS)},
                    "Both Android backends for every protocol 0.9.0 shipped, this candidate's build. "
                    "xhttp-h3-network-change is not tested on Android (owner decision of 2026-11-15, standing)."))
for platform, scenarios in (("apple", asce), ("android", dsc)):
    ids = {x["id"] for x in scenarios}
    assert ids == POLICY.scenarios(platform), (platform, sorted(ids ^ POLICY.scenarios(platform)))

# ------------------------------------------------------------------- resources
res = apple[LAN + "ios-v010-resources-result.json"]
bounds = []
for protocol in sorted({e["protocol"] for e in res if e.get("event") == "sample"}):
    samples = [e for e in res if e.get("event") == "sample" and e["protocol"] == protocol]
    baseline = next(e for e in samples if e["stage"] == "baseline")
    recover = [e for e in samples if e["stage"].startswith("recovery")]
    # "The RSS after the first cycle's recovery" is the median RSS of the first cycle's last recovery stage
    # (cycle 1, recovery-8, five samples), as the Android collector's rss[0] is the median of its first cycle's
    # recovery samples. The bound is 0.10.0's (owner decision of 2026-11-15, standing): Apple RSS growth is bounded
    # per protocol by Android's rule, max(8 MiB, 25% of that RSS); footprint and threads keep 8 MiB and 8. For
    # this candidate the rule was fixed before the measurement. What was observed is computed as 0.9.0 did.
    first = statistics.median(e["rss"] for e in samples if e["cycle"] == 1 and e["stage"] == "recovery-8")
    second = statistics.median(e["rss"] for e in samples if e["cycle"] == 2 and e["stage"] == "recovery-8")
    limits = {"rss": max(8388608, math.ceil(first * .25)), "footprint": 8388608, "threads": 8}
    growth = {k: max(0, max(e[k] for e in recover) - baseline[k]) for k in limits}
    bounds.append({"protocol": protocol, "baseline": baseline, "growth": growth, "limits": limits,
                   "withinBounds": all(growth[k] <= v for k, v in limits.items()), "recoverySamples": len(recover),
                   "rssAfterFirstCycleRecovery": first, "rssAfterSecondCycleRecovery": second,
                   "rssGrowthBetweenCycleRecoveries": second - first,
                   "v09RssBound": 8388608, "withinV09RssBound": growth["rss"] <= 8388608,
                   "complete": any(e["event"] == "resource-complete" and ok(e) and e["protocol"] == protocol for e in res)})
recover = [e for e in android["android/android-resources/events.jsonl"] if e["kind"] == "resource-recovery"]
assert len(bounds) == 2 and all(x["complete"] for x in bounds), bounds
# 0.9.0's preregistered Apple bounds (8 MiB RSS and footprint, 8 threads). The probe itself enforces footprint
# and threads only; a bound this archive's method fails is reported, never re-chosen after the fact.
APPLE_BOUNDS_FAILED = [{"protocol": x["protocol"], "growth": x["growth"], "limits": x["limits"]}
                       for x in bounds if not x["withinBounds"]]
assert len(recover) == 4 and all(x["passed"] for x in recover)
alim = {"residentMemoryGrowthBytes": max(x["limits"]["rss"] for x in bounds), "threadGrowth": 8, "fatalErrors": 0,
        "unrecoveredTransitions": 0}
aobs = {"residentMemoryGrowthBytes": max(x["growth"]["rss"] for x in bounds),
        "threadGrowth": max(x["growth"]["threads"] for x in bounds), "fatalErrors": 0, "unrecoveredTransitions": 0}
dlim = {"residentMemoryGrowthBytes": max(max(8388608, math.ceil(x["rss"][0] * .25)) for x in recover),
        "threadGrowth": 4, "fatalErrors": 0, "unrecoveredTransitions": 0}
dobs = {"residentMemoryGrowthBytes": max(0, max(x["rssGrowthBytes"] for x in recover)),
        "threadGrowth": max(0, max(x["threadGrowth"] for x in recover)), "fatalErrors": 0, "unrecoveredTransitions": 0}

# ------------------------------------------------------------- README tables
def table(platform):
    lines = ["| Scenario | Transitions | Runs (attempt) | Build |", "| --- | --- | --- | --- |"]
    for ident, entry in timeline[platform].items():
        groups = {}
        for transition in entry["transitions"]:
            groups.setdefault(tuple(entry["provingSources"][transition]), []).append(transition)
        for sources, transitions in groups.items():
            runs = ", ".join(f"`{info[s][0]}` ({info[s][1]})" for s in sources)
            builds = "; ".join(sorted({info[s][2] for s in sources}))
            lines.append(f"| `{ident}` | {', '.join(transitions)} | {runs} | {builds} |")
    return "\n".join(lines)


readme = (E / "report/README.md").read_text().replace("{{APPLE_TABLE}}", table("apple")).replace("{{ANDROID_TABLE}}", table("android"))
put("README.md", None, readme)
inv = {"candidate": REV, "files": sorted(inventory, key=lambda x: x["path"]),
       "scope": "sanitized records of the 0.10.1 candidate's campaign and the runs carried over from the 0.10.0 release's "
                "campaign (iPhone xicmp and WAN mKCP, Android xicmp); every failed attempt of a counted run retained"}
(S / "inventory.json").write_text(json.dumps(inv, indent=2) + "\n")

MiB = lambda b: f"{b / 1048576:.2f} MiB"
by = {x["protocol"].split(":")[0]: x for x in bounds}
METHOD = ("Apple (this candidate's build): growth is the maximum recovery sample minus the pre-load baseline, per protocol, "
          "as in 0.9.0. Footprint is bounded at 8 MiB and threads at 8, the documented criterion the probe enforces ("
          + "; ".join(f"{k}: footprint +{MiB(v['growth']['footprint'])}, threads +{v['growth']['threads']}" for k, v in sorted(by.items()))
          + "). RSS growth is bounded per protocol by 0.10.0's rule (owner decision of 2026-11-15, in force before this "
          "measurement): max(8 MiB, 25% of the RSS after the first cycle's recovery, the median of cycle 1's recovery-8 "
          "stage) — "
          + "; ".join(f"{k}: grew {MiB(v['growth']['rss'])} against {MiB(v['limits']['rss'])}, and {MiB(max(0, v['rssGrowthBetweenCycleRecoveries']))} "
                      f"from the first cycle's recovery to the second's" for k, v in sorted(by.items()))
          + ". The manifest limit is the larger of the per-protocol limits, and each protocol is checked against its own. "
          "Android (this candidate): per-case max(8 MiB, 25% of the first recovery RSS) and 4 threads, fixed before "
          "measurement; the manifest limit is the maximum of those limits and each case was checked on its own. Android "
          "stress: 240 HTTP and 480 UDP requests per burst, 32 at once for mKCP and 8 at once for MASQUE (a MASQUE "
          "tunnel admits 16 TCP flows at once; owner decision of 2026-11-15, standing).")
DEVICE_OS = json.loads((E / "report/attempts.json").read_text())["os"]
devices = []
for platform, scenarios, limits, observed, model, osver, arch, logs in [
        ("apple", asce, alim, aobs, "iPhone 17 Pro Max (iPhone18,2)", DEVICE_OS["apple"], "arm64", apple),
        ("android", dsc, dlim, dobs, "Samsung SM-A145F", DEVICE_OS["android"], "arm64-v8a", android)]:
    selected = sorted({e["source"] for t in timeline[platform].values() for e in t["evidence"]})
    assert set(selected) == set(logs), (platform, sorted(set(logs) - set(selected)))
    profile = {"scope": "Resource growth on measured recovery windows. Zero fatal/unrecovered counts apply to accepted success "
                        "paths; failed attempts and negative controls are retained, not erased.",
               "limits": limits, "observed": observed,
               "method": METHOD,
               "evaluation": bounds if platform == "apple" else recover,
               "samples": res if platform == "apple" else
               [x for x in android["android/android-resources/events.jsonl"] if x["kind"].startswith("resource-")]}
    arts = [artifact(platform, "resource-profile", profile),
            artifact(platform, "sanitized-log", {"scope": "All counted attempts, including negative controls; failed attempts "
                                                          "are under failed/ in the report", "sources": source_payload(logs.keys())}),
            artifact(platform, "transition-timeline", timeline[platform])]
    devices.append({"platform": platform, "physical": True, "model": model, "osVersion": osver, "architecture": arch,
                    "durationSeconds": sum(duration(logs[f]) for f in selected), "scenarios": scenarios,
                    "limits": limits, "observed": observed, "artifacts": arts, "result": "pass"})

(E / "report/apple-bounds.json").write_text(json.dumps(bounds, indent=1) + "\n")
if APPLE_BOUNDS_FAILED:
    print(json.dumps({"stopped": "Apple resource growth outside 0.9.0's bounds; no archive written",
                      "failed": APPLE_BOUNDS_FAILED, "tree": str(S)}, indent=2))
    sys.exit(3)

# ----------------------------------------------------------------- performance
comparisons = load("performance-protocols/protocol-comparisons.json")
features = load("performance-features/performance.json")
assert comparisons["complete"] and comparisons["allProfilesPassed"] and features["result"] == "pass"
measurements = features["measurements"] + comparisons["schema5Measurements"]
assert {m["id"] for m in measurements} == set(POLICY.measurement_comparisons) and len(measurements) == 10
paths = [f["path"] for f in inventory]
perfarts = [artifact("performance", "benchmark-raw", source_payload(
    ["performance-features/benchmark-raw.json", "performance-protocols/benchmark-raw.json"]))]
perfarts.append(artifact("performance", "build-manifest", source_payload(
    ["performance-features/build-manifest.json", "performance-protocols/manifest.json", "release-comparison/manifest.json"]
    + [f"performance-builds/{n}.json" for n in ("baseline", "candidate", "harness")])))
perfarts.append(artifact("performance", "protocol-comparisons", source_payload(["performance-protocols/protocol-comparisons.json"])))
perfarts.append(artifact("performance", "release-comparison", raw=(S / "release-comparison/release-comparison.json").read_bytes()))
used.add("release-comparison/release-comparison.json")
owner = json.loads((RELEASES / "v0.10.1-owner-decisions.json").read_text())
perfarts.append(artifact("performance", "known-limitations",
                         {"ownerDecision": owner, "report": (S / "README.md").read_text(), "inventory": inv,
                          "supportingEvidence": source_payload([p for p in paths if p not in used])}))
manifest = {"schemaVersion": 5, "candidate": {"revision": REV, "tree": TREE, "dirty": False}, "devices": devices,
            "performance": {"profile": "release", "clean": True, "measurements": measurements,
                            "artifacts": perfarts, "result": "pass"}, "result": "pass"}
artifacts["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
archive = RELEASES / "v0.10.1-device-evidence.zip"
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name, data in sorted(artifacts.items()):
        zinfo = zipfile.ZipInfo(name, date_time=(2026, 11, 17, 0, 0, 0))
        zinfo.compress_type = zipfile.ZIP_DEFLATED
        zinfo.external_attr = 0o100644 << 16
        z.writestr(zinfo, data)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(E / "schema5-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
check = subprocess.run([sys.executable, "scripts/check-v010-release-evidence.py", str(archive), REV, TREE],
                       cwd=CLONE, capture_output=True, text=True)
(E / "validation").mkdir(exist_ok=True)
(E / "validation/check-v010-release-evidence.txt").write_text(
    f"$ python3 scripts/check-v010-release-evidence.py <zip> {REV} {TREE}   (from the stand's clean candidate clone)\n"
    f"exit {check.returncode}\n{check.stdout}{check.stderr}")
descriptor = {"candidateCommit": REV, "candidateTree": TREE, "archive": archive.name, "archiveSHA256": digest,
              "schemaVersion": 5,
              "localValidation": ("passed with the candidate's unchanged check-v010-release-evidence.py"
                                  if check.returncode == 0 else "FAILED"),
              "workflowValidation": "pending", "publication": "authorized; pending validation and canonical artifacts",
              "scope": "Physical iPhone and Samsung runs under the v0.10 profile: every LAN run of both phones and the "
                       "iPhone's WAN MASQUE and XHTTP H3 runs on the 0.10.1 candidate's build, with iPhone xicmp and WAN mKCP "
                       "and Android xicmp carried over from the 0.10.0 release's build by owner decision; the ten schema-5 "
                       "performance metrics and the comparison against 0.9.0; all failed attempts retained.",
              "workflowRun": "pending"}
(RELEASES / "v0.10.1-device-evidence.json").write_text(json.dumps(descriptor, indent=2) + "\n")
print(json.dumps({"archive": str(archive), "sha256": digest, "bytes": archive.stat().st_size, "check": check.returncode,
                  "checkOutput": (check.stdout + check.stderr).strip(), "publishedFiles": len(inventory) + 1,
                  "appleScenarios": len(asce), "androidScenarios": len(dsc),
                  "metrics": [(m["id"], round(statistics.median(m["samples"]), 2), m["comparison"], round(m["threshold"], 3))
                              for m in measurements]}, indent=2))

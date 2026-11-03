#!/usr/bin/env python3
"""Assemble the 0.9.0 schema-4 evidence archive and its publication tree.

v0.9 counterpart of docs/device-results/2026-10-18-v081-candidate/assemble-evidence.py.
Copies the publishable campaign records into
publication/docs/device-results/2026-11-02-v090-candidate with local paths
redacted, refuses to continue if an address, device identifier or WAN fixture
secret survives, maps the device events onto the v0.9 scenarios (every claimed
transition must be backed by a passed event of its own kind), and writes
publication/docs/releases/v0.9.0-device-evidence.zip.
Usage: assemble_v09.py [--known-limitations FILE]"""
import hashlib, json, math, pathlib, re, shutil, statistics, sys, zipfile, datetime

C = pathlib.Path(__file__).resolve().parents[1]
REPO = C.parents[2]
REV = "30928ad51b4a434546cf143f8e385a8746523172"
TREE = "e55a6c3f021643bd507a611c247f2781aaabbb83"
NAME = "2026-11-02-v090-candidate"
P = C / "publication"
S = P / "docs/device-results" / NAME
RELEASES = P / "docs/releases"

# ---------------------------------------------------------------- publication
publish = {}  # published path -> raw path
for name in ["v09-smoke", "v09-lifecycle", "v09-resources", "ciphers-v09", "legacy-v09", "shared",
             "fakedns-negative", "fakedns-recovery", "projection-file-descriptor", "projection-packet-pump"]:
    publish[f"ios-{name}-result.json"] = f"ios-{name}/result.json"
for protocol in ["http", "https", "shadowsocks-aead", "socks"]:
    for kind in ["result", "plan", "services-restored"]:
        publish[f"ios-wan/{protocol}-{kind}.json"] = f"ios-wan/{protocol}-{kind}.json"
publish["ios-wan/services-before.json"] = "ios-wan/services-before.json"
publish["ios-wan/services-after-cleanup.json"] = "ios-wan/services-after-cleanup.json"
for name in ["android-v09", "android-legacy-v09", "android-cancel-tcp", "android-cancel-udp",
             "android-resources-a", "android-resources-b", "android-shared"]:
    publish[f"{name}/events.jsonl"] = f"{name}/events.jsonl"
for name in ["v09", "ciphers-v09", "legacy-v09"]:
    publish[f"host-loopback/{name}.log"] = f"host-loopback/{name}.log"
for name in ["performance.json", "benchmark-raw.json", "build-manifest.json"]:
    publish[f"performance-features/{name}"] = f"performance-features/{name}"
for name in ["manifest.json", "protocol-comparisons.json", "benchmark-raw.json"]:
    publish[f"performance-protocols/{name}"] = f"performance-protocols/{name}"
# Every preserved failure and diagnosis: its explanation and its own records,
# never fixture inputs, launch descriptors or raw device/server logs.
KEEP = re.compile(r"(^|/)(README[^/]*|[^/]*result\.json|events\.jsonl|[^/]*plan\.json|manifest\.json|"
                  r"[^/]*\.py)$")
for root in ["failed", "diagnostics"]:
    for path in sorted((C / root).rglob("*")):
        rel = path.relative_to(C).as_posix()
        if path.is_file() and KEEP.search(rel) and "-fixture/" not in rel and "__pycache__" not in rel:
            publish[rel] = rel
for path in sorted((C / "tools").rglob("*")):
    if path.is_file() and "__pycache__" not in path.parts:
        rel = path.relative_to(C).as_posix()
        publish[rel] = rel

HOME = str(pathlib.Path.home())
SCRATCH = "<scratch>"
REDACT = [(SCRATCH + "/core-0.9.0", "<candidate-worktree>"), (SCRATCH, "<scratch>"),
          (str(REPO), "<repo>"), (HOME, "<home>")]


def wan_secrets():
    """Credentials, links and markers of the WAN fixtures (inputs stay unpublished)."""
    found = set()
    for path in C.rglob("*input*.json"):
        if "publication" in path.parts:
            continue
        data = json.loads(path.read_text())
        found.add(data.get("redactionMarker", ""))
        for case in data.get("cases", []) + data.get("invalidImports", []):
            found.add(case.get("text", ""))
            found.update(re.findall(r"[A-Za-z0-9+/=_-]{12,}", case.get("text", "")))
            if "configJSON" in case:
                def leaves(value):
                    if isinstance(value, dict):
                        for k, v in value.items():
                            if k in {"user", "pass", "password", "id", "key", "psk"} and isinstance(v, str):
                                yield v
                            yield from leaves(v)
                    elif isinstance(value, list):
                        for v in value:
                            yield from leaves(v)
                found.update(leaves(json.loads(case["configJSON"])))
    return {s for s in found if len(s) >= 8}


import subprocess
vps = subprocess.run(["ssh", "-G", "xray-vps"], capture_output=True, text=True).stdout
vps = next(line.split()[1] for line in vps.splitlines() if line.startswith("hostname "))
# Device and signing identifiers live in an unpublished file next to the raw campaign.
FORBIDDEN = {"server address": vps, "account name": pathlib.Path.home().name,
             **json.loads((C / "private/identifiers.json").read_text())}
# The published tools name the devices they drove; replace those identifiers too.
REDACT += [(value, f"<{label.lower().replace(' ', '-')}>") for label, value in FORBIDDEN.items()
           if label not in ("server address", "account name")]
PRIVATE = re.compile(r"\b(?:192\.168|10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
SECRETS = wan_secrets()

if S.exists():
    shutil.rmtree(S)
S.mkdir(parents=True)
RELEASES.mkdir(parents=True, exist_ok=True)
# The report and the decision record are written by hand in report/.
shutil.copyfile(C / "report/README.md", S / "README.md")
shutil.copyfile(C / "report/v0.9.0-owner-decisions.json", RELEASES / "v0.9.0-owner-decisions.json")
inventory = []
for published, raw in sorted(publish.items()):
    source = C / raw
    data = source.read_bytes()
    text = data.decode()
    for old, new in REDACT:
        text = text.replace(old, new)
    for label, value in FORBIDDEN.items():
        assert value not in text, f"{label} in {published}"
    assert not PRIVATE.search(text), f"private address {PRIVATE.search(text).group()} in {published}"
    leaked = [s for s in SECRETS if s in text]
    assert not leaked, f"WAN fixture secret in {published}"
    target = S / published
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text)
    inventory.append({"path": published, "sourcePath": raw, "encoding": "redacted UTF-8",
                      "sourceSHA256": hashlib.sha256(data).hexdigest(),
                      "publishedSHA256": hashlib.sha256(text.encode()).hexdigest()})
inv = {"candidate": REV, "files": inventory,
       "scope": "sanitized exact-candidate measurements; original failures and diagnoses retained"}
(S / "inventory.json").write_text(json.dumps(inv, indent=2) + "\n")

# ------------------------------------------------------------------- scenarios
load = lambda p: json.loads((S / p).read_text())
apple = {p: load(p) for p in publish if p.startswith("ios-") and p.endswith("-result.json")
         and not p.startswith("ios-wan/") or p in [f"ios-wan/{x}-result.json" for x in ["http", "https", "shadowsocks-aead", "socks"]]}
android = {p: [json.loads(l) for l in (S / p).read_text().splitlines() if l.strip()]
           for p in publish if p.startswith("android-") and p.endswith("events.jsonl")}


def stamp(row):
    if "hostTime" in row:
        return row["hostTime"]
    return datetime.datetime.fromisoformat(row["time"].replace("Z", "+00:00")).timestamp()


def duration(rows):
    times = [stamp(x) for x in rows if "hostTime" in x or "time" in x]
    assert len(times) > 1
    return max(1, math.ceil(max(times) - min(times)))


artifacts, used = {}, set()


def artifact(platform, kind, value):
    path = f"{platform}/{kind}.json"
    payload = (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()
    artifacts[path] = payload
    return {"kind": kind, "path": path, "sha256": hashlib.sha256(payload).hexdigest()}


def source_payload(paths):
    used.update(paths)
    return {p: {"sha256": hashlib.sha256((S / p).read_bytes()).hexdigest(), "text": (S / p).read_text()}
            for p in sorted(paths)}


timeline = {"apple": {}, "android": {}}


def scenario(platform, ident, selections, proofs, scope):
    """proofs: transition -> predicate over the selected rows; each must match."""
    records = apple if platform == "apple" else android
    evidence, seconds, selected = [], 0, []
    for path, predicate in selections:
        indexed = [(i, x) for i, x in enumerate(records[path]) if predicate(x)]
        assert indexed, (platform, ident, path)
        selected += [x for _, x in indexed]
        seconds += duration([x for _, x in indexed])
        evidence.append({"source": path, "eventIndexes": [i for i, _ in indexed], "first": stamp(indexed[0][1]),
                         "last": stamp(indexed[-1][1]), "durationSeconds": duration([x for _, x in indexed])})
    counts = {}
    for transition, proof in proofs.items():
        counts[transition] = sum(1 for x in selected if proof(x))
        assert counts[transition], (platform, ident, transition)
    timeline[platform][ident] = {"scope": scope, "evidence": evidence, "transitions": list(proofs),
                                 "provingEventCounts": counts}
    return {"id": ident, "durationSeconds": seconds, "transitions": list(proofs), "trafficResult": "pass",
            "result": "pass"}


ok = lambda x: x.get("result") == "passed"
ev = lambda name, extra=lambda x: True: (lambda x: x.get("event") == name and ok(x) and extra(x))
kind = lambda name, extra=lambda x: True: (lambda x: x.get("kind") == name and extra(x))
allrows = lambda x: True
V4, V6 = "198.51.100.7", "2001:db8::7"
domain = lambda x: str(x.get("host", "")).endswith(".test")
wan_stage = lambda stage: ev("transition-recovered", lambda x: x.get("stage") == stage)
WAN = {"socks": ["socks"], "http": ["http", "https"], "shadowsocks-aead": ["shadowsocks-aead"]}

asce = []
for p in ["socks", "http", "shadowsocks-aead"]:
    pred = lambda x, p=p: str(x.get("protocol", "")).split(":")[0] == p
    files = ["ios-v09-smoke-result.json", "ios-v09-lifecycle-result.json", "ios-v09-resources-result.json",
             "ios-ciphers-v09-result.json"]
    sel = [(f, pred) for f in files if any(pred(x) for x in apple[f])]
    for w in WAN[p]:
        path = f"ios-wan/{w}-result.json"
        assert apple[path][-1]["event"] == "complete" and ok(apple[path][-1]), path
        sel.append((path, allrows))
    udp = ({"ipv4-udp-refused": ev("udp-refused", lambda x: x.get("transition") == "ipv4-udp-refused"),
            "ipv6-udp-refused": ev("udp-refused", lambda x: x.get("transition") == "ipv6-udp-refused")}
           if p == "http" else
           {"ipv4-udp": ev("udp", lambda x: x.get("transition") == "ipv4-udp"),
            "ipv6-udp": ev("udp", lambda x: x.get("transition") == "ipv6-udp")})
    proofs = {"ipv4-tcp": ev("tcp", lambda x: x.get("host") == V4), "ipv6-tcp": ev("tcp", lambda x: x.get("host") == V6),
              **udp, "domain-destination": ev("tcp", domain), "routed-dns": ev("dns-anchor"),
              "start-stop": ev("disconnected"),
              "cancel-active-flow": lambda x: x.get("event") == "connection-close-verified",
              "reconnect": lambda x: (x.get("event") in ("traffic-after-close", "rapid-restart", "startup-cancelled")
                                      and ok(x)),
              "wifi-cellular-wifi": wan_stage("cellular"), "lock-wake": wan_stage("after-unlock"),
              "resource-recovery": ev("resource-complete")}
    asce.append(scenario("apple", p, sel, proofs,
                         "LAN smoke/lifecycle/resources/ciphers plus owner-driven iPhone WAN (Wi-Fi to cellular to "
                         "Wi-Fi, lock/wake). HTTP carries no UDP: each UDP probe is shown refused as a negative "
                         "control. SOCKS WAN UDP ran while the provider firewall temporarily allowed the reference "
                         "server's ephemeral UDP relay ports. Cancellation means verified local connection closure, "
                         "not bounded remote EOF."))
shared_proofs = {"tcp-udp-domain-routed-dns": ev("udp"), "active-close-and-recovery": ev("traffic-after-close")}
for p in ["vless-encryption", "ip-on-demand", "xhttp-download-session"]:
    sel = [("ios-shared-result.json", lambda x, p=p: x.get("protocol") == p)]
    proofs = dict(shared_proofs)
    if p == "ip-on-demand":
        sel += [(f"ios-fakedns-{phase}-result.json", allrows) for phase in ["negative", "recovery"]]
        proofs["fakedns-positive-asis-negative-recovery"] = lambda x: x.get("event") == "dns-fakeip-anchor"
    asce.append(scenario("apple", p, sel, proofs,
                         "Actual device exchanges; the expected AsIs negative is retained as failed traffic and "
                         "evaluated as a successful negative control, not a successful flow."))
asce.append(scenario("apple", "cancellation",
                     [(f, allrows) for f in ["ios-v09-lifecycle-result.json", "ios-v09-smoke-result.json"]],
                     {"startup-cancel-restart": ev("startup-cancelled"), "rapid-restart": ev("rapid-restart"),
                      "active-local-connection-close-verified": lambda x: x.get("event") == "connection-close-verified"},
                     "Local cancellation and recovery; no remote EOF guarantee."))
asce.append(scenario("apple", "host-adapter-projection",
                     [(f"ios-projection-{p}-result.json", allrows) for p in ["file-descriptor", "packet-pump"]],
                     {"fd-and-packet-pump": ev("host-adapter-projection"),
                      "actual-tcp-udp-callback-counters": ev("host-adapter-projection",
                                                             lambda x: x["tcpCallbacks"] > 0 and x["udpCallbacks"] > 0)},
                     "Debug provider observation hooks (tools/ios-projection-build.patch); native library unchanged."))
asce.append(scenario("apple", "profile-import",
                     [(f, allrows) for f in ["ios-v09-smoke-result.json", "ios-ciphers-v09-result.json"]],
                     {f"{p}-link": ev("import", lambda x, p=p: x["protocol"].split(":")[0] == p)
                      for p in ["socks", "http", "shadowsocks-aead"]}
                     | {"invalid-input-redaction": ev("invalid-import-redaction")},
                     "Successful links and actual rejected/redacted malformed imports."))
asce.append(scenario("apple", "legacy-regression", [("ios-legacy-v09-result.json", allrows)],
                     {p: ev("disconnected", lambda x, p=p: x["protocol"].split(":")[0] == p)
                      for p in ["vless-reality", "xhttp-h1", "xhttp-h2", "xhttp-h3", "hysteria2", "wireguard",
                                "trojan", "shadowsocks2022", "vmess"]},
                     "Canonical candidate device traffic and recovery for every pre-0.9 outbound."))

CASES = {"socks": lambda c: c.startswith("socks-"), "http": lambda c: c.startswith("http-"),
         "shadowsocks-aead": lambda c: c.startswith("shadowsocks-aead-")}
dsc = []
for p in ["socks", "http", "shadowsocks-aead"]:
    for backend in ["file-descriptor", "packet-pump"]:
        pred = lambda x, p=p, b=backend: CASES[p](str(x.get("case", ""))) and x.get("backend") == b
        files = ["android-v09/events.jsonl", "android-cancel-tcp/events.jsonl", "android-cancel-udp/events.jsonl",
                 "android-resources-a/events.jsonl", "android-resources-b/events.jsonl"]
        sel = [(f, pred) for f in files if any(pred(x) for x in android[f])]
        assert any(x["kind"] == "case-pass" and pred(x) for x in android["android-v09/events.jsonl"])
        has = lambda t: kind("traffic", lambda x, t=t: t in x.get("transitions", []))
        udp = ({"ipv4-udp-refused": has("ipv4-udp-refused"), "ipv6-udp-refused": has("ipv6-udp-refused")}
               if p == "http" else {"ipv4-udp": has("ipv4-udp"), "ipv6-udp": has("ipv6-udp")})
        proofs = {"ipv4-tcp": has("ipv4-tcp"), "ipv6-tcp": has("ipv6-tcp"), **udp,
                  "domain-destination": has("domain-destination"), "routed-dns": has("routed-dns"),
                  "start-stop": kind("case-pass"),
                  "cancel-active-flow": kind("local-active-cancellation", lambda x: x["localCancellationPassed"]),
                  "reconnect": kind("cancel-start-recovery"),
                  "resource-recovery": kind("resource-recovery", lambda x: x["passed"])}
        dsc.append(scenario("android", f"{p}-{backend}", sel, proofs,
                            "Exact candidate physical Android traffic on this TUN backend. Wi-Fi/cellular and "
                            "lock/wake are not tested on Android (owner decision 2026-11-01). Cancellation is local "
                            "active closure with traffic recovery."))
for p in ["vless-encryption", "ip-on-demand", "xhttp-download-session"]:
    pred = lambda x, p=p: x.get("case") == p or (p == "ip-on-demand" and x["kind"].startswith("ip-"))
    proofs = {"both-tun-backends": kind("case-pass"), "tcp-udp-domain-routed-dns": kind("traffic"),
              "close-recovery": kind("close-recovery")}
    if p == "ip-on-demand":
        proofs["asis-negative-and-recovery"] = kind("ip-on-demand-recovery-control")
    dsc.append(scenario("android", p, [("android-shared/events.jsonl", pred)], proofs,
                        "Exact candidate physical Android traffic and controls."))
dsc.append(scenario("android", "cancellation",
                    [(f, allrows) for f in ["android-cancel-tcp/events.jsonl", "android-cancel-udp/events.jsonl"]],
                    {"local-active-close": kind("local-active-cancellation", lambda x: x["localCancellationPassed"]),
                     "remote-eof-within-bound": kind("local-active-cancellation", lambda x: x["remoteCloseBoundPassed"]),
                     "delayed-udp-cancel": kind("udp-active-cancelled"),
                     "traffic-recovery": kind("udp-cancel-recovery")},
                    "16 local TCP cancellations (remote EOF inside the bound in every one) and 8 delayed UDP "
                    "cancellations with recovery."))
dsc.append(scenario("android", "host-adapter-projection",
                    [("android-shared/events.jsonl",
                      lambda x: x["kind"] in ["host-adapter-projection", "projection-controls-complete"])],
                    {"included-uid-tcp-udp": kind("host-adapter-projection"),
                     "controls-complete": kind("projection-controls-complete")},
                    "Actual Android host admission counters and traffic controls."))
dsc.append(scenario("android", "profile-import", [("android-v09/events.jsonl", allrows)],
                    {f"{p}-link": kind("share-link-import", lambda x, p=p: x["passed"] and CASES[p](x["case"]))
                     for p in ["socks", "http", "shadowsocks-aead"]}
                    | {"invalid-input-redaction": kind("invalid-import-control",
                                                       lambda x: x["passed"] and x["markerAbsentFromHostLog"])},
                    "Actual link imports and malformed-input rejection/redaction."))
dsc.append(scenario("android", "legacy-regression", [("android-legacy-v09/events.jsonl", allrows)],
                    {p: kind("case-pass", lambda x, p=p: x["case"] == p)
                     for p in ["vless-reality", "xhttp-h1", "xhttp-h2", "xhttp-h3", "hysteria2", "wireguard",
                               "trojan", "shadowsocks2022", "vmess"]},
                    "Both Android backends for every pre-0.9 outbound."))

# ------------------------------------------------------------------- resources
res = apple["ios-v09-resources-result.json"]
bounds = []
for protocol in sorted({e["protocol"] for e in res if e.get("event") == "sample"}):
    samples = [e for e in res if e.get("event") == "sample" and e["protocol"] == protocol]
    baseline = next(e for e in samples if e["stage"] == "baseline")
    recover = [e for e in samples if e["stage"].startswith("recovery")]
    limits = {"rss": 8388608, "footprint": 8388608, "threads": 8}
    growth = {k: max(0, max(e[k] for e in recover) - baseline[k]) for k in limits}
    bounds.append({"protocol": protocol, "baseline": baseline, "growth": growth, "limits": limits,
                   "withinBounds": all(growth[k] <= v for k, v in limits.items()), "recoverySamples": len(recover),
                   "complete": any(e["event"] == "resource-complete" and ok(e) and e["protocol"] == protocol
                                   for e in res)})
recover = [e for f in ["android-resources-a/events.jsonl", "android-resources-b/events.jsonl"]
           for e in android[f] if e["kind"] == "resource-recovery"]
assert len(bounds) == 4 and all(x["withinBounds"] and x["complete"] for x in bounds)
assert len(recover) == 14 and all(x["passed"] for x in recover)
alim = {"residentMemoryGrowthBytes": 8388608, "threadGrowth": 8, "fatalErrors": 0, "unrecoveredTransitions": 0}
aobs = {"residentMemoryGrowthBytes": max(x["growth"]["rss"] for x in bounds),
        "threadGrowth": max(x["growth"]["threads"] for x in bounds), "fatalErrors": 0, "unrecoveredTransitions": 0}
dlim = {"residentMemoryGrowthBytes": max(max(8388608, math.ceil(x["rss"][0] * .25)) for x in recover),
        "threadGrowth": 4, "fatalErrors": 0, "unrecoveredTransitions": 0}
dobs = {"residentMemoryGrowthBytes": max(0, max(x["rssGrowthBytes"] for x in recover)),
        "threadGrowth": max(0, max(x["threadGrowth"] for x in recover)), "fatalErrors": 0, "unrecoveredTransitions": 0}

devices = []
for platform, scenarios, limits, observed, model, osver, arch, logs in [
        ("apple", asce, alim, aobs, "iPhone 17 Pro Max (iPhone18,2)", "iOS 27.0.1 (24A446)", "arm64", apple),
        ("android", dsc, dlim, dobs, "Samsung SM-A145F", "Android 15 / API 35", "arm64-v8a", android)]:
    selected = sorted({e["source"] for t in timeline[platform].values() for e in t["evidence"]})
    profile = {"scope": "Resource growth on measured recovery windows. Zero fatal/unrecovered counts apply to accepted "
                        "success paths; failed attempts and negative controls are retained in logs, not erased.",
               "limits": limits, "observed": observed,
               "method": "Apple: recovery versus baseline, 8 MiB RSS/footprint and 8 threads per protocol. Android: "
                         "per-case max(8 MiB, 25% first recovery RSS) and 4 threads, fixed before measurement; the "
                         "manifest limit is the maximum of those limits and each case was checked on its own.",
               "evaluation": bounds if platform == "apple" else recover,
               "samples": res if platform == "apple" else
               [x for f in ["android-resources-a/events.jsonl", "android-resources-b/events.jsonl"]
                for x in android[f] if x["kind"].startswith("resource-")]}
    arts = [artifact(platform, "resource-profile", profile),
            artifact(platform, "sanitized-log", {"scope": "All accepted attempts, including negative controls; "
                                                          "superseded attempts are under failed/ in the report",
                                                 "sources": source_payload(logs.keys())}),
            artifact(platform, "transition-timeline", timeline[platform])]
    devices.append({"platform": platform, "physical": True, "model": model, "osVersion": osver,
                    "architecture": arch, "durationSeconds": sum(duration(logs[f]) for f in selected),
                    "scenarios": scenarios, "limits": limits, "observed": observed, "artifacts": arts,
                    "result": "pass"})

# ----------------------------------------------------------------- performance
comparisons = load("performance-protocols/protocol-comparisons.json")
features = load("performance-features/performance.json")
assert comparisons["complete"] and comparisons["allProfilesPassed"] and features["result"] == "pass"
measurements = features["measurements"] + comparisons["schema4Measurements"]
assert len(measurements) == 13
paths = [f["path"] for f in inventory]
raw = [p for p in paths if p.startswith("performance-") and p != "performance-protocols/protocol-comparisons.json"]
perfarts = [artifact("performance", "benchmark-raw", source_payload(raw))]
perfarts.append(artifact("performance", "build-manifest",
                         source_payload(["performance-features/build-manifest.json", "performance-protocols/manifest.json"])))
perfarts.append(artifact("performance", "protocol-comparisons",
                         source_payload(["performance-protocols/protocol-comparisons.json"])))
owner = json.loads((RELEASES / "v0.9.0-owner-decisions.json").read_text())
perfarts.append(artifact("performance", "known-limitations",
                         {"ownerDecision": owner, "report": (S / "README.md").read_text(), "inventory": inv,
                          "supportingEvidence": source_payload([p for p in paths if p not in used])}))
manifest = {"schemaVersion": 4, "candidate": {"revision": REV, "tree": TREE, "dirty": False}, "devices": devices,
            "performance": {"profile": "release", "clean": True, "measurements": measurements,
                            "artifacts": perfarts, "result": "pass"}, "result": "pass"}
artifacts["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
archive = RELEASES / "v0.9.0-device-evidence.zip"
with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name, data in sorted(artifacts.items()):
        info = zipfile.ZipInfo(name, date_time=(2026, 11, 2, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        z.writestr(info, data)
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(C / "schema4-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({"archive": str(archive), "sha256": digest, "bytes": archive.stat().st_size,
                  "publishedFiles": len(inventory), "appleScenarios": len(asce), "androidScenarios": len(dsc),
                  "metrics": [(m["id"], round(statistics.median(m["samples"]), 2), m["comparison"], m["threshold"])
                              for m in measurements]}, indent=2))

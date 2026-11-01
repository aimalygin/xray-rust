"""Summarise protocol-bench series: host CPU ms/GiB, MiB/s, server CPU, peak RSS, payload checks, drops.

usage: python3 -I analyze.py RUN_DIR [loop|wifi|smoke]
"""
import hashlib
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

out = Path(sys.argv[1])
SET = sys.argv[2] if len(sys.argv) > 2 else "loop"
CLK_TCK = 100
HDR = 36
GIB = 1 << 30
MIB = 1 << 20
ORDER = ["vless-raw", "vless-mux", "reality-vision", "xhttp-tls-h2", "xhttp-tls-h2-streamup", "ss-aes256gcm", "ss-chacha20", "ss2022-aes256", "trojan-tls"]


def zeros_md5(n):
    h = hashlib.md5()
    chunk = bytes(MIB)
    for _ in range(n // MIB):
        h.update(chunk)
    return h.hexdigest()


def per_flow(mode, flows):
    if SET == "wifi":
        return 128 * MIB
    if SET == "smoke":
        return 16 * MIB
    return GIB if flows == 1 else 256 * MIB


MD5 = {}
rows = defaultdict(list)
srv = defaultdict(list)
conns = defaultdict(list)
hwm = defaultdict(lambda: defaultdict(int))
idle_rss = defaultdict(list)
idle = defaultdict(list)
temps = []
bad = defaultdict(list)
buffer = []
for line in (out / "raw.txt").read_text().splitlines():
    rep, cfg, pid, rest = re.match(r"rep=(\d+) cfg=(\S+) pid=(\d+) (.*)", line).groups()
    if not rest.startswith("result"):
        m = re.match(r"flow\d+ (?:md5|srvcount)=(\S+)", rest)
        buffer.append(m.group(1) if m else rest)
        continue
    kv = dict(re.findall(r"(\w+)[=:](\S+)", rest))
    got, buffer = buffer, []
    mode, flows = kv["mode"], int(kv["flows"])
    secs = float(kv["t1"]) - float(kv["t0"])
    ticks, sticks = int(kv["ticks"]), int(kv["srvticks"])
    temps.append(int(kv["temperature"]))
    hwm[cfg][(rep, pid)] = max(hwm[cfg][(rep, pid)], int(kv["hwmkb"]))
    if mode == "idle":
        idle[cfg].append(ticks * 1000 / CLK_TCK / secs)
        idle_rss[cfg].append(int(kv["rsskb"]))
        continue
    size = per_flow(mode, flows)
    if mode == "dl":
        expected = MD5.setdefault(size, zeros_md5(size))
    else:
        expected = str(size + HDR)
    key = (cfg, mode, flows)
    if SET == "wifi" and mode == "ul" and not got:
        pass
    if len(got) != flows or any(g != expected for g in got):
        bad[key].append((rep, got))
        continue
    total = size * flows
    gib = total / GIB
    rows[key].append((ticks * 1000 / CLK_TCK / gib, total / MIB / secs))
    srv[key].append(sticks * 1000 / CLK_TCK / gib)
    conns[key].append(int(kv["srvconns"]))

drops = []
for line in (out / "samples.txt").read_text().splitlines():
    if "XRAY_ANDROID_SAMPLE" in line:
        sample = json.loads(line[line.index("{"):])
        drops.append((line.split(" pid=")[0], sample["tunDroppedPackets"], sample["fatalTunErrors"]))


def fmt(values, digits=0):
    med = statistics.median(values)
    return f"{med:.{digits}f} ({min(values):.{digits}f}–{max(values):.{digits}f})"


cfgs = [c for c in ORDER if any(k[0] == c for k in list(rows) + list(bad))]
print("| config | traffic | flows | ok/n | host CPU ms/GiB | Δ vs vless-raw | MiB/s | server CPU ms/GiB | server conns |")
print("|---|---|---|---|---|---|---|---|---|")
for mode in ("dl", "ul"):
    for flows in (1, 4):
        base = rows.get(("vless-raw", mode, flows))
        base_med = statistics.median(x[0] for x in base) if base else None
        for cfg in cfgs:
            key = (cfg, mode, flows)
            r = rows.get(key, [])
            n = len(r) + len(bad.get(key, []))
            if not n:
                continue
            if not r:
                print(f"| {cfg} | {mode} | {flows} | 0/{n} | FAIL | | | | |")
                continue
            med = statistics.median(x[0] for x in r)
            delta = "—" if cfg == "vless-raw" or base_med is None else f"{(med / base_med - 1) * 100:+.0f}%"
            cs = sorted(set(conns[key]))
            print(f"| {cfg} | {mode} | {flows} | {len(r)}/{n} | {fmt([x[0] for x in r])} | {delta} | "
                  f"{fmt([x[1] for x in r], 1)} | {fmt(srv[key])} | {','.join(map(str, cs))} |")
print()
print("| config | idle CPU ms/s | RSS after start, MiB | peak RSS (VmHWM) per process, MiB |")
print("|---|---|---|---|")
for cfg in cfgs:
    peaks = [v / 1024 for v in hwm[cfg].values()]
    print(f"| {cfg} | {fmt(idle[cfg], 1)} | {fmt([v / 1024 for v in idle_rss[cfg]], 1)} | {fmt(peaks, 1)} |")
print()
print("battery temperature (0.1 C): min", min(temps), "max", max(temps))
for key, items in bad.items():
    print("payload FAIL", key, "reps", [i[0] for i in items], "example", items[0][1][:4])
print("drops/fatal per lifetime (nonzero only):", [d for d in drops if d[1] or d[2]] or "none", f"of {len(drops)} lifetimes")

"""Summarise memseries.sh output: host RSS before, peak (VmHWM), sampled max, after; payload checks; drops.

usage: python3 -I analyze_mem.py RUN_DIR
"""
import hashlib
import json
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

out = Path(sys.argv[1])
MIB = 1 << 20
MD5 = {n: hashlib.md5(bytes(n * MIB)).hexdigest() for n in (4, 16)}
rows = defaultdict(list)
bad = defaultdict(int)
temps = []
buffer = []
for line in (out / "raw.txt").read_text().splitlines():
    rep, case, rest = re.match(r"rep=(\d+) case=(\S+) pid=\d+ (.*)", line).groups()
    if not rest.startswith("memresult"):
        m = re.match(r"flow\d+ md5=(\S+)", rest)
        buffer.append(m.group(1) if m else rest)
        continue
    kv = {k: v for k, v in re.findall(r"(\w+)[=:](\S+)", rest)}
    got, buffer = buffer, []
    flows = int(kv["flows"])
    expected = MD5[16 if flows <= 64 else 4]
    ok = len(got) == flows and all(g == expected for g in got)
    if not ok:
        bad[case] += 1
    temps.append(int(kv["temperature"]))
    secs = float(kv["t1"]) - float(kv["t0"])
    rows[case].append(dict(
        ok=ok,
        rss0=int(kv["rss0kb"]) / 1024,
        hwm=int(kv["hwmkb"]) / 1024,
        rssmax=int(kv["rssmaxkb"]) / 1024,
        after=int(kv["rssafterkb"]) / 1024,
        delta=(int(kv["hwmkb"]) - int(kv["rss0kb"])) / 1024,
        conns=int(kv["srvconnsmax"]),
        mibs=1024 / secs,
        cpu=int(kv["ticks"]) * 10,
    ))


def fmt(values, digits=1):
    return f"{statistics.median(values):.{digits}f} ({min(values):.{digits}f}–{max(values):.{digits}f})"


print("| profile:flows | ok/n | RSS before, MiB | peak VmHWM, MiB | peak − before, MiB | sampled max RSS, MiB | RSS 2 s after, MiB | max server conns | MiB/s | host CPU ms/GiB |")
print("|---|---|---|---|---|---|---|---|---|---|")
for case in sorted(rows, key=lambda c: (int(c.split(":")[1]), c)):
    r = rows[case]
    good = [x for x in r if x["ok"]]
    print(f"| {case} | {len(good)}/{len(r)} | {fmt([x['rss0'] for x in r])} | {fmt([x['hwm'] for x in r])} | "
          f"{fmt([x['delta'] for x in r])} | {fmt([x['rssmax'] for x in r])} | {fmt([x['after'] for x in r])} | "
          f"{fmt([x['conns'] for x in r], 0)} | {fmt([x['mibs'] for x in good] or [0])} | {fmt([x['cpu'] for x in good] or [0], 0)} |")
print()
print("battery temperature (0.1 C): min", min(temps), "max", max(temps))
print("payload failures:", dict(bad) or "none")
drops = []
for line in (out / "samples.txt").read_text().splitlines():
    if "XRAY_ANDROID_SAMPLE" in line:
        s = json.loads(line[line.index("{"):])
        drops.append((line.split(" pid=")[0], s["tunDroppedPackets"], s["fatalTunErrors"]))
print("drops/fatal (nonzero only):", [d for d in drops if d[1] or d[2]] or "none", f"of {len(drops)} lifetimes")

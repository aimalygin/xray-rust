#!/bin/bash
# run-mem.sh <label> <traffic> <flows> [ENV=VALUE ...]
# run-one-v2.sh plus: CLIENT may be a wrapper script, MATCH names the exe whose
# /proc entry is sampled, and a 100 ms time series goes to <out>/series:
# t_ms VmRSS RssAnon RssFile VmHWM Threads utime stime (KiB / ticks).
set -u
label=$1; traffic=$2; flows=$3; shift 3
out=/runs/mem/$label-$traffic-$flows
rm -rf "$out"; mkdir -p "$out"
for kv in "$@"; do export "$kv"; done
client=${CLIENT:-/target/bin/xray-rust-after}
match=${MATCH:-$client}
sample() {
  local pid="" st rss anon file hwm thr t0 now
  t0=$(date +%s%N)
  while [ ! -e "$out/.stop" ]; do
    if [ -z "$pid" ]; then
      for p in /proc/[0-9]*; do
        if [ -r "$p/cmdline" ] && read -r -d '' exe < "$p/cmdline" 2>/dev/null && [ "$exe" = "$match" ]; then pid=${p#/proc/}; echo "$pid" > "$out/pid"; break; fi
      done
    fi
    if [ -n "$pid" ] && read -r st < "/proc/$pid/stat" 2>/dev/null; then
      rss=; anon=; file=; hwm=; thr=
      while read -r key value _; do
        case $key in VmRSS:) rss=$value ;; RssAnon:) anon=$value ;; RssFile:) file=$value ;; VmHWM:) hwm=$value ;; Threads:) thr=$value ;; esac
      done < "/proc/$pid/status"
      set -- ${st##*) }
      now=$(date +%s%N)
      [ -n "$hwm" ] && echo "$(( (now - t0) / 1000000 )) $rss $anon $file $hwm $thr ${12} ${13}" >> "$out/series"
    fi
    sleep 0.1
  done
}
sample & sampler=$!
${HARNESS:-/target/bin/xray-bench-ab} run --engine xray-rust --xray-rust-bin "$client" \
  --xray-core-bin /xbin/xray-core-linux-arm64 --no-auto-build --workload stream-transport \
  --stream-transport xhttp-h3 --xhttp-mode stream-up --traffic "$traffic" \
  --connections "$flows" --iterations ${ITERATIONS:-4096} --payload-size 65536 --runs 1 \
  --run-timeout-ms 300000 --out-dir "$out/bench" > "$out/bench.log" 2>&1 || echo "bench exit $?" >> "$out/bench.log"
touch "$out/.stop"; wait $sampler
r=$(ls "$out"/bench/*/xray-rust/stream-transport/result.json 2>/dev/null | head -1)
python3 - "$r" "$label" "$traffic" "$flows" "$out" <<'PY'
import json, sys, os
path, label, traffic, flows, out = sys.argv[1:6]
res = json.load(open(path)) if path else {}
rows = []
try:
    rows = [list(map(int, l.split())) for l in open(os.path.join(out, 'series')) if len(l.split()) == 8]
except FileNotFoundError:
    pass
last = rows[-1] if rows else None
moved = (res.get('bytes_sent') or 0) + (res.get('bytes_received') or 0)
ticks = (last[6] + last[7]) if last else 0
print(json.dumps({'label': label, 'traffic': traffic, 'flows': int(flows), 'status': res.get('status'),
  'vm_hwm_kib': max((r[4] for r in rows), default=None), 'peak_rss_anon_kib': max((r[2] for r in rows), default=None),
  'peak_rss_file_kib': max((r[3] for r in rows), default=None), 'max_threads': max((r[5] for r in rows), default=None),
  'throughput_mbps': res.get('throughput_mbps'), 'transfer_ms': res.get('transfer_duration_ms'),
  'cpu_ticks': ticks, 'cpu_ms_per_gib': round(ticks * 10 / (moved / 2**30), 1) if moved and ticks else None}))
PY

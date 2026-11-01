#!/bin/bash
# run-one-v2.sh <label> <traffic> <flows> [ENV=VALUE ...]
# One xray-bench XHTTP H3 stream-up case; also samples the client's /proc
# VmHWM (exact peak RSS), RssAnon and CPU ticks every 100 ms without forking.
set -u
label=$1; traffic=$2; flows=$3; shift 3
out=/runs/v2/$label-$traffic-$flows
rm -rf "$out"; mkdir -p "$out"
for kv in "$@"; do export "$kv"; done
client=${CLIENT:-/target/bin/xray-rust-exp}
sample() {
  local pid="" line st hwm anon
  while [ ! -e "$out/.stop" ]; do
    if [ -z "$pid" ]; then
      for p in /proc/[0-9]*; do
        if [ -r "$p/cmdline" ] && read -r -d '' exe < "$p/cmdline" 2>/dev/null && [ "$exe" = "$client" ]; then pid=${p#/proc/}; break; fi
      done
    fi
    if [ -n "$pid" ] && read -r st < "/proc/$pid/stat" 2>/dev/null; then
      hwm=; anon=
      while read -r key value _; do
        case $key in VmHWM:) hwm=$value ;; RssAnon:) anon=$value ;; esac
      done < "/proc/$pid/status"
      set -- ${st##*) }
      [ -n "$hwm" ] && echo "${12} ${13} $hwm $anon" > "$out/proc.last"
      [ -n "$anon" ] && { [ ! -e "$out/anon.peak" ] || [ "$anon" -gt "$(cat "$out/anon.peak")" ]; } && echo "$anon" > "$out/anon.peak"
    fi
    sleep 0.1
  done
}
sample & sampler=$!
${HARNESS:-/target/bin/xray-bench} run --engine xray-rust --xray-rust-bin "$client" \
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
utime = stime = hwm = None
try:
    u, s, h, a = (open(os.path.join(out, 'proc.last')).read().split() + [None] * 4)[:4]
    utime, stime, hwm = int(u), int(s), int(h) if h else None
except (FileNotFoundError, ValueError):
    pass
anon = int(open(os.path.join(out, 'anon.peak')).read()) if os.path.exists(os.path.join(out, 'anon.peak')) else None
moved = (res.get('bytes_sent') or 0) + (res.get('bytes_received') or 0)
ticks = (utime or 0) + (stime or 0)
print(json.dumps({'label': label, 'traffic': traffic, 'flows': int(flows), 'status': res.get('status'),
  'peak_rss_kib': res.get('peak_rss_kib'), 'vm_hwm_kib': hwm, 'peak_rss_anon_kib': anon,
  'throughput_mbps': res.get('throughput_mbps'), 'transfer_ms': res.get('transfer_duration_ms'),
  'cpu_ticks': ticks, 'bytes': moved,
  'cpu_ms_per_gib': round(ticks * 10 / (moved / 2**30), 1) if moved and ticks else None,
  'harness_cpu_ms_per_gib': res.get('cpu_millis_per_gib')}))
PY

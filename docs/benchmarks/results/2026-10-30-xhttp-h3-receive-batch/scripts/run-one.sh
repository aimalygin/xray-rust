#!/bin/sh
# run-one.sh <label> <traffic> <flows> [ENV=VALUE ...]
# Runs one xray-bench stream-transport XHTTP H3 stream-up case inside the container.
set -eu
label=$1; traffic=$2; flows=$3; shift 3
out=/runs/$label-$traffic-$flows
rm -rf "$out"; mkdir -p "$out"
for kv in "$@"; do export "$kv"; done
export XRAY_EXP_RESIDENCY_LOG=${XRAY_EXP_RESIDENCY_LOG:-$out/residency.log}
[ "$XRAY_EXP_RESIDENCY_LOG" = off ] && unset XRAY_EXP_RESIDENCY_LOG
/target/bin/xray-bench run --engine xray-rust --xray-rust-bin ${CLIENT:-/target/bin/xray-rust-exp} \
  --xray-core-bin /xbin/xray-core-linux-arm64 --no-auto-build --workload stream-transport \
  --stream-transport xhttp-h3 --xhttp-mode stream-up --traffic "$traffic" \
  --connections "$flows" --iterations ${ITERATIONS:-4096} --payload-size 65536 --runs 1 \
  --run-timeout-ms 300000 --out-dir "$out/bench" > "$out/bench.log" 2>&1 || echo "bench exit $?" >> "$out/bench.log"
r=$(ls "$out"/bench/*/xray-rust/stream-transport/result.json 2>/dev/null | head -1)
python3 - "$r" "$label" "$traffic" "$flows" "${XRAY_EXP_RESIDENCY_LOG:-}" <<'PY'
import json, sys, re
path, label, traffic, flows, rlog = sys.argv[1:6]
res = json.load(open(path)) if path else {}
peak_res = None
if rlog:
    try:
        lines = open(rlog).read().strip().splitlines()
        peak_res = max(int(re.search(r'peak_resident_pages=(\d+)', l).group(1)) for l in lines) if lines else None
        last = lines[-1] if lines else ''
        bufs = int(re.search(r'buffers=(\d+)', last).group(1)) if last else None
        virt = int(re.search(r'virt_pages=(\d+)', last).group(1)) if last else None
    except FileNotFoundError:
        bufs = virt = None
else:
    bufs = virt = None
print(json.dumps({'label': label, 'traffic': traffic, 'flows': int(flows), 'status': res.get('status'),
  'peak_rss_kib': res.get('peak_rss_kib'), 'throughput_mbps': res.get('throughput_mbps'),
  'cpu_millis_per_gib': res.get('cpu_millis_per_gib'), 'cpu_millis': res.get('cpu_millis'),
  'transfer_ms': res.get('transfer_duration_ms'), 'recvbuf_buffers': bufs,
  'recvbuf_virt_kib': virt * 4 if virt is not None else None,
  'recvbuf_peak_resident_kib': peak_res * 4 if peak_res is not None else None}))
PY

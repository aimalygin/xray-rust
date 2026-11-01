#!/bin/bash
# rbn.sh <rounds> <outfile> <profile|none> <traffic:flows>...
# Interleaved runs of /target/bin/xray-rust-rb-<variant> for each variant in
# VARIANTS (default "before timed") with run-one-v2.sh. The order rotates
# across rounds and scenarios, so each build takes each position equally
# often. ITERATIONS passes through to the harness (default 4096 x 64 KiB);
# DELAY_MS is the round trip delayed.sh measured, recorded with each result.
rounds=$1; outfile=$2; profile=$3; shift 3
export HARNESS=/target/bin/xray-bench-ab
read -r -a variants <<< "${VARIANTS:-before timed}"
n=${#variants[@]}
for r in $(seq 1 "$rounds"); do
  i=0
  for sc in "$@"; do
    traffic=${sc%:*}; flows=${sc#*:}
    k=$(( (r + i) % n ))
    for j in $(seq 0 $((n - 1))); do
      v=${variants[$(( (k + j) % n ))]}
      envs=(); [ "$profile" != none ] && envs=("XRAY_TUN_PROFILE=$profile")
      line=$(CLIENT=/target/bin/xray-rust-rb-$v /runs/run-one-v2.sh "rbn-$profile-${ITERATIONS:-4096}-d${DELAY_MS:-0}-r$r-$v" "$traffic" "$flows" "${envs[@]}")
      echo "{\"round\": $r, \"variant\": \"$v\", \"position\": $j, \"profile\": \"$profile\", \"iterations\": ${ITERATIONS:-4096}, \"delay_ms\": ${DELAY_MS:-0}, \"result\": $line}" >> "$outfile"
    done
    i=$((i+1))
  done
done
echo DONE > "$outfile.done"

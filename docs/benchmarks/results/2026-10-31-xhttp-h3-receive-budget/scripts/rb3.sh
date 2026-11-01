#!/bin/bash
# rb3.sh <rounds> <outfile> <profile|none> <traffic:flows>...
# Interleaved runs of /target/bin/xray-rust-rb-{before,cap,behind} with
# run-one-v2.sh. The order rotates across rounds and scenarios, so each
# build runs first, second and third equally often. ITERATIONS passes
# through to the harness (default 4096 x 64 KiB); DELAY_MS is the round
# trip delayed.sh added, recorded with each result.
rounds=$1; outfile=$2; profile=$3; shift 3
export HARNESS=/target/bin/xray-bench-ab
variants=(before cap behind)
for r in $(seq 1 "$rounds"); do
  i=0
  for sc in "$@"; do
    traffic=${sc%:*}; flows=${sc#*:}
    k=$(( (r + i) % 3 ))
    for j in 0 1 2; do
      v=${variants[$(( (k + j) % 3 ))]}
      envs=(); [ "$profile" != none ] && envs=("XRAY_TUN_PROFILE=$profile")
      line=$(CLIENT=/target/bin/xray-rust-rb-$v /runs/run-one-v2.sh "rb3-$profile-${ITERATIONS:-4096}-d${DELAY_MS:-0}-r$r-$v" "$traffic" "$flows" "${envs[@]}")
      echo "{\"round\": $r, \"variant\": \"$v\", \"position\": $j, \"profile\": \"$profile\", \"iterations\": ${ITERATIONS:-4096}, \"delay_ms\": ${DELAY_MS:-0}, \"result\": $line}" >> "$outfile"
    done
    i=$((i+1))
  done
done
echo DONE > "$outfile.done"

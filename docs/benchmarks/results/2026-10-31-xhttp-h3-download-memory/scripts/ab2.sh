#!/bin/bash
# ab2.sh <rounds> <outfile> <profile|none> <traffic:flows>...
# Interleaved A/B of /target/bin/xray-rust-ab2-{before,after} with
# run-one-v2.sh; the order alternates across rounds and scenarios.
# ITERATIONS passes through to the harness (default 4096 x 64 KiB).
rounds=$1; outfile=$2; profile=$3; shift 3
export HARNESS=/target/bin/xray-bench-ab
for r in $(seq 1 "$rounds"); do
  i=0
  for sc in "$@"; do
    traffic=${sc%:*}; flows=${sc#*:}
    if [ $(( (r + i) % 2 )) -eq 1 ]; then order="before after"; else order="after before"; fi
    for v in $order; do
      envs=(); [ "$profile" != none ] && envs=("XRAY_TUN_PROFILE=$profile")
      line=$(CLIENT=/target/bin/xray-rust-ab2-$v /runs/run-one-v2.sh "ab2-$profile-${ITERATIONS:-4096}-r$r-$v" "$traffic" "$flows" "${envs[@]}")
      echo "{\"round\": $r, \"variant\": \"$v\", \"profile\": \"$profile\", \"iterations\": ${ITERATIONS:-4096}, \"result\": $line}" >> "$outfile"
    done
    i=$((i+1))
  done
done
echo DONE > "$outfile.done"

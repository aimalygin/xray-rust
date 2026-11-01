#!/bin/bash
# attr.sh <rounds>: instrumented client, h3 read-ahead variants none/full,
# interleaved with alternating order; memlogs to /runs/memlogs/attr-*.log.
for r in $(seq 1 "$1"); do
  if [ $((r % 2)) -eq 1 ]; then order="none full"; else order="full none"; fi
  for v in $order; do
    line=$(CLIENT=/target/bin/xray-rust-memexp5 /runs/run-mem.sh attr-r$r-$v download 32 XRAY_EXP_MEMLOG=/runs/memlogs/attr-r$r-$v.log XRAY_EXP_H3_FIX=$v)
    echo "{\"round\": $r, \"variant\": \"$v\", \"result\": $line}" >> /runs/attr.jsonl
  done
done

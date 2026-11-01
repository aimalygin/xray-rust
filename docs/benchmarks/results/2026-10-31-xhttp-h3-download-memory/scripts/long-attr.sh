#!/bin/bash
# long-attr.sh <rounds>: instrumented final build, 16,384 x 64 KiB downloads,
# h3 read-ahead variants none/next/full in rotating order.
for r in $(seq 1 "$1"); do
  case $((r % 3)) in 1) order="none next full" ;; 2) order="next full none" ;; 0) order="full none next" ;; esac
  for v in $order; do
    line=$(CLIENT=/target/bin/xray-rust-memexp5 ITERATIONS=16384 /runs/run-mem.sh long5-r$r-$v download 32 XRAY_EXP_MEMLOG=/runs/memlogs/long5-r$r-$v.log XRAY_EXP_H3_FIX=$v)
    echo "{\"round\": $r, \"variant\": \"$v\", \"result\": $line}" >> /runs/long5.jsonl
  done
done

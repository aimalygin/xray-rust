#!/bin/bash
# Four rotated 32-download runs per build (before, timed, cap) with
# run-mem.sh's 100 ms /proc series, to see how high and when each peaks.
export HARNESS=/target/bin/xray-bench-ab
variants=(before timed cap)
for r in 1 2 3 4; do
  for j in 0 1 2; do
    v=${variants[$(( (r + j) % 3 ))]}
    line=$(CLIENT=/target/bin/xray-rust-rb-$v /runs/run-mem.sh "timed-series-r$r-$v" download 32)
    echo "{\"round\": $r, \"variant\": \"$v\", \"result\": $line}" >> /runs/timed-series.jsonl
  done
done

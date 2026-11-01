#!/bin/bash
# Four rotated 32-download runs per build (before, timed, floor) with
# run-mem.sh's 100 ms /proc series.
export HARNESS=/target/bin/xray-bench-ab
variants=(before timed floor)
for r in 1 2 3 4; do
  for j in 0 1 2; do
    v=${variants[$(( (r + j) % 3 ))]}
    line=$(CLIENT=/target/bin/xray-rust-rb-$v /runs/run-mem.sh "floor-series-r$r-$v" download 32)
    echo "{\"round\": $r, \"variant\": \"$v\", \"result\": $line}" >> /runs/floor-series.jsonl
  done
done

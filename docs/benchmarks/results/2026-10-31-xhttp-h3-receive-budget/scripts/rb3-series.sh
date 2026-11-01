#!/bin/bash
# Two rotated 32-download runs per build with run-mem.sh's 100 ms /proc
# series, to see when each peak happens; results in rb3-series.jsonl.
export HARNESS=/target/bin/xray-bench-ab
variants=(before cap behind)
for r in 1 2; do
  for j in 0 1 2; do
    v=${variants[$(( (r + j) % 3 ))]}
    line=$(CLIENT=/target/bin/xray-rust-rb-$v /runs/run-mem.sh "rb3-series-r$r-$v" download 32)
    echo "{\"round\": $r, \"variant\": \"$v\", \"result\": $line}" >> /runs/rb3-series.jsonl
  done
done

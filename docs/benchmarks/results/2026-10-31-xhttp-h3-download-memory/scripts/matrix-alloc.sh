#!/bin/bash
# matrix-alloc.sh <rounds> <outfile> <traffic:flows> <variant>...
# Interleaves allocator wrappers (/runs/wrappers/<variant>.sh) of one client;
# the variant order rotates each round. One JSON line per run.
rounds=$1; outfile=$2; sc=$3; shift 3
traffic=${sc%:*}; flows=${sc#*:}
variants=("$@"); n=${#variants[@]}
for r in $(seq 1 "$rounds"); do
  for i in $(seq 0 $((n - 1))); do
    v=${variants[$(( (i + r) % n ))]}
    line=$(CLIENT=/runs/wrappers/$v.sh MATCH=${MATCH:-/target/bin/xray-rust-after} /runs/run-mem.sh "alloc-r$r-$v" "$traffic" "$flows")
    echo "{\"round\": $r, \"variant\": \"$v\", \"result\": $line}" >> "$outfile"
  done
done
echo DONE > "$outfile.done"

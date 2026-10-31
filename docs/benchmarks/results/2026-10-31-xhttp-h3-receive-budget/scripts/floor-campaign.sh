#!/bin/bash
# before, timed (e970cae1) and floor (95280e73), rotated, on loopback:
# default profile 5 rounds, long downloads 3 rounds, the mobile profile 3
# rounds, then four 32-download /proc series per build.
export VARIANTS="before timed floor"
/runs/rbn.sh 5 /runs/floor-default.jsonl none download:32 full-duplex:32 upload:32 download:8 download:1 full-duplex:1 upload:1
ITERATIONS=16384 /runs/rbn.sh 3 /runs/floor-long.jsonl none download:32
/runs/rbn.sh 3 /runs/floor-mobile.jsonl mobile download:32 full-duplex:32 upload:32 download:8 download:1
/runs/floor-series.sh

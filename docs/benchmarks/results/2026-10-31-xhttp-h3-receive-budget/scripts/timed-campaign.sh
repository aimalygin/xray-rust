#!/bin/bash
# before against timed (e970cae1) on loopback: default profile 5 rounds,
# long downloads 3 rounds, the mobile profile 3 rounds, then the /proc series.
/runs/rbn.sh 5 /runs/timed-default.jsonl none download:32 full-duplex:32 upload:32 download:8 download:1 full-duplex:1 upload:1
ITERATIONS=16384 /runs/rbn.sh 3 /runs/timed-long.jsonl none download:32
/runs/rbn.sh 3 /runs/timed-mobile.jsonl mobile download:32 full-duplex:32 upload:32 download:8 download:1

#!/bin/bash
# The loopback runs: default profile 5 rounds (eight downloads get the
# 2 MiB handshake window as their share there), long downloads 3 rounds,
# the mobile profile 3 rounds (eight downloads get 512 KiB each), then
# two 32-download runs per build with a 100 ms /proc series.
/runs/rb3.sh 5 /runs/rb3-default.jsonl none download:32 full-duplex:32 upload:32 download:8 download:1 full-duplex:1 upload:1
ITERATIONS=16384 /runs/rb3.sh 3 /runs/rb3-long.jsonl none download:32
/runs/rb3.sh 3 /runs/rb3-mobile.jsonl mobile download:32 full-duplex:32 upload:32 download:8 download:1
/runs/rb3-series.sh

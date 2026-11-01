#!/bin/bash
# The whole A/B: default profile 5 rounds, long downloads 3 rounds, mobile 3 rounds.
/runs/ab2.sh 5 /runs/ab2-default.jsonl none download:32 full-duplex:32 upload:32 download:1 full-duplex:1 upload:1
ITERATIONS=16384 /runs/ab2.sh 3 /runs/ab2-long.jsonl none download:32
/runs/ab2.sh 3 /runs/ab2-mobile.jsonl mobile download:32 full-duplex:32 upload:32

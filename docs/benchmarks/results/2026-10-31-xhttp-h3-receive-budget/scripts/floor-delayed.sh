#!/bin/bash
# before, timed and floor, rotated, on the delayed path (--cap-add NET_ADMIN):
# at about 54 ms one download 6 rounds and eight downloads 8 rounds, at about
# 113 ms 6 rounds each.
set -u
export VARIANTS="before timed floor"
/runs/delayed.sh 20 /runs/rbn.sh 6 /runs/floor-delayed.jsonl none download:1
/runs/delayed.sh 20 /runs/rbn-from.sh 1 8 /runs/floor-delayed.jsonl none download:8
/runs/delayed.sh 50 /runs/rbn.sh 6 /runs/floor-delayed.jsonl none download:1 download:8

#!/bin/bash
# More rounds where the first before/timed runs were noisy (rounds numbered
# after the first campaign's): one download on loopback, ten rounds; eight
# downloads at about 54 ms, eight rounds (with --cap-add NET_ADMIN); then the
# 32-download /proc series of before, timed and cap.
set -u
/runs/rbn-from.sh 6 15 /runs/timed-extra-default.jsonl none download:1
/runs/delayed.sh 20 /runs/rbn-from.sh 5 12 /runs/timed-extra-delayed.jsonl none download:8
tc qdisc del dev lo root
/runs/timed-series.sh

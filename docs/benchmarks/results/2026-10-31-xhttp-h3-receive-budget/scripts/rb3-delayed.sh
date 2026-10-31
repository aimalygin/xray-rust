#!/bin/bash
# The delayed-path runs, with --cap-add NET_ADMIN: one download and eight
# downloads, 3 rounds each, at about 50 and 113 ms of added round trip
# (one-way netem 20 and 50 ms; delayed.sh records the measured round trip).
set -u
for d in 20 50; do
  /runs/delayed.sh "$d" /runs/rb3.sh 3 /runs/rb3-delayed.jsonl none download:1 download:8
done

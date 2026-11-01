#!/bin/bash
# Builds floor for Linux, then runs the loopback and delayed campaigns.
SP=/private/tmp/claude-501/-Users-antonmalygin-xray-rust--claude-worktrees-beautiful-dijkstra-bf07ae/9f34f254-3a4d-41c5-94d6-78e2c4a31a68/scratchpad
cd "$SP/linux"
echo "start $(date)"
./drun.sh /runs/build-floor.sh > build-floor.log 2>&1
echo "build exit $? $(date)"
./drun.sh /runs/floor-campaign.sh > floor-campaign.log 2>&1
echo "loopback done $(date)"
docker run --rm --cap-add NET_ADMIN -v xray-h3-target:/target -v "$SP/linux/bin":/xbin -v "$SP/linux/runs":/runs xray-h3-bench:netem /runs/floor-delayed.sh > floor-delayed.log 2>&1
echo "delayed done $(date)"

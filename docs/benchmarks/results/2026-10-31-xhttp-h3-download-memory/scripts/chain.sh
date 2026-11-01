#!/bin/bash
# Waits for the other session's macOS campaign to finish and the host to be
# quiet (no other benchmark driver, 1-minute load under 4), then runs the
# release A/B and the long instrumented runs in Docker.
S=/private/tmp/claude-501/-Users-antonmalygin-xray-rust--claude-worktrees-nice-lehmann-0efff9/50dfeae3-3271-4746-b4b8-3726590a951c/scratchpad
quiet=0
while [ $quiet -lt 6 ]; do
  if pgrep -f "ab/variants.py|run-migration-campaign|modes_table.py" >/dev/null; then quiet=0
  elif awk -v l="$(sysctl -n vm.loadavg | awk '{print $2}')" 'BEGIN { exit !(l < 4) }'; then quiet=$((quiet + 1))
  else quiet=0; fi
  sleep 10
done
echo "start $(date)"
"$S/linux/drun.sh" /runs/ab2-campaign.sh > "$S/linux/ab2-campaign.log" 2>&1
echo "ab2 done $(date)"
"$S/linux/drun.sh" /runs/long-attr.sh 2 > "$S/linux/long-attr.log" 2>&1
echo "long done $(date)"

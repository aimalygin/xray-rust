#!/bin/bash
# Counts, in a fixture server.log, flows to the fixture's ranges (198.51.100.0/24, 2001:db8::/32) and how many
# of them the reference Xray-core routed to [blocked] (the coordinator's measure, 2026-11-15).
for f in "$@"; do
  all=$(grep -E -c 'accepted (tcp|udp):(198\.51\.100\.[0-9]+|\[2001:db8:[0-9a-f:]*\]):' "$f")
  blk=$(grep -E 'accepted (tcp|udp):(198\.51\.100\.[0-9]+|\[2001:db8:[0-9a-f:]*\]):' "$f" | grep -c '\[blocked\]')
  echo "$f: fixture-range=$all blocked=$blk"
done

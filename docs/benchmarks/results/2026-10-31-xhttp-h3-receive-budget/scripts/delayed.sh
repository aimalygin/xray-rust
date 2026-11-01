#!/bin/bash
# delayed.sh <one-way ms> <command...>: holds every UDP packet on the
# container's loopback for <one-way ms>. Both directions cross lo, so the
# QUIC round trip grows by about twice that; TCP (the harness's SOCKS and
# sink legs) is not delayed. Needs --cap-add NET_ADMIN. The VM's netem adds
# more than configured, so the UDP round trip is measured first, appended to
# /runs/delayed-calibration.jsonl, and passed to the command as DELAY_MS.
set -euo pipefail
d=$1; shift
tc qdisc del dev lo root 2>/dev/null || true
tc qdisc add dev lo root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
tc qdisc add dev lo parent 1:3 handle 30: netem delay "${d}ms" limit 1000000
tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 17 0xff flowid 1:3
tc filter add dev lo parent 1: protocol ipv6 prio 2 u32 match ip6 protocol 17 0xff flowid 1:3
cal=$(python3 /runs/calibrate.py "one-way $d ms")
echo "$cal" >> /runs/delayed-calibration.jsonl
DELAY_MS=$(python3 -c 'import json, sys; print(round(json.loads(sys.argv[1])["udp_rtt_ms"]))' "$cal") "$@"

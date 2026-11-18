#!/bin/bash
# The iPhone LAN queue's runs by name, with this Mac pinging the router ten times a second meanwhile
# (test-bed setting from results/ios/diagnostics/arp-first-exchange/README.md: the fixture host is on Wi-Fi and
# answers the phone's ARP requests late when its radio is idle). The ping's output is kept beside the queue log.
# usage: queue-ios-lan-keepawake.sh <run> [<run> ...]
O=<stand>
GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
stamp=$(date -u +%H%M%S)
ping -i 0.1 "$GW" > "$O/results/keepawake-ping-$stamp.txt" 2>&1 &
ka=$!; trap 'kill -INT $ka 2>/dev/null' EXIT
echo "### keep-awake ping to the router running (results/keepawake-ping-$stamp.txt)"
for run in "$@"; do bash "$O/results/queue-ios-lan.sh" "$run" || { echo "### STOPPED at $run"; exit 1; }; done
echo "### keepawake queue finished"

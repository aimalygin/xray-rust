#!/bin/bash
# The iPhone host-adapter projection runs (0.10.0 runbook 3.5): installs the projection build, makes both
# runs through attempt.sh with the keep-awake ping running, and puts the main app back whatever happens.
O=<stand>; T=$O/tools
export IPHONE_UDID=<iphone-udid> DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
GW=$(route -n get default 2>/dev/null | awk '/gateway:/{print $2}')
stamp=$(date -u +%H%M%S); ping -i 0.1 "$GW" > "$O/results/keepawake-ping-$stamp.txt" 2>&1 &
ka=$!
restore() { kill -INT $ka 2>/dev/null
  xcrun devicectl device install app --device "$IPHONE_UDID" "$O/apple/XrayClient.app" > "$O/apple/reinstall-main-app.log" 2>&1 \
    && echo "### main app reinstalled" || echo "### MAIN APP REINSTALL FAILED"; }
trap restore EXIT
xcrun devicectl device install app --device "$IPHONE_UDID" "$O/apple/XrayClient-projection.app" > "$O/apple/install-projection-app.log" 2>&1 \
  || { echo "### projection app install failed"; exit 1; }
echo "### $(date -u +%T) projection app installed; keep-awake ping results/keepawake-ping-$stamp.txt"
last() { ls -d "$O/results/ios/$1"/attempt-* 2>/dev/null | sort -V | tail -1; }
r() { local run=$1 env=$2; echo "### $(date -u +%T) $run"
      LAUNCH_ENV="$env" $T/attempt.sh ios "$run" $T/run_apple_v010.sh run-v07-apple-protocol-fixture.py --protocol v09 --mode smoke 2>&1 | tail -2
      local a; a=$(last "$run"); local got; got=$(cat "$a/outcome.txt" 2>/dev/null || echo none)
      echo "### $(date -u +%T) $run ${a##*/}: $got"; [ "$got" = "done:passed" ]; }
r ios-projection-file-descriptor '{"XRAY_V07_DEVICE_PROBE":"1","XRAY_ADAPTER_PROJECTION_DEVICE_CHECK":"1"}' || { echo "### STOPPED"; exit 1; }
r ios-projection-packet-pump '{"XRAY_V07_DEVICE_PROBE":"1","XRAY_ADAPTER_PROJECTION_DEVICE_CHECK":"1","XRAY_PROJECTION_PACKET_PUMP":"1"}' || { echo "### STOPPED"; exit 1; }
echo "### $(date -u +%T) projection runs done"

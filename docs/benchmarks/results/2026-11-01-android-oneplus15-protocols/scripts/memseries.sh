#!/usr/bin/env bash
# usage: memseries.sh OUTDIR REPS CONFIG PROFILE:FLOWS...
# Peak RSS of the devicehost process with N concurrent downloads (VLESS raw via phone Go server).
# One fresh process per PROFILE:FLOWS, round-robin order shifted per repeat.
# 64 flows x 16 MiB (port 5404) or 256 flows x 4 MiB (port 5405), 1 GiB in total.
set -u
S=${ANDROID_SERIAL:?set ANDROID_SERIAL to the phone serial}
PKG=org.xrayrust.devicehost
HERE=$(cd "$(dirname "$0")/.." && pwd)  # result directory: configs/ sits beside scripts/
OUT=$1; REPS=$2; CFG=$3; shift 3
CASES=("$@")
mkdir -p "$OUT"
A="adb -s $S"
b64=$(sed "s/SERVER/127.0.0.1/" "$HERE/configs/client/$CFG.json" | base64)
start() {
  $A shell am start -n $PKG/.MainActivity --es command disconnect >/dev/null 2>&1
  sleep 2
  $A shell am force-stop $PKG
  sleep 1
  $A logcat -c
  $A shell am start --activity-clear-task -n $PKG/.MainActivity --es command connect --es exp-profile "$1" --es exp-config-b64 "$b64" >/dev/null 2>&1
  for _ in $(seq 1 40); do
    sleep 0.5
    if $A logcat -d -s XrayDeviceGate | grep -q "state=running"; then
      PID=$($A shell pidof $PKG | tr -d '\r')
      return 0
    fi
  done
  echo "start failed $1" >&2
  return 1
}
for rep in $(seq 1 "$REPS"); do
  n=${#CASES[@]}
  for k in $(seq 0 $((n-1))); do
    c=${CASES[$(( (k + rep) % n ))]}
    profile=${c%%:*}; flows=${c##*:}
    port=5404; [ "$flows" -gt 64 ] && port=5405
    start "$profile" || exit 1
    sleep 5
    tag="rep=$rep case=$c pid=$PID"
    line=$($A shell sh /data/local/tmp/protob/memtest.sh "$PID" 10001 "$flows" "$port" | tr -d '\r')
    echo "$line" | sed "s/^/$tag /" >> "$OUT/raw.txt"
    echo "$line" | grep memresult | sed "s/^/$tag /"
    $A shell am start -n $PKG/.MainActivity --es command close-connections >/dev/null 2>&1
    sleep 1
    $A logcat -d -s XrayDeviceGate | grep -E "XRAY_BENCH|XRAY_ANDROID_SAMPLE" | grep -v '"runtimeRunning":false' | sed -n '1p;$p' | sed "s/^/$tag /" >> "$OUT/samples.txt"
    $A shell am start -n $PKG/.MainActivity --es command disconnect >/dev/null 2>&1
    sleep 2
  done
done
$A shell am force-stop $PKG
echo done

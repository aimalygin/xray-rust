#!/usr/bin/env bash
# usage: series.sh OUTDIR REPS SERVER_ADDR CASESET CONFIG...
#   SERVER_ADDR: 127.0.0.1 (Go Xray on the phone) or the Mac LAN IP (Go Xray on the Mac)
#   CASESET: loop (dl/ul x1 x4, 1 GiB per case) | wifi (dl/ul x1, 128 MiB) | smoke (dl/ul x1 x4, 64 MiB)
# One fresh devicehost process per config, round-robin order shifted per repeat.
set -u
S=${ANDROID_SERIAL:?set ANDROID_SERIAL to the phone serial}
PKG=org.xrayrust.devicehost
HERE=$(cd "$(dirname "$0")/.." && pwd)  # result directory: configs/ sits beside scripts/
OUT=$1; REPS=$2; SRV=$3; SET=$4; shift 4
CFGS=("$@")
PROFILE=${PROFILE:-Mobile}
mkdir -p "$OUT"
A="adb -s $S"
port_of() {
  case $1 in
    vless-raw|vless-mux) echo 10001 ;;
    reality-vision) echo 10002 ;;
    xhttp-tls-h2|xhttp-tls-h2-streamup) echo 10003 ;;
    ss-aes256gcm) echo 10004 ;;
    ss-chacha20) echo 10005 ;;
    ss2022-aes256) echo 10006 ;;
    trojan-tls) echo 10007 ;;
  esac
}
restart() {
  local cfg=$1 b64
  b64=$(sed "s/SERVER/$SRV/" "$HERE/configs/client/$cfg.json" | base64)
  $A shell am start -n $PKG/.MainActivity --es command disconnect >/dev/null 2>&1
  sleep 2
  $A shell am force-stop $PKG
  sleep 1
  $A logcat -c
  $A shell am start --activity-clear-task -n $PKG/.MainActivity --es command connect --es exp-profile "$PROFILE" --es exp-config-b64 "$b64" >/dev/null 2>&1
  for _ in $(seq 1 40); do
    sleep 0.5
    if $A logcat -d -s XrayDeviceGate | grep -q "state=running"; then
      PID=$($A shell pidof $PKG | tr -d '\r')
      return 0
    fi
    if $A logcat -d -s XrayDeviceGate | grep -q "state=start-failed"; then break; fi
  done
  echo "start failed cfg=$cfg" >&2
  $A logcat -d -s XrayDeviceGate >&2
  return 1
}
run_case() {
  local tag=$1; shift
  local line
  line=$($A shell sh /data/local/tmp/protob/bench.sh "$PID" "$SPID" "$SPORT" "$@" | tr -d '\r')
  echo "$line" | sed "s/^/$tag /" >> "$OUT/raw.txt"
  echo "$line" | grep result | sed "s/^/$tag /"
}
if [ "$SRV" = 127.0.0.1 ]; then
  SPID=$($A shell pidof xray | tr -d '\r')
else
  SPID=$($A shell pidof $PKG | tr -d '\r'); SPID=${SPID:-1}
fi
for rep in $(seq 1 "$REPS"); do
  n=${#CFGS[@]}
  for k in $(seq 0 $((n-1))); do
    cfg=${CFGS[$(( (k + rep) % n ))]}
    SPORT=$(port_of "$cfg")
    restart "$cfg" || exit 1
    [ "$SRV" = 127.0.0.1 ] || SPID=$PID
    sleep 3
    tag="rep=$rep cfg=$cfg pid=$PID"
    echo "$tag $(date +%T) $($A shell dumpsys battery | grep -E ' (temperature|status|level):' | tr -d ' \r' | tr '\n' ' ')" >> "$OUT/battery.txt"
    run_case "$tag" idle 0 10 0
    case $SET in
      loop)
        run_case "$tag" dl 1 0 5401; sleep 2
        run_case "$tag" dl 4 0 5402; sleep 2
        run_case "$tag" ul 1 1073741824 5403; sleep 2
        run_case "$tag" ul 4 268435456 5406; sleep 2 ;;
      smoke)
        run_case "$tag" dl 1 0 5404; sleep 1
        run_case "$tag" dl 4 0 5404; sleep 1
        run_case "$tag" ul 1 16777216 5407; sleep 1
        run_case "$tag" ul 4 16777216 5407; sleep 1 ;;
      wifi)
        run_case "$tag" dl 1 0 5304; sleep 2
        run_case "$tag" ul 1 134217728 5303; sleep 2 ;;
    esac
    $A shell am start -n $PKG/.MainActivity --es command close-connections >/dev/null 2>&1
    sleep 1
    $A logcat -d -s XrayDeviceGate | grep -E "XRAY_BENCH|XRAY_ANDROID_SAMPLE" | grep -v '"runtimeRunning":false' | sed -n '1p;$p' | sed "s/^/$tag /" >> "$OUT/samples.txt"
    $A shell am start -n $PKG/.MainActivity --es command disconnect >/dev/null 2>&1
    sleep 2
  done
done
$A shell am force-stop $PKG
echo done

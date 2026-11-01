#!/usr/bin/env bash
# usage: hostctl.sh start CONFIG [SERVER_ADDR] | stop
# Starts one devicehost process with a client config (debug helper, same start path as series.sh).
set -u
S=${ANDROID_SERIAL:?set ANDROID_SERIAL to the phone serial}
PKG=org.xrayrust.devicehost
HERE=$(cd "$(dirname "$0")/.." && pwd)  # result directory: configs/ sits beside scripts/
A="adb -s $S"
$A shell am start -n $PKG/.MainActivity --es command disconnect >/dev/null 2>&1
sleep 2
$A shell am force-stop $PKG
[ "$1" = stop ] && exit 0
b64=$(sed "s/SERVER/${3:-127.0.0.1}/" "$HERE/configs/client/$2.json" | base64)
$A logcat -c
$A shell am start --activity-clear-task -n $PKG/.MainActivity --es command connect --es exp-profile "${PROFILE:-Mobile}" --es exp-config-b64 "$b64" >/dev/null
sleep 3
$A logcat -d -s XrayDeviceGate

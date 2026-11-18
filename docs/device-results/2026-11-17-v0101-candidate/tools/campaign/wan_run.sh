#!/bin/bash
# usage: wan_run.sh <android|ios> <mkcp|masque|xhttp-h3|xicmp>   (android: xicmp only on this candidate)
# One run against the fixture on the VPS as an attempt, N first free, three at most:
#   mkcp, masque, xhttp-h3 -> results/<platform>/<platform>-wan-<kind>/attempt-N, network change
#     (RUNBOOK "Runs 2 and 5" and Android "Network change, WAN");
#   xicmp -> results/<platform>/<platform>-xicmp/attempt-N, the smoke set (xicmp's server needs a
#     Linux host; the fixture runs as root there, ICMP echo must be open at the provider).
# mKCP and xicmp carry VLESS, which the core refuses toward a public address without encryption,
# so they get the candidate fixture's own --vless-encryption (docs/v010-release-evidence.md).
# Starts the remote fixture on the VPS (UDP 53053), copies its envelope to attempt-N/probe.json,
# runs the device through attempt.sh with ATTEMPT=N and PROBE_FILE, erases the envelope, stops
# the remote fixture with SIGINT (it removes its credentials) and keeps its server.log.
set -u
platform="${1:?android|ios}"; kind="${2:?mkcp|masque|xhttp-h3|xicmp}"
O=<stand>; T=$O/tools
WAN=xray-vps; PORT=53053; ARCH=amd64
XSHA=eb615ae57b35196b7bdd4e525bb3528a2f716bf6a2857662617dbf4b1a2904f5
R=/tmp/xray-0100-wan
export ANDROID_SERIAL=<samsung-serial> ADB_MDNS=0 ADB=$HOME/Library/Android/sdk/platform-tools/adb
export IPHONE_UDID=<iphone-udid> DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
case "$platform/$kind" in
  android/mkcp|android/masque|android/xhttp-h3)
    # The owner's decision of 2026-11-15 («Снять с Android»): the Android network change is not
    # tested on this candidate (no cellular data on the test device); docs/v0100-release.md item 5.
    echo "$platform/$kind: the Android network change is not tested on 0.10.0 (owner, 2026-11-15)"; exit 2 ;;
  android/xicmp) script=scripts/run-v08-android-protocol-fixture.py; fargs="--suite v010 --protocol xicmp --vless-encryption" ;;
  ios/mkcp) script=scripts/run-v07-apple-protocol-fixture.py; fargs="--protocol mkcp --mode transitions --vless-encryption" ;;
  ios/masque) script=scripts/run-v07-apple-protocol-fixture.py; fargs="--protocol masque --mode transitions" ;;
  ios/xicmp) script=scripts/run-v07-apple-protocol-fixture.py; fargs="--protocol xicmp --mode smoke --vless-encryption" ;;
  ios/xhttp-h3) script=scripts/run-v08-apple-acceptance-fixture.py; fargs="--suite xhttp-h3-v010 --mode transitions" ;;
  *) echo "unknown $platform/$kind"; exit 2 ;;
esac
run=$platform-wan-$kind; [ "$kind" = xicmp ] && run=$platform-xicmp
dir=$O/results/$platform/$run
mkdir -p "$dir"; chmod 700 "$dir"
n=1; while [ -e "$dir/attempt-$n" ]; do n=$((n + 1)); done
[ "$n" -le 3 ] || { echo "$dir already has three attempts"; exit 1; }
D=$dir/attempt-$n; mkdir "$D"
PUB=$(ssh $WAN "ip -4 -o addr show dev ens6 scope global | awk '{print \$4}' | cut -d/ -f1")
[ -n "$PUB" ] || { echo "no public address"; exit 1; }
rout=$R/$run-a$n-fixture
cmd="cd $R/xray-rust-7503d1a4 && exec python3 $script $fargs --bind $PUB --port $PORT --reference-binary $R/xray-linux-$ARCH --reference-sha256 $XSHA --output $rout --seconds 1800"
{ echo "fixture (remote, $WAN): $cmd"; date -u +fixture-started=%FT%TZ; } > "$D/fixture-command.txt"
ssh $WAN "$cmd" > "$D/fixture.log" 2>&1 < /dev/null &
sshpid=$!
echo "== $run attempt-$n: remote fixture starting"
ready=; for _ in $(seq 1 45); do ssh $WAN "test -f $rout/v07-probe.json" && { ready=1; break; }; kill -0 $sshpid 2>/dev/null || break; sleep 2; done
rc=1
if [ -n "$ready" ]; then
  scp -q $WAN:$rout/v07-probe.json "$D/probe.json" && chmod 600 "$D/probe.json"
  if [ "$kind" = xicmp ] && [ "$platform" = android ]; then
    ATTEMPT=$n PROBE_FILE=$D/probe.json $T/attempt.sh android $run $T/run_android_v010.sh 2>&1 | tail -4
  elif [ "$kind" = xicmp ]; then
    ATTEMPT=$n PROBE_FILE=$D/probe.json $T/attempt.sh ios $run $T/run_apple_v010.sh 2>&1 | tail -4
  elif [ "$platform" = android ]; then
    ATTEMPT=$n PROBE_FILE=$D/probe.json $T/attempt.sh android $run $T/run_android_v010.sh -- --network-change 2>&1 | tail -4
  else
    ATTEMPT=$n PROBE_FILE=$D/probe.json RUN_SECONDS=1700 $T/attempt.sh ios $run $T/run_apple_v010.sh 2>&1 | tail -4
  fi
  rc=${PIPESTATUS[0]}
  rm -P "$D/probe.json"
else
  echo "remote fixture not ready; see $D/fixture.log"
fi
ssh $WAN "pkill -INT -f '[p]ython3 scripts/.*--output $rout'"
for _ in $(seq 1 30); do kill -0 $sshpid 2>/dev/null || break; sleep 1; done
kill $sshpid 2>/dev/null; wait $sshpid 2>/dev/null
scp -q $WAN:$rout/server.log "$D/server.log" 2>/dev/null || echo "no server.log"
ssh $WAN "pgrep -f '[x]ray-linux.*$rout' >/dev/null && echo 'remote xray still running' || echo 'remote fixture gone'" | tee -a "$D/fixture-command.txt"
echo "== $run attempt-$n: rc=$rc"
exit $rc

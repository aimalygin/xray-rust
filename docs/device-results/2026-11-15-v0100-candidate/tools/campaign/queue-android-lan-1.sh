#!/bin/bash
# Android LAN runs of the fourth candidate, RUNBOOK sections 2 and 3 in order (owner «теперь устройства»,
# order «Сначала VPS», so these come after the public-host runs). Each run goes through attempt.sh.
# The queue stops at the first non-zero outcome so a failure is looked at before anything else runs.
O=<stand>; T=$O/tools
export ANDROID_SERIAL=<samsung-serial> ADB_MDNS=0 ADB=$HOME/Library/Android/sdk/platform-tools/adb
last() { ls -d "$O/results/android/$1"/attempt-* 2>/dev/null | sort -V | tail -1; }
r() { local run=$1 want=$2; shift 2; echo "### $(date -u +%T) $run"; "$@" 2>&1 | tail -2
      local a; a=$(last "$run"); local got; got=$(cat "$a/outcome.txt" 2>/dev/null || echo none)
      echo "### $(date -u +%T) $run ${a##*/}: $got"
      [ "$got" = "$want" ] || { echo "### STOP: $run ${a##*/} is '$got', expected '$want'"; exit 1; }; }
r android-v010 "driver exit=0" $T/attempt.sh android android-v010 $T/run_android_v010.sh --suite v010 --protocol v010
r android-smoke-v010 "driver exit=0" $T/attempt.sh android android-smoke-v010 $T/run_android_v010.sh --suite v010 --protocol smoke-v010
r android-legacy-v010 "driver exit=0" $T/attempt.sh android android-legacy-v010 $T/run_android_v010.sh --suite legacy-v010
r android-import-v010 "driver exit=0" $T/attempt.sh android android-import-v010 $T/run_android_v010.sh --suite v010 --protocol import-v010
r android-cancel-tcp "collector exit=0" $T/attempt.sh android android-cancel-tcp $T/run_collector_v010.sh local_cancel_v010.py -- --suite v010 --protocol v010
r android-cancel-udp "collector exit=0" $T/attempt.sh android android-cancel-udp $T/run_collector_v010.sh udp_cancel_v010.py --suite v010 -- --suite v010 --protocol v010 --udp-delay-seconds 3
r android-resources "collector exit=0" $T/attempt.sh android android-resources $T/run_collector_v010.sh resources_v010.py -- --suite v010 --protocol v010
r android-shared "collector exit=0" $T/attempt.sh android android-shared $T/shared/run_android_shared.sh
r android-cancel-tcp-v09 "collector exit=0" $T/attempt.sh android android-cancel-tcp-v09 $T/run_collector_v010.sh shared/local_cancel_v09.py -- --suite v09 --protocol v09
r android-cancel-udp-v09 "collector exit=0" $T/attempt.sh android android-cancel-udp-v09 $T/run_collector_v010.sh shared/udp_cancel_v09.py --suite v09 -- --suite v09 --protocol v09 --udp-delay-seconds 3
echo "### $(date -u +%T) queue done"

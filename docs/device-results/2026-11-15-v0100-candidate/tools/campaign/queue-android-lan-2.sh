#!/bin/bash
# Android LAN runs of the fourth candidate, continued after android-resources attempt-1 stopped queue 1 (MASQUE TCP flow
# budget of 16 vs the stress concurrency of 32; not retried). The three runs left; independent of that limit.
# Each run goes through attempt.sh.
# The queue stops at the first non-zero outcome so a failure is looked at before anything else runs.
O=<stand>; T=$O/tools
export ANDROID_SERIAL=<samsung-serial> ADB_MDNS=0 ADB=$HOME/Library/Android/sdk/platform-tools/adb
last() { ls -d "$O/results/android/$1"/attempt-* 2>/dev/null | sort -V | tail -1; }
r() { local run=$1 want=$2; shift 2; echo "### $(date -u +%T) $run"; "$@" 2>&1 | tail -2
      local a; a=$(last "$run"); local got; got=$(cat "$a/outcome.txt" 2>/dev/null || echo none)
      echo "### $(date -u +%T) $run ${a##*/}: $got"
      [ "$got" = "$want" ] || { echo "### STOP: $run ${a##*/} is '$got', expected '$want'"; exit 1; }; }
r android-shared "collector exit=0" $T/attempt.sh android android-shared $T/shared/run_android_shared.sh
r android-cancel-tcp-v09 "collector exit=0" $T/attempt.sh android android-cancel-tcp-v09 $T/run_collector_v010.sh shared/local_cancel_v09.py -- --suite v09 --protocol v09
r android-cancel-udp-v09 "collector exit=0" $T/attempt.sh android android-cancel-udp-v09 $T/run_collector_v010.sh shared/udp_cancel_v09.py --suite v09 -- --suite v09 --protocol v09 --udp-delay-seconds 3
echo "### $(date -u +%T) queue done"

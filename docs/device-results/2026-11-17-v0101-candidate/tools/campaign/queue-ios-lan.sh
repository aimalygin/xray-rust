#!/bin/bash
# iPhone LAN runs on the 0.10.1 candidate's tree (owner «Только затронутое», 2026-11-16: the LAN runs are
# made again, the public-host runs are carried over from the 0.10.0 campaign). The runs and their order are
# those of the 0.10.0 runbooks (device-706a766c.noindex/RUNBOOK.md sections 1 and 3.1). Each run goes through
# attempt.sh. The queue stops at the first unexpected outcome so a failure is looked at before anything else runs.
O=<stand>; T=$O/tools
export IPHONE_UDID=<iphone-udid> DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
last() { ls -d "$O/results/ios/$1"/attempt-* 2>/dev/null | sort -V | tail -1; }
r() { local run=$1 want=$2; shift 2; echo "### $(date -u +%T) $run"; "$@" 2>&1 | tail -2
      local a; a=$(last "$run"); local got; got=$(cat "$a/outcome.txt" 2>/dev/null || echo none)
      echo "### $(date -u +%T) $run ${a##*/}: $got"
      [ "$got" = "$want" ] || { echo "### STOP: $run ${a##*/} is '$got', expected '$want'"; exit 1; }; }
only="${1:-all}"
want() { [ "$only" = all ] || [ "$only" = "$1" ]; }
want ios-v010-smoke && r ios-v010-smoke "done:passed" $T/attempt.sh ios ios-v010-smoke $T/run_apple_v010.sh run-v07-apple-protocol-fixture.py --protocol v010 --mode smoke
want ios-v010-lifecycle && r ios-v010-lifecycle "done:passed" $T/attempt.sh ios ios-v010-lifecycle $T/run_apple_v010.sh run-v07-apple-protocol-fixture.py --protocol v010 --mode lifecycle
want ios-v010-resources && r ios-v010-resources "done:passed" $T/attempt.sh ios ios-v010-resources $T/run_apple_v010.sh run-v07-apple-protocol-fixture.py --protocol v010 --mode resources
want ios-smoke-v010 && r ios-smoke-v010 "done:passed" $T/attempt.sh ios ios-smoke-v010 $T/run_apple_v010.sh run-v07-apple-protocol-fixture.py --protocol smoke-v010 --mode smoke
want ios-legacy-v010 && r ios-legacy-v010 "done:passed" env WARMUP_SECONDS=10 $T/attempt.sh ios ios-legacy-v010 $T/run_apple_v010.sh run-v08-apple-acceptance-fixture.py --suite legacy-v010 --mode smoke
want ios-import-v010 && r ios-import-v010 "done:passed" $T/attempt.sh ios ios-import-v010 $T/run_apple_v010.sh run-v07-apple-protocol-fixture.py --protocol import-v010 --mode smoke
want ios-shared && r ios-shared "done:passed" $T/attempt.sh ios ios-shared $T/run_apple_v010.sh $T/shared/shared_fixture_v09.py --platform apple
# The negative control must fail: literal-IP TCP passes, the synthetic name does not.
want ios-fakedns-negative && r ios-fakedns-negative "done:failed" $T/attempt.sh ios ios-fakedns-negative $T/run_apple_v010.sh $T/shared/shared_fixture_v09.py --platform apple --ip-strategy AsIs --only ip-on-demand
want ios-fakedns-recovery && r ios-fakedns-recovery "done:passed" $T/attempt.sh ios ios-fakedns-recovery $T/run_apple_v010.sh $T/shared/shared_fixture_v09.py --platform apple --only ip-on-demand
echo "### $(date -u +%T) queue done"

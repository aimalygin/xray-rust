#!/usr/bin/env bash
# usage: attempt.sh <platform> <run> <runner> [runner args...]
# Runs one attempt of a campaign run under results/<platform>/<run>/attempt-N/, N the
# first free number. Every runner below writes its fixture (fixture/, fixture.log), the
# device output and command.txt inside that attempt directory and refuses to reuse one.
# With PROBE_FILE (fixture started elsewhere: WAN host or sudo xicmp) pass ATTEMPT=N
# explicitly, because the fixture was already started into attempt-N/fixture.
set -u
platform="${1:?platform (ios|android)}"; run="${2:?run name}"; runner="${3:?runner}"; shift 3
O=<stand>
dir=$O/results/$platform/$run
mkdir -p "$dir"; chmod 700 $O/results "$O/results/$platform" "$dir" 2>/dev/null
if [ -n "${ATTEMPT:-}" ]; then
  n=$ATTEMPT
else
  n=1; while [ -e "$dir/attempt-$n" ]; do n=$((n + 1)); done
fi
[ "$n" -le 3 ] || { echo "$dir already has three attempts: stop this run and go on"; exit 1; }
echo "== $platform/$run attempt-$n"
CAMPAIGN_DIR="$dir" exec "$runner" "attempt-$n" "$@"

#!/usr/bin/env bash
# usage: run_collector_v010.sh <name> <collector.py> [collector args] -- <android fixture args...>
# Normally called through attempt.sh (CAMPAIGN_DIR=results/android/<run>, <name>=attempt-N).
# v0.10 copy of docs/device-results/2026-11-02-v090-candidate/tools/run_collector.sh, for the
# Android cancellation and resource runs (local_cancel_v010.py, udp_cancel_v010.py,
# resources_v010.py, shared/local_cancel_v09.py, shared/udp_cancel_v09.py). Differences:
# paths of candidate 7eb199bb, ANDROID_SERIAL from the environment, everything inside the
# attempt directory (fixture/, fixture.log, device/ = RUN_DIR, collector.log, command.txt),
# an existing attempt refused.
set -u
name="${1:?run name}"; collector="${2:?collector}"; shift 2
cargs=(); while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do cargs+=("$1"); shift; done; shift
O=<stand>
CANDIDATE=$O/candidate
C="${CAMPAIGN_DIR:-$O/campaign}"
T=$O/tools
REF=<perf>/xray
: "${ANDROID_SERIAL:?set ANDROID_SERIAL (adb devices)}"
export PATH="/opt/homebrew/opt/python@3.12/libexec/bin:$HOME/sdk/go1.27.3/bin:$PATH"
cd "$CANDIDATE" || exit 1
[ "$(git rev-parse 'HEAD^{tree}')" = b637ff77211f6dc1aa865779d42b0325a7c7cc86 ] || { echo "$CANDIDATE is not candidate 7eb199bb"; exit 1; }
out="$C/$name"
[ -e "$out" ] && { echo "$out exists: keep it and use the next attempt"; exit 1; }
mkdir -p "$C"; chmod 700 "$C"; mkdir "$out"
BIND="${BIND:-$(ipconfig getifaddr en1)}"
{ printf 'cwd: %s\n' "$PWD"; printf 'command:'; printf ' %q' "$0" "$name" "$collector" "${cargs[@]+"${cargs[@]}"}" -- "$@"; printf '\n'
  printf 'fixture: python3 scripts/run-v08-android-protocol-fixture.py --bind %s --reference-binary %s --output %s --seconds 1800 %s\n' \
    "$BIND" "$REF" "$out/fixture" "$*"
  printf 'ANDROID_SERIAL=%s\n' "$ANDROID_SERIAL"; date -u +started=%FT%TZ; } > "$out/command.txt"
python3 scripts/run-v08-android-protocol-fixture.py --bind "$BIND" --reference-binary "$REF" \
  --output "$out/fixture" --seconds 1800 "$@" > "$out/fixture.log" 2>&1 &
fixture=$!
trap 'kill -INT $fixture 2>/dev/null; wait $fixture' EXIT
for _ in $(seq 1 60); do [ -f "$out/fixture/v07-probe.json" ] && break; sleep 1; done
[ -f "$out/fixture/v07-probe.json" ] || { echo "fixture not ready; see $out/fixture.log"; exit 1; }
sleep "${WARMUP_SECONDS:-10}"
RUN_DIR="$out/device" FIXTURE_DIR="$out/fixture" FIXTURE_LOG="$out/fixture.log" \
  ANDROID_SERIAL="$ANDROID_SERIAL" ADB="$HOME/Library/Android/sdk/platform-tools/adb" PYTHONPATH="$T" \
  python3 "$T/$collector" "${cargs[@]+"${cargs[@]}"}" > "$out/collector.log" 2>&1
rc=$?
echo "collector exit=$rc" | tee "$out/outcome.txt"
echo "events: $out/device/events.jsonl"
exit $rc

#!/usr/bin/env bash
# usage: run_android_v010.sh <name> <android fixture args...> [-- <matrix driver args...>]
#        PROBE_FILE=<v07-probe.json> run_android_v010.sh <name> [-- <matrix driver args...>]
# Normally called through attempt.sh (CAMPAIGN_DIR=results/android/<run>, <name>=attempt-N).
# One Android matrix of docs/v010-release-evidence.md "Android": starts
# scripts/run-v08-android-protocol-fixture.py on this Mac's LAN address into <attempt>/fixture
# (unless PROBE_FILE names the envelope of a fixture already running: WAN host, or xicmp
# under sudo), then scripts/run-v09-android-device-matrix.py --package-suffix .v010 with
# --work-dir <attempt>/device (events.jsonl, logcat). command.txt records the invocation.
set -u
name="${1:?run name}"; shift
fixture_args=(); while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do fixture_args+=("$1"); shift; done
[ "$#" -gt 0 ] && shift
O=<stand>
CANDIDATE=$O/candidate
C="${CAMPAIGN_DIR:-$O/campaign}"
REF=<perf>/xray
: "${ANDROID_SERIAL:?set ANDROID_SERIAL (adb devices)}"
export ANDROID_SERIAL
export ADB="${ADB:-$HOME/Library/Android/sdk/platform-tools/adb}"
export PATH="/opt/homebrew/opt/python@3.12/libexec/bin:$HOME/sdk/go1.27.3/bin:$PATH"
cd "$CANDIDATE" || exit 1
[ "$(git rev-parse 'HEAD^{tree}')" = b637ff77211f6dc1aa865779d42b0325a7c7cc86 ] || { echo "$CANDIDATE is not candidate 7eb199bb"; exit 1; }
out="$C/$name"
if [ -n "${PROBE_FILE:-}" ]; then
  [ -e "$out/device" ] && { echo "$out was already run: use the next attempt"; exit 1; }
else
  [ -e "$out" ] && { echo "$out exists: keep it and use the next attempt"; exit 1; }
fi
mkdir -p "$C"; chmod 700 "$C"; mkdir -p "$out"
{ printf 'cwd: %s\n' "$PWD"; printf 'command:'; printf ' %q' "$0" "$name" "${fixture_args[@]+"${fixture_args[@]}"}" -- "$@"; printf '\n'
  for v in PROBE_FILE FIXTURE_SECONDS BIND ANDROID_SERIAL ADB; do
    [ -n "${!v:-}" ] && printf '%s=%s\n' "$v" "${!v}"; done; date -u +started=%FT%TZ; } > "$out/command.txt"
if [ -n "${PROBE_FILE:-}" ]; then
  probe="$PROBE_FILE"
  [ -f "$probe" ] || { echo "no $probe"; exit 1; }
else
  BIND="${BIND:-$(ipconfig getifaddr en1)}"
  printf 'fixture: python3 scripts/run-v08-android-protocol-fixture.py --bind %s --reference-binary %s --output %s --seconds %s %s\n' \
    "$BIND" "$REF" "$out/fixture" "${FIXTURE_SECONDS:-1800}" "${fixture_args[*]}" >> "$out/command.txt"
  python3 scripts/run-v08-android-protocol-fixture.py --bind "$BIND" --reference-binary "$REF" \
    --output "$out/fixture" --seconds "${FIXTURE_SECONDS:-1800}" "${fixture_args[@]}" > "$out/fixture.log" 2>&1 &
  fixture=$!
  trap 'kill -INT $fixture 2>/dev/null; wait $fixture' EXIT
  for _ in $(seq 1 60); do [ -f "$out/fixture/v07-probe.json" ] && break; sleep 1; done
  [ -f "$out/fixture/v07-probe.json" ] || { echo "fixture not ready; see $out/fixture.log"; exit 1; }
  probe="$out/fixture/v07-probe.json"
fi
printf 'driver: python3 scripts/run-v09-android-device-matrix.py --fixture %s --work-dir %s --package-suffix .v010 %s\n' \
  "$probe" "$out/device" "$*" >> "$out/command.txt"
# The driver waits until the envelope is --warmup-seconds old (10 by default) itself.
python3 scripts/run-v09-android-device-matrix.py --fixture "$probe" --work-dir "$out/device" \
  --package-suffix .v010 "$@" > "$out/driver.log" 2>&1
rc=$?
echo "driver exit=$rc" | tee "$out/outcome.txt"
echo "events: $out/device/events.jsonl; log: $out/driver.log"
exit $rc

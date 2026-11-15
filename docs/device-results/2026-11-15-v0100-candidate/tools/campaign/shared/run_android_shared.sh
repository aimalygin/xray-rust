#!/usr/bin/env bash
# usage: run_android_shared.sh <name>   (normally through ../attempt.sh android android-shared ...)
# v0.10 campaign copy of docs/device-results/2026-11-02-v090-candidate/tools/run_android_shared.sh
# (see tools/shared/CHANGES.md). Two fixtures: the shared one (shared_fixture_v09.py --platform
# android) and the v0.9 protocol one whose socks/http/shadowsocks-aead cases the projection
# controls use, then shared_android_v09.py. Differences: paths, ANDROID_SERIAL from the
# environment, everything inside the attempt directory (fixture/, protocol-fixture/, their
# logs, device/ = RUN_DIR, collector.log, command.txt), an existing attempt refused.
set -u
name="${1:?run name}"
O=<stand>
C="${CAMPAIGN_DIR:-$O/campaign}"; T=$O/tools/shared
REF=<perf>/xray
: "${ANDROID_SERIAL:?set ANDROID_SERIAL (adb devices)}"
cd $O/candidate || exit 1
[ "$(git rev-parse 'HEAD^{tree}')" = b637ff77211f6dc1aa865779d42b0325a7c7cc86 ] || { echo "$O/candidate is not candidate 7eb199bb"; exit 1; }
out="$C/$name"
[ -e "$out" ] && { echo "$out exists: keep it and use the next attempt"; exit 1; }
mkdir -p "$C"; chmod 700 "$C"; mkdir "$out"
export PATH="/opt/homebrew/opt/python@3.12/libexec/bin:$HOME/sdk/go1.27.3/bin:$PATH"
BIND="${BIND:-$(ipconfig getifaddr en1)}"
{ printf 'cwd: %s\ncommand: %q %q\n' "$PWD" "$0" "$name"
  printf 'fixture: python3 %s/shared_fixture_v09.py --platform android --bind %s --reference-binary %s --output %s --seconds 1800\n' "$T" "$BIND" "$REF" "$out/fixture"
  printf 'protocol fixture: python3 scripts/run-v08-android-protocol-fixture.py --suite v09 --protocol v09 --bind %s --reference-binary %s --output %s --seconds 1800\n' "$BIND" "$REF" "$out/protocol-fixture"
  printf 'ANDROID_SERIAL=%s\n' "$ANDROID_SERIAL"; date -u +started=%FT%TZ; } > "$out/command.txt"
python3 $T/shared_fixture_v09.py --platform android --bind "$BIND" --reference-binary $REF \
  --output "$out/fixture" --seconds 1800 > "$out/fixture.log" 2>&1 & shared=$!
python3 scripts/run-v08-android-protocol-fixture.py --suite v09 --protocol v09 --bind "$BIND" --reference-binary $REF \
  --output "$out/protocol-fixture" --seconds 1800 > "$out/protocol-fixture.log" 2>&1 & proto=$!
trap 'kill -INT $shared $proto 2>/dev/null; wait $shared $proto' EXIT
for _ in $(seq 1 60); do [ -f "$out/fixture/v07-probe.json" ] && [ -f "$out/protocol-fixture/v07-probe.json" ] && break; sleep 1; done
[ -f "$out/fixture/v07-probe.json" ] && [ -f "$out/protocol-fixture/v07-probe.json" ] || { echo "fixtures not ready"; exit 1; }
sleep "${WARMUP_SECONDS:-5}"
RUN_DIR="$out/device" FIXTURE_DIR="$out/fixture" PROTOCOL_FIXTURE_DIR="$out/protocol-fixture" \
  ANDROID_SERIAL="$ANDROID_SERIAL" ADB="$HOME/Library/Android/sdk/platform-tools/adb" PYTHONPATH="$T" \
  python3 $T/shared_android_v09.py > "$out/collector.log" 2>&1
rc=$?
echo "collector exit=$rc" | tee "$out/outcome.txt"
echo "events: $out/device/events.jsonl"
exit $rc

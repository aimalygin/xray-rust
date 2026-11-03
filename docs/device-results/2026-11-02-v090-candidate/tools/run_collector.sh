#!/usr/bin/env bash
# usage: run_collector.sh <name> <collector.py> [collector args] -- <fixture args...>
set -u
name="$1"; collector="$2"; shift 2
cargs=(); while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do cargs+=("$1"); shift; done; shift
C=<repo>/target/release-090/campaign.noindex
T=$C/tools
cd <repo>
export PATH="<scratch>/py312bin:$HOME/sdk/go1.27.3/bin:$PATH"
BIND=$(ipconfig getifaddr en1)
python3 scripts/run-v08-android-protocol-fixture.py --bind "$BIND" --reference-binary target/release-090/xray-core/xray \
  --output "$C/$name-fixture" --seconds 1800 "$@" > "$C/$name-fixture.log" 2>&1 &
fixture=$!
trap 'kill -INT $fixture 2>/dev/null; wait $fixture' EXIT
for _ in $(seq 1 60); do [ -f "$C/$name-fixture/v07-probe.json" ] && break; sleep 1; done
[ -f "$C/$name-fixture/v07-probe.json" ] || { echo "fixture not ready"; exit 1; }
sleep "${WARMUP_SECONDS:-10}"
RUN_DIR="$C/$name" FIXTURE_DIR="$C/$name-fixture" FIXTURE_LOG="$C/$name-fixture.log" \
  ANDROID_SERIAL=<samsung-serial> ADB="$HOME/Library/Android/sdk/platform-tools/adb" PYTHONPATH="$T" \
  python3 "$T/$collector" "${cargs[@]+"${cargs[@]}"}" > "$C/$name.collector.log" 2>&1
echo "collector exit=$?"

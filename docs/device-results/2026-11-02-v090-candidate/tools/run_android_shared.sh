#!/usr/bin/env bash
# Two fixtures: the shared one (tools/shared_fixture_v09.py) and the v0.9 protocol one.
set -u
name="$1"
C=<repo>/target/release-090/campaign.noindex; T=$C/tools
cd <repo>
export PATH="<scratch>/py312bin:$HOME/sdk/go1.27.3/bin:$PATH"
BIND=$(ipconfig getifaddr en1)
python3 $T/shared_fixture_v09.py --platform android --bind "$BIND" --reference-binary target/release-090/xray-core/xray \
  --output "$C/$name-fixture" --seconds 1800 > "$C/$name-fixture.log" 2>&1 & shared=$!
python3 scripts/run-v08-android-protocol-fixture.py --suite v09 --protocol v09 --bind "$BIND" --reference-binary target/release-090/xray-core/xray \
  --output "$C/$name-protocol-fixture" --seconds 1800 > "$C/$name-protocol-fixture.log" 2>&1 & proto=$!
trap 'kill -INT $shared $proto 2>/dev/null; wait $shared $proto' EXIT
for _ in $(seq 1 60); do [ -f "$C/$name-fixture/v07-probe.json" ] && [ -f "$C/$name-protocol-fixture/v07-probe.json" ] && break; sleep 1; done
[ -f "$C/$name-fixture/v07-probe.json" ] && [ -f "$C/$name-protocol-fixture/v07-probe.json" ] || { echo "fixtures not ready"; exit 1; }
sleep "${WARMUP_SECONDS:-5}"
RUN_DIR="$C/$name" FIXTURE_DIR="$C/$name-fixture" PROTOCOL_FIXTURE_DIR="$C/$name-protocol-fixture" \
  ANDROID_SERIAL=<samsung-serial> ADB="$HOME/Library/Android/sdk/platform-tools/adb" PYTHONPATH="$T" \
  python3 $T/shared_android_v09.py > "$C/$name.collector.log" 2>&1
echo "collector exit=$?"

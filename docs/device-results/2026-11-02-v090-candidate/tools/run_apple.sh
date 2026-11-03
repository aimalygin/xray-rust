#!/usr/bin/env bash
# usage: run_apple.sh <name> <fixture script> <fixture args...>
# Mirrors docs/device-results/2026-10-18-v081-candidate/ios-wan-manual.py launch/collect.
set -u
name="$1"; script="$2"; shift 2
C=<repo>/target/release-090/campaign.noindex
DEVICE=<iphone-udid>; BUNDLE=org.texforge.XrayClient
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
export PATH="<scratch>/py312bin:$HOME/sdk/go1.27.3/bin:$PATH"
cd <repo>
out="$C/$name"; mkdir -p "$out"
BIND=$(ipconfig getifaddr en1)
case "$script" in /*) path="$script" ;; *) path="scripts/$script" ;; esac
python3 "$path" --bind "$BIND" --reference-binary target/release-090/xray-core/xray \
  --output "$C/$name-fixture" --seconds "${FIXTURE_SECONDS:-1800}" "$@" > "$C/$name-fixture.log" 2>&1 &
fixture=$!
trap 'kill -INT $fixture 2>/dev/null; wait $fixture' EXIT
for _ in $(seq 1 60); do [ -f "$C/$name-fixture/v07-probe.json" ] && break; sleep 1; done
[ -f "$C/$name-fixture/v07-probe.json" ] || { echo "fixture not ready"; exit 1; }
sleep "${WARMUP_SECONDS:-3}"
dc() { local a="$1" b="$2"; shift 2; xcrun devicectl device "$a" "$b" --device "$DEVICE" --timeout 30 "$@"; }
dc copy to --source "$C/$name-fixture/v07-probe.json" --destination Documents/v07-probe.json \
  --domain-type appDataContainer --domain-identifier "$BUNDLE" > "$out/copy-to.log" 2>&1 || { echo "copy failed"; exit 1; }
launched=$(date +%s)
launch_env='{"XRAY_V07_DEVICE_PROBE":"1"}'; [ -n "${LAUNCH_ENV:-}" ] && launch_env="$LAUNCH_ENV"
dc process launch --terminate-existing --environment-variables "$launch_env" \
  --json-output "$out/launch.json" "$BUNDLE" > "$out/launch.log" 2>&1 || { echo "launch failed"; exit 1; }
echo "launched at $launched"
deadline=$(( launched + ${RUN_SECONDS:-1500} ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 10
  dc copy from --source Documents/v07-result.json --destination "$out/result.partial.json" \
    --domain-type appDataContainer --domain-identifier "$BUNDLE" > /dev/null 2>&1 || continue
  state=$(python3 - "$out/result.partial.json" "$launched" <<'PY'
import json, sys, datetime
rows = json.load(open(sys.argv[1]))
if not rows: print("empty"); raise SystemExit
first = datetime.datetime.fromisoformat(rows[0]["time"].replace("Z", "+00:00")).timestamp()
if first < float(sys.argv[2]) - 5: print("stale"); raise SystemExit
print("done:" + rows[-1].get("result", "") if rows[-1].get("event") == "complete" else "running:%d:%s" % (len(rows), rows[-1].get("event")))
PY
)
  case "$state" in
    done:*) mv "$out/result.partial.json" "$out/result.json"; echo "$state"; exit 0 ;;
    running:*) echo "$state" > "$out/progress.txt" ;;
  esac
done
echo "deadline without complete; last: $(cat "$out/progress.txt" 2>/dev/null)"; exit 1

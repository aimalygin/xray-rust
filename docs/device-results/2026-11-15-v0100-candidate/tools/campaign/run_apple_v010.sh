#!/usr/bin/env bash
# usage: run_apple_v010.sh <name> <fixture script> <fixture args...>   (LAN fixture on this Mac)
#        PROBE_FILE=<v07-probe.json> run_apple_v010.sh <name>          (fixture already running:
#                                                                        WAN host, or xicmp under sudo)
# Normally called through attempt.sh, which sets CAMPAIGN_DIR=results/ios/<run> and <name>=attempt-N.
# v0.10 copy of docs/device-results/2026-11-02-v090-candidate/tools/run_apple.sh. Differences:
# paths of candidate 7eb199bb; IPHONE_UDID from the environment; the attempt directory holds
# everything (fixture/, fixture.log, command.txt, copy/launch logs, result.json) and is never
# reused; PROBE_FILE skips the local fixture. Copy, launch and polling are those of 0.9.0.
set -u
name="${1:?run name}"; shift
O=<stand>
CANDIDATE=$O/candidate
C="${CAMPAIGN_DIR:-$O/campaign}"
REF=<perf>/xray
DEVICE="${IPHONE_UDID:?set IPHONE_UDID (xcrun devicectl list devices)}"; BUNDLE=org.texforge.XrayClient
export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
export PATH="/opt/homebrew/opt/python@3.12/libexec/bin:$HOME/sdk/go1.27.3/bin:$PATH"
cd "$CANDIDATE" || exit 1
[ "$(git rev-parse 'HEAD^{tree}')" = b637ff77211f6dc1aa865779d42b0325a7c7cc86 ] || { echo "$CANDIDATE is not candidate 7eb199bb"; exit 1; }
out="$C/$name"
if [ -n "${PROBE_FILE:-}" ]; then
  [ -e "$out/copy-to.log" ] && { echo "$out was already run: use the next attempt"; exit 1; }
else
  [ -e "$out" ] && { echo "$out exists: keep it and use the next attempt"; exit 1; }
fi
mkdir -p "$C"; chmod 700 "$C"; mkdir -p "$out"
{ printf 'cwd: %s\n' "$PWD"; printf 'command:'; printf ' %q' "$0" "$name" "$@"; printf '\n'
  for v in PROBE_FILE LAUNCH_ENV WARMUP_SECONDS RUN_SECONDS FIXTURE_SECONDS BIND IPHONE_UDID; do
    [ -n "${!v:-}" ] && printf '%s=%s\n' "$v" "${!v}"; done; date -u +started=%FT%TZ; } > "$out/command.txt"
if [ -n "${PROBE_FILE:-}" ]; then
  probe="$PROBE_FILE"
  [ -f "$probe" ] || { echo "no $probe"; exit 1; }
else
  script="${1:?fixture script}"; shift
  BIND="${BIND:-$(ipconfig getifaddr en1)}"
  case "$script" in /*) path="$script" ;; *) path="scripts/$script" ;; esac
  printf 'fixture: python3 %s --bind %s --reference-binary %s --output %s --seconds %s %s\n' "$path" "$BIND" "$REF" \
    "$out/fixture" "${FIXTURE_SECONDS:-1800}" "$*" >> "$out/command.txt"
  python3 "$path" --bind "$BIND" --reference-binary "$REF" \
    --output "$out/fixture" --seconds "${FIXTURE_SECONDS:-1800}" "$@" > "$out/fixture.log" 2>&1 &
  fixture=$!
  trap 'kill -INT $fixture 2>/dev/null; wait $fixture' EXIT
  for _ in $(seq 1 60); do [ -f "$out/fixture/v07-probe.json" ] && break; sleep 1; done
  [ -f "$out/fixture/v07-probe.json" ] || { echo "fixture not ready; see $out/fixture.log"; exit 1; }
  probe="$out/fixture/v07-probe.json"
fi
sleep "${WARMUP_SECONDS:-3}"
dc() { local a="$1" b="$2"; shift 2; xcrun devicectl device "$a" "$b" --device "$DEVICE" --timeout 30 "$@"; }
dc copy to --source "$probe" --destination Documents/v07-probe.json \
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
    done:*) mv "$out/result.partial.json" "$out/result.json"; echo "$state" | tee "$out/outcome.txt"; exit 0 ;;
    running:*) echo "$state" > "$out/progress.txt" ;;
  esac
done
echo "deadline without complete; last: $(cat "$out/progress.txt" 2>/dev/null)" | tee "$out/outcome.txt"; exit 1

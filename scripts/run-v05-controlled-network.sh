#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_XRAY_CORE_REVISION="5ca6f4b7d4dc20a881d4330e498892697627ec0c"
readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly OUTPUT_ARGUMENT="${1:-target/benchmarks/v05-controlled-network}"
readonly DELAY_MS="${XRAY_NETEM_DELAY_MS:-40}"
readonly JITTER_MS="${XRAY_NETEM_JITTER_MS:-10}"
readonly LOSS_PERCENT="${XRAY_NETEM_LOSS_PERCENT:-1}"
readonly HOLD_MS="${XRAY_NETEM_HOLD_MS:-120000}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo 'controlled RTT/loss coverage requires Linux tc netem' >&2
  exit 1
fi
if [[ -z "${XRAY_CORE_CHECKOUT:-}" ]]; then
  echo 'XRAY_CORE_CHECKOUT must point at the pinned Xray-core checkout' >&2
  exit 1
fi
for value in "$DELAY_MS" "$JITTER_MS" "$HOLD_MS"; do
  if [[ ! "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo 'delay, jitter, and hold duration must be positive integers' >&2
    exit 1
  fi
done
if [[ ! "$LOSS_PERCENT" =~ ^([0-9]+([.][0-9]+)?)$ ]]; then
  echo 'loss percentage must be a non-negative number' >&2
  exit 1
fi
if ! command -v tc >/dev/null 2>&1; then
  echo 'tc is required for controlled RTT/loss coverage' >&2
  exit 1
fi
if ! command -v sudo >/dev/null 2>&1; then
  echo 'passwordless sudo is required to configure loopback netem' >&2
  exit 1
fi

readonly XRAY_CORE_DIR="$(cd "$XRAY_CORE_CHECKOUT" && pwd -P)"
readonly ACTUAL_XRAY_CORE_REVISION="$(git -C "$XRAY_CORE_DIR" rev-parse --verify HEAD)"
if [[ "$ACTUAL_XRAY_CORE_REVISION" != "$EXPECTED_XRAY_CORE_REVISION" ]]; then
  echo "Xray-core checkout is $ACTUAL_XRAY_CORE_REVISION; expected $EXPECTED_XRAY_CORE_REVISION" >&2
  exit 1
fi
if [[ -n "$(git -C "$XRAY_CORE_DIR" status --porcelain --untracked-files=all)" ]]; then
  echo 'controlled RTT/loss coverage requires a clean Xray-core checkout' >&2
  exit 1
fi
if [[ -n "$(git -C "$WORKSPACE_ROOT" status --porcelain --untracked-files=all)" ]]; then
  echo 'controlled RTT/loss coverage requires a clean xray-rust checkout' >&2
  exit 1
fi

if [[ "$OUTPUT_ARGUMENT" = /* ]]; then
  readonly OUTPUT_ROOT="$OUTPUT_ARGUMENT"
else
  readonly OUTPUT_ROOT="$WORKSPACE_ROOT/$OUTPUT_ARGUMENT"
fi
if [[ -e "$OUTPUT_ROOT" ]]; then
  echo "controlled RTT/loss output already exists: $OUTPUT_ROOT" >&2
  exit 1
fi
mkdir -p "$OUTPUT_ROOT"

controlled_tmp="$(mktemp -d "${TMPDIR:-/tmp}/xray-v05-netem.XXXXXX")"
netem_installed=0
cleanup() {
  if [[ "$netem_installed" -eq 1 ]]; then
    sudo -n tc qdisc del dev lo root >/dev/null 2>&1 || true
  fi
  rm -rf -- "$controlled_tmp"
}
trap cleanup EXIT INT TERM

cd "$WORKSPACE_ROOT"
cargo build --locked --release -p xray-bench -p xray-cli
env \
  -u GOFLAGS \
  -u GOEXPERIMENT \
  -u GOTOOLCHAIN \
  GOENV=off \
  GOWORK=off \
  CGO_ENABLED=0 \
  go -C "$XRAY_CORE_DIR" build -o "$controlled_tmp/xray" ./main

readonly TARGET_ARGUMENT="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}"
if [[ "$TARGET_ARGUMENT" = /* ]]; then
  readonly TARGET_DIR="$TARGET_ARGUMENT"
else
  readonly TARGET_DIR="$WORKSPACE_ROOT/$TARGET_ARGUMENT"
fi
readonly BENCH_BINARY="$TARGET_DIR/release/xray-bench"
readonly XRAY_RUST_BINARY="$TARGET_DIR/release/xray-rust"

initial_qdisc="$(tc qdisc show dev lo)"
if ! grep -Eq '^qdisc noqueue ' <<<"$initial_qdisc"; then
  echo "refusing to replace a non-default loopback qdisc: $initial_qdisc" >&2
  exit 1
fi
sudo -n tc qdisc replace dev lo root netem \
  delay "${DELAY_MS}ms" "${JITTER_MS}ms" \
  loss "${LOSS_PERCENT}%"
netem_installed=1
active_qdisc="$(tc qdisc show dev lo)"
if ! grep -Fq 'netem' <<<"$active_qdisc"; then
  echo "loopback qdisc did not become netem: $active_qdisc" >&2
  exit 1
fi

{
  echo "workspace_revision=$(git rev-parse --verify HEAD)"
  echo "xray_core_revision=$ACTUAL_XRAY_CORE_REVISION"
  echo "delay_ms=$DELAY_MS"
  echo "jitter_ms=$JITTER_MS"
  echo "loss_percent=$LOSS_PERCENT"
  echo "hold_ms=$HOLD_MS"
  echo "qdisc=$active_qdisc"
} >"$OUTPUT_ROOT/netem-environment.txt"

common_args=(
  --engine xray-rust
  --workload stream-transport
  --xray-rust-bin "$XRAY_RUST_BINARY"
  --xray-core-bin "$controlled_tmp/xray"
  --xray-core-dir "$XRAY_CORE_DIR"
  --no-auto-build
  --runs 1
  --run-timeout-ms 300000
)

run_duplex() {
  local transport="$1"
  local command=(
    "$BENCH_BINARY" run "${common_args[@]}"
    --stream-transport "$transport"
    --traffic full-duplex
    --connections 2
    --iterations 32
    --payload-size 4096
    --out-dir "$OUTPUT_ROOT/${transport}-duplex"
  )
  if [[ "$transport" == xhttp-* ]]; then
    command+=(--xhttp-mode stream-one)
  fi
  "${command[@]}"
}

for transport in ws httpupgrade grpc xhttp-h1 xhttp-h2 xhttp-h3; do
  run_duplex "$transport"
done

for transport in xhttp-h2 xhttp-h3; do
  "$BENCH_BINARY" run "${common_args[@]}" \
    --stream-transport "$transport" \
    --traffic held-open \
    --xhttp-mode stream-one \
    --connections 4 \
    --duration-ms "$HOLD_MS" \
    --out-dir "$OUTPUT_ROOT/${transport}-held-open"
done

echo "controlled RTT/loss evidence written to $OUTPUT_ROOT"

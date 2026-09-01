#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly OUTPUT_ARGUMENT="${1:-target/benchmarks/v05-pre-device}"
if [[ "$OUTPUT_ARGUMENT" = /* ]]; then
  readonly OUTPUT_ROOT="$OUTPUT_ARGUMENT"
else
  readonly OUTPUT_ROOT="$WORKSPACE_ROOT/$OUTPUT_ARGUMENT"
fi
readonly REPEATS=5

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo 'v0.5 pre-device budgets are calibrated against the macOS v0.4.0 publication host' >&2
  exit 1
fi

if [[ -n "$(git -C "$WORKSPACE_ROOT" status --porcelain=v1 --untracked-files=normal)" ]]; then
  echo 'v0.5 pre-device benchmarks require a clean worktree for source provenance' >&2
  exit 1
fi

if [[ -e "$OUTPUT_ROOT" ]]; then
  echo "v0.5 pre-device output already exists: $OUTPUT_ROOT" >&2
  exit 1
fi

cd "$WORKSPACE_ROOT"
cargo build --locked --release -p xray-bench
cargo build --locked --release -p xray-cli --bin xray-rust

readonly TARGET_ARGUMENT="${CARGO_TARGET_DIR:-$WORKSPACE_ROOT/target}"
if [[ "$TARGET_ARGUMENT" = /* ]]; then
  readonly TARGET_DIR="$TARGET_ARGUMENT"
else
  readonly TARGET_DIR="$WORKSPACE_ROOT/$TARGET_ARGUMENT"
fi
readonly BENCH_BINARY="$TARGET_DIR/release/xray-bench"
readonly XRAY_RUST_BINARY="$TARGET_DIR/release/xray-rust"

for repeat in $(seq 1 "$REPEATS"); do
  "$BENCH_BINARY" route-probe \
    --iterations 10000000 \
    --rules 64 \
    --outbounds 8 \
    --out-dir "$OUTPUT_ROOT/route-$repeat"
  "$BENCH_BINARY" dns-policy-probe \
    --iterations 100000 \
    --servers 4 \
    --matchers 4096 \
    --out-dir "$OUTPUT_ROOT/dns-$repeat"
  "$BENCH_BINARY" phase2-probe \
    --iterations 10000 \
    --members 64 \
    --connections 64 \
    --chain-depth 8 \
    --out-dir "$OUTPUT_ROOT/phase2-$repeat"
done

common_process_args=(
  --engine xray-rust
  --xray-rust-bin "$XRAY_RUST_BINARY"
  --no-auto-build
  --runs 5
)

"$BENCH_BINARY" run "${common_process_args[@]}" \
  --workload idle \
  --duration-ms 2000 \
  --out-dir "$OUTPUT_ROOT/process-idle"
"$BENCH_BINARY" run "${common_process_args[@]}" \
  --workload many-idle-flows \
  --connections 100 \
  --duration-ms 5000 \
  --out-dir "$OUTPUT_ROOT/process-flows-100"
"$BENCH_BINARY" run "${common_process_args[@]}" \
  --workload many-idle-flows \
  --connections 1000 \
  --duration-ms 5000 \
  --run-timeout-ms 30000 \
  --out-dir "$OUTPUT_ROOT/process-flows-1000"
"$BENCH_BINARY" run "${common_process_args[@]}" \
  --workload tcp-freedom \
  --connections 1 \
  --iterations 1000 \
  --payload-size 1024 \
  --out-dir "$OUTPUT_ROOT/process-tcp"
"$BENCH_BINARY" run "${common_process_args[@]}" \
  --workload tun-tcp-freedom \
  --connections 16 \
  --iterations 100 \
  --payload-size 1024 \
  --out-dir "$OUTPUT_ROOT/process-tun-fd"

python3 "$WORKSPACE_ROOT/scripts/check-v05-performance.py" "$OUTPUT_ROOT"

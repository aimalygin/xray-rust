#!/usr/bin/env bash
set -euo pipefail

# Overrides: XRAY_CORE_DIR, XRAY_BENCH_OUT_DIR, XRAY_BENCH_RUNS,
# XRAY_BENCH_HELD_MS, XRAY_BENCH_SETTLE_MS, XRAY_BENCH_SAMPLE_MS,
# XRAY_BENCH_MAX_POST_BYTES, XRAY_BENCH_PAYLOAD_SIZE, and
# XRAY_BENCH_TRAFFIC_ITERATIONS. Set XRAY_BENCH_XRAY_RUST_BIN and
# XRAY_BENCH_XRAY_CORE_BIN together to reuse exact release binaries.
repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

xray_core_dir=${XRAY_CORE_DIR:-Xray-core}
out_dir=${XRAY_BENCH_OUT_DIR:-target/benchmarks/xhttp-memory}
runs=${XRAY_BENCH_RUNS:-5}
held_ms=${XRAY_BENCH_HELD_MS:-30000}
settle_ms=${XRAY_BENCH_SETTLE_MS:-5000}
sample_ms=${XRAY_BENCH_SAMPLE_MS:-100}
max_post_bytes=${XRAY_BENCH_MAX_POST_BYTES:-500000}
payload_size=${XRAY_BENCH_PAYLOAD_SIZE:-16384}
traffic_iterations=${XRAY_BENCH_TRAFFIC_ITERATIONS:-1000}
xray_rust_bin_override=${XRAY_BENCH_XRAY_RUST_BIN:-}
xray_core_bin_override=${XRAY_BENCH_XRAY_CORE_BIN:-}

if [[ -n "$xray_rust_bin_override" && -z "$xray_core_bin_override" ]] \
  || [[ -z "$xray_rust_bin_override" && -n "$xray_core_bin_override" ]]; then
  echo "XRAY_BENCH_XRAY_RUST_BIN and XRAY_BENCH_XRAY_CORE_BIN must be set together." >&2
  exit 2
fi

use_explicit_binaries=false
if [[ -n "$xray_rust_bin_override" ]]; then
  if [[ ! -f "$xray_rust_bin_override" || ! -x "$xray_rust_bin_override" ]]; then
    echo "XRAY_BENCH_XRAY_RUST_BIN is not executable: $xray_rust_bin_override" >&2
    exit 2
  fi
  if [[ ! -f "$xray_core_bin_override" || ! -x "$xray_core_bin_override" ]]; then
    echo "XRAY_BENCH_XRAY_CORE_BIN is not executable: $xray_core_bin_override" >&2
    exit 2
  fi
  use_explicit_binaries=true
fi

if [[ ! -d "$xray_core_dir" ]]; then
  echo "Xray-core checkout not found: $xray_core_dir" >&2
  echo "Set XRAY_CORE_DIR to its checkout path." >&2
  exit 2
fi

if [[ "$use_explicit_binaries" == true ]]; then
  xray_rust_bin=$xray_rust_bin_override
else
  cargo build --locked --release -p xray-cli --bin xray-rust
  cargo_target_dir=${CARGO_TARGET_DIR:-target}
  xray_rust_bin="$cargo_target_dir/release/xray-rust"
fi

common=(
  cargo run --locked --release -p xray-bench -- compare
  --workload stream-transport
  --xhttp-profile legacy-extra-h1-packet-up
  --sample-interval-ms "$sample_ms"
  --settle-ms "$settle_ms"
  --runs "$runs"
  --out-dir "$out_dir"
  --xray-rust-bin "$xray_rust_bin"
  --xray-core-dir "$xray_core_dir"
)
if [[ "$use_explicit_binaries" == true ]]; then
  common+=(
    --xray-core-bin "$xray_core_bin_override"
    --no-auto-build
  )
fi

for flows in 1 16 32; do
  echo "held-open: flows=$flows max_post_bytes=$max_post_bytes"
  "${common[@]}" \
    --xhttp-max-post-bytes "$max_post_bytes" \
    --traffic held-open \
    --connections "$flows" \
    --iterations 1 \
    --payload-size "$payload_size" \
    --duration-ms "$held_ms" \
    --run-timeout-ms "$((held_ms + settle_ms + 120000))"
done

echo "held-open control: flows=16 max_post_bytes=16384"
"${common[@]}" \
  --xhttp-max-post-bytes 16384 \
  --traffic held-open \
  --connections 16 \
  --iterations 1 \
  --payload-size "$payload_size" \
  --duration-ms "$held_ms" \
  --run-timeout-ms "$((held_ms + settle_ms + 120000))"

for flows in 1 16; do
  echo "sustained packet-up: flows=$flows iterations=$traffic_iterations"
  "${common[@]}" \
    --xhttp-max-post-bytes "$max_post_bytes" \
    --traffic packet-up \
    --connections "$flows" \
    --iterations "$traffic_iterations" \
    --payload-size "$payload_size" \
    --duration-ms 0 \
    --run-timeout-ms 300000
done

echo "Results: $out_dir"

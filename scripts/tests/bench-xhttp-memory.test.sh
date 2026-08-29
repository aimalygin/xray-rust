#!/usr/bin/env bash
set -euo pipefail

repo_root="$(CDPATH= cd -- "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
recipe="$repo_root/scripts/bench-xhttp-memory.sh"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

fake_bin="$tmp_dir/fake bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/cargo" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
python3 - "$CARGO_LOG" "$@" <<'PY'
import json
import pathlib
import sys

with pathlib.Path(sys.argv[1]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(sys.argv[2:]) + "\n")
PY
SH
chmod +x "$fake_bin/cargo"

core_dir="$tmp_dir/exact Xray-core checkout"
mkdir -p "$core_dir"
rust_bin="$tmp_dir/xray rust binary"
core_bin="$tmp_dir/xray core binary"
printf '#!/usr/bin/env bash\nexit 0\n' >"$rust_bin"
printf '#!/usr/bin/env bash\nexit 0\n' >"$core_bin"
chmod +x "$rust_bin" "$core_bin"

# Exercise every recipe invocation under hostile inherited overrides. The
# runner below must pin every consumed input so the fixtures remain hermetic.
export CDPATH=.
export CARGO_TARGET_DIR="$tmp_dir/hostile cargo target"
export XRAY_CORE_DIR="$tmp_dir/hostile core"
export XRAY_BENCH_OUT_DIR="$tmp_dir/hostile output"
export XRAY_BENCH_RUNS=99
export XRAY_BENCH_HELD_MS=98
export XRAY_BENCH_SETTLE_MS=97
export XRAY_BENCH_SAMPLE_MS=96
export XRAY_BENCH_MAX_POST_BYTES=95
export XRAY_BENCH_PAYLOAD_SIZE=94
export XRAY_BENCH_TRAFFIC_ITERATIONS=93
export XRAY_BENCH_XRAY_RUST_BIN="$tmp_dir/hostile rust binary"
export XRAY_BENCH_XRAY_CORE_BIN="$tmp_dir/hostile core binary"

run_recipe() {
  local log_file="$1"
  shift
  env \
    PATH="$fake_bin:$PATH" \
    CARGO_LOG="$log_file" \
    CARGO_TARGET_DIR= \
    XRAY_CORE_DIR="$core_dir" \
    XRAY_BENCH_OUT_DIR="$tmp_dir/pinned output" \
    XRAY_BENCH_RUNS=5 \
    XRAY_BENCH_HELD_MS=30000 \
    XRAY_BENCH_SAMPLE_MS=101 \
    XRAY_BENCH_SETTLE_MS=1 \
    XRAY_BENCH_MAX_POST_BYTES=500000 \
    XRAY_BENCH_PAYLOAD_SIZE=16384 \
    XRAY_BENCH_TRAFFIC_ITERATIONS=1000 \
    XRAY_BENCH_XRAY_RUST_BIN= \
    XRAY_BENCH_XRAY_CORE_BIN= \
    "$@" \
    bash "$recipe"
}

explicit_log="$tmp_dir/explicit.jsonl"
explicit_out="$tmp_dir/explicit output"
run_recipe "$explicit_log" \
  XRAY_BENCH_OUT_DIR="$explicit_out" \
  XRAY_BENCH_XRAY_RUST_BIN="$rust_bin" \
  XRAY_BENCH_XRAY_CORE_BIN="$core_bin"

python3 - "$explicit_log" "$explicit_out" "$rust_bin" "$core_bin" "$core_dir" <<'PY'
import json
import pathlib
import sys

log_path, output, rust_bin, core_bin, core_dir = sys.argv[1:]
commands = [json.loads(line) for line in pathlib.Path(log_path).read_text().splitlines()]
common = [
    "run", "--locked", "--release", "-p", "xray-bench", "--", "compare",
    "--workload", "stream-transport",
    "--xhttp-profile", "legacy-extra-h1-packet-up",
    "--sample-interval-ms", "101",
    "--settle-ms", "1",
    "--runs", "5",
    "--out-dir", output,
    "--xray-rust-bin", rust_bin,
    "--xray-core-dir", core_dir,
    "--xray-core-bin", core_bin,
    "--no-auto-build",
]
expected = []
for flows in (1, 16, 32):
    expected.append(common + [
        "--xhttp-max-post-bytes", "500000",
        "--traffic", "held-open",
        "--connections", str(flows),
        "--iterations", "1",
        "--payload-size", "16384",
        "--duration-ms", "30000",
        "--run-timeout-ms", "150001",
    ])
expected.append(common + [
    "--xhttp-max-post-bytes", "16384",
    "--traffic", "held-open",
    "--connections", "16",
    "--iterations", "1",
    "--payload-size", "16384",
    "--duration-ms", "30000",
    "--run-timeout-ms", "150001",
])
for flows in (1, 16):
    expected.append(common + [
        "--xhttp-max-post-bytes", "500000",
        "--traffic", "packet-up",
        "--connections", str(flows),
        "--iterations", "1000",
        "--payload-size", "16384",
        "--duration-ms", "0",
        "--run-timeout-ms", "300000",
    ])
if commands != expected:
    raise SystemExit(
        "explicit-binary recipe commands differ\n"
        f"expected={json.dumps(expected, indent=2)}\n"
        f"actual={json.dumps(commands, indent=2)}"
    )
PY

relative_log="$tmp_dir/relative-cdpath.jsonl"
(
  cd "$repo_root"
  recipe=scripts/bench-xhttp-memory.sh
  run_recipe "$relative_log" \
    XRAY_BENCH_OUT_DIR="$explicit_out" \
    XRAY_BENCH_XRAY_RUST_BIN="$rust_bin" \
    XRAY_BENCH_XRAY_CORE_BIN="$core_bin"
)
cmp -s "$explicit_log" "$relative_log" \
  || fail "relative invocation with exported CDPATH produced different commands"

default_log="$tmp_dir/default.jsonl"
default_out="$tmp_dir/default output"
run_recipe "$default_log" XRAY_BENCH_OUT_DIR="$default_out"
python3 - "$default_log" "$default_out" "$core_dir" <<'PY'
import json
import pathlib
import sys

log_path, output, core_dir = sys.argv[1:]
commands = [json.loads(line) for line in pathlib.Path(log_path).read_text().splitlines()]
common = [
    "run", "--locked", "--release", "-p", "xray-bench", "--", "compare",
    "--workload", "stream-transport",
    "--xhttp-profile", "legacy-extra-h1-packet-up",
    "--sample-interval-ms", "101",
    "--settle-ms", "1",
    "--runs", "5",
    "--out-dir", output,
    "--xray-rust-bin", "target/release/xray-rust",
    "--xray-core-dir", core_dir,
]
expected = [["build", "--locked", "--release", "-p", "xray-cli", "--bin", "xray-rust"]]
for flows in (1, 16, 32):
    expected.append(common + [
        "--xhttp-max-post-bytes", "500000",
        "--traffic", "held-open",
        "--connections", str(flows),
        "--iterations", "1",
        "--payload-size", "16384",
        "--duration-ms", "30000",
        "--run-timeout-ms", "150001",
    ])
expected.append(common + [
    "--xhttp-max-post-bytes", "16384",
    "--traffic", "held-open",
    "--connections", "16",
    "--iterations", "1",
    "--payload-size", "16384",
    "--duration-ms", "30000",
    "--run-timeout-ms", "150001",
])
for flows in (1, 16):
    expected.append(common + [
        "--xhttp-max-post-bytes", "500000",
        "--traffic", "packet-up",
        "--connections", str(flows),
        "--iterations", "1000",
        "--payload-size", "16384",
        "--duration-ms", "0",
        "--run-timeout-ms", "300000",
    ])
if commands != expected:
    raise SystemExit(
        "default recipe commands differ\n"
        f"expected={json.dumps(expected, indent=2)}\n"
        f"actual={json.dumps(commands, indent=2)}"
    )
PY

expect_failure() {
  local name="$1"
  local expected="$2"
  shift 2
  local log_file="$tmp_dir/$name.jsonl"
  local output

  if output="$(run_recipe "$log_file" XRAY_BENCH_OUT_DIR="$tmp_dir/$name-output" "$@" 2>&1)"; then
    fail "$name was accepted"
  fi
  grep -Fq "$expected" <<<"$output" \
    || fail "$name did not report '$expected': $output"
  if [[ -s "$log_file" ]]; then
    fail "$name invoked cargo before rejecting invalid binary configuration"
  fi
}

expect_failure partial_rust "must be set together" \
  XRAY_BENCH_XRAY_RUST_BIN="$rust_bin"
expect_failure partial_core "must be set together" \
  XRAY_BENCH_XRAY_CORE_BIN="$core_bin"

nonexec_rust="$tmp_dir/nonexec rust"
nonexec_core="$tmp_dir/nonexec core"
printf 'not executable\n' >"$nonexec_rust"
printf 'not executable\n' >"$nonexec_core"
expect_failure nonexec_rust "XRAY_BENCH_XRAY_RUST_BIN is not executable" \
  XRAY_BENCH_XRAY_RUST_BIN="$nonexec_rust" \
  XRAY_BENCH_XRAY_CORE_BIN="$core_bin"
expect_failure nonexec_core "XRAY_BENCH_XRAY_CORE_BIN is not executable" \
  XRAY_BENCH_XRAY_RUST_BIN="$rust_bin" \
  XRAY_BENCH_XRAY_CORE_BIN="$nonexec_core"

echo "xhttp memory benchmark recipe tests passed"

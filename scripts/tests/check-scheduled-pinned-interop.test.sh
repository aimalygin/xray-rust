#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SCRIPT_UNDER_TEST="$WORKSPACE_ROOT/scripts/check-scheduled-pinned-interop.sh"
TEST_ROOT="$(mktemp -d)"
TEST_ROOT="$(cd "$TEST_ROOT" && pwd -P)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT

EXPECTED_XRAY_CORE_REVISION="5ca6f4b7d4dc20a881d4330e498892697627ec0c"
BROAD_FINGERPRINTS="chrome,hellochrome_133,hellofirefox_148,hellosafari_26_3,helloios_13,hello360_11_0,hellochrome_120_pq,hellofirefox_99"

FAKE_BIN="$TEST_ROOT/bin"
FAKE_CORE="$TEST_ROOT/Xray-core"
FAKE_CORE_LINK="$TEST_ROOT/Xray-core-link"
FAKE_TARGET="$TEST_ROOT/target"
FAKE_CARGO_LOG="$TEST_ROOT/cargo.log"
FAKE_GO_LOG="$TEST_ROOT/go.log"
FAKE_CORE_PATH_LOG="$TEST_ROOT/xray-core-path.log"
mkdir -p "$FAKE_BIN" "$FAKE_CORE"
ln -s "$FAKE_CORE" "$FAKE_CORE_LINK"

cat >"$FAKE_BIN/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if (( $# == 5 )) &&
  [[ "$1" == "-C" ]] &&
  [[ "$2" == "$FAKE_EXPECTED_CORE" ]] &&
  [[ "$3" == "rev-parse" ]] &&
  [[ "$4" == "--verify" ]] &&
  [[ "$5" == "HEAD" ]]; then
  printf '%s\n' "$FAKE_GIT_REVISION"
  exit 0
fi

if (( $# == 5 )) &&
  [[ "$1" == "-C" ]] &&
  [[ "$2" == "$FAKE_EXPECTED_CORE" ]] &&
  [[ "$3" == "status" ]] &&
  [[ "$4" == "--porcelain" ]] &&
  [[ "$5" == "--untracked-files=all" ]]; then
  if [[ -n "${FAKE_GIT_STATUS_OUTPUT:-}" ]]; then
    printf '%s\n' "$FAKE_GIT_STATUS_OUTPUT"
  fi
  exit 0
fi

printf 'unexpected git invocation: %s\n' "$*" >&2
exit 90
EOF

cat >"$FAKE_BIN/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' 'xray-core-build' >>"$FAKE_INVOCATION_LOG"

[[ -z "${GOFLAGS+x}" ]] || {
  echo 'Xray-core build inherited GOFLAGS' >&2
  exit 91
}
[[ -z "${GOEXPERIMENT+x}" ]] || {
  echo 'Xray-core build inherited GOEXPERIMENT' >&2
  exit 92
}
[[ "${GOENV:-}" == "off" ]] || {
  echo 'Xray-core build did not set GOENV=off' >&2
  exit 93
}
[[ "${GOWORK:-}" == "off" ]] || {
  echo 'Xray-core build did not set GOWORK=off' >&2
  exit 94
}
[[ "${GOTOOLCHAIN:-}" == "local" ]] || {
  echo 'Xray-core build did not set GOTOOLCHAIN=local' >&2
  exit 95
}
[[ "${CGO_ENABLED:-}" == "0" ]] || {
  echo 'Xray-core build did not set CGO_ENABLED=0' >&2
  exit 96
}

if (( $# != 6 )) ||
  [[ "$1" != "-C" ]] ||
  [[ "$2" != "$FAKE_EXPECTED_CORE" ]] ||
  [[ "$3" != "build" ]] ||
  [[ "$4" != "-o" ]] ||
  [[ "$6" != "./main" ]]; then
  printf 'unexpected go invocation: %s\n' "$*" >&2
  exit 97
fi

output="$5"
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$output"
chmod +x "$output"
printf 'build|core=%s|output=%s|goflags=unset|goexperiment=unset|goenv=off|gowork=off|gotoolchain=local|cgo=0\n' \
  "$2" "$output" >>"$FAKE_GO_LOG"
printf '%s\n' "$output" >"$FAKE_CORE_PATH_LOG"
EOF

cat >"$FAKE_BIN/rustc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'rustc test'
EOF

cat >"$FAKE_BIN/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

command_args=("$@")
printf 'invoke|%s\n' "$*" >>"$FAKE_CARGO_LOG"

die() {
  echo "$*" >&2
  exit 98
}

assert_args() {
  local context="$1"
  shift
  local expected=("$@")
  local index

  if (( ${#command_args[@]} != ${#expected[@]} )); then
    die "unexpected $context argument count: ${command_args[*]}"
  fi
  for (( index = 0; index < ${#expected[@]}; index++ )); do
    if [[ "${command_args[index]}" != "${expected[index]}" ]]; then
      die "unexpected $context arguments: ${command_args[*]}"
    fi
  done
}

option_value() {
  local option="$1"
  local index
  for (( index = 0; index < ${#command_args[@]}; index++ )); do
    if [[ "${command_args[index]}" == "$option" ]]; then
      (( index += 1 ))
      [[ "$index" -lt "${#command_args[@]}" ]] || die "missing value for $option"
      printf '%s\n' "${command_args[index]}"
      return 0
    fi
  done
  die "missing required option: $option"
}

case "${1:-}" in
  test)
    assert_args "scheduled interop test" \
      test --locked -p xray-core-rs --test local_xray_interop_tests \
      -- --ignored --nocapture --test-threads=1

    [[ -z "${GOFLAGS+x}" ]] || die 'scheduled interop test inherited GOFLAGS'
    [[ -z "${GOEXPERIMENT+x}" ]] || die 'scheduled interop test inherited GOEXPERIMENT'
    [[ -z "${XRAY_CORE_EXPECTED_REVISION+x}" ]] || \
      die 'scheduled interop test inherited XRAY_CORE_EXPECTED_REVISION'
    [[ "${GOENV:-}" == "off" ]] || die 'scheduled interop test did not set GOENV=off'
    [[ "${GOWORK:-}" == "off" ]] || die 'scheduled interop test did not set GOWORK=off'
    [[ "${GOTOOLCHAIN:-}" == "local" ]] || die 'scheduled interop test did not set GOTOOLCHAIN=local'
    [[ "${CGO_ENABLED:-}" == "0" ]] || die 'scheduled interop test did not set CGO_ENABLED=0'

    printf '%s\n' 'serial-ignored-interop' >>"$FAKE_INVOCATION_LOG"
    printf 'test|command=%s|fingerprints=%s|burst_fingerprints=%s|burst_flows=%s|xhttp_cases=%s|goflags=unset|goexperiment=unset|core_expected_revision=unset|goenv=%s|gowork=%s|gotoolchain=%s|cgo=%s\n' \
      "$*" \
      "${XRAY_REALITY_INTEROP_FINGERPRINTS:-}" \
      "${XRAY_REALITY_INTEROP_BURST_FINGERPRINTS:-}" \
      "${XRAY_REALITY_INTEROP_BURST_FLOWS:-}" \
      "${XRAY_XHTTP_INTEROP_CASES:-}" \
      "$GOENV" "$GOWORK" "$GOTOOLCHAIN" "$CGO_ENABLED" >>"$FAKE_CARGO_LOG"
    ;;
  build)
    assert_args "scheduled xray-rust build" \
      build --locked --release -p xray-cli --bin xray-rust
    case "$FAKE_EXPECTED_CARGO_TARGET_MODE" in
      unset)
        [[ -z "${CARGO_TARGET_DIR+x}" ]] || \
          die "CARGO_TARGET_DIR should be unset, got: $CARGO_TARGET_DIR"
        ;;
      set)
        [[ "${CARGO_TARGET_DIR:-}" == "$FAKE_EXPECTED_CARGO_TARGET_VALUE" ]] || \
          die "unexpected CARGO_TARGET_DIR: ${CARGO_TARGET_DIR:-unset}"
        ;;
      *)
        die "unexpected target fixture mode: $FAKE_EXPECTED_CARGO_TARGET_MODE"
        ;;
    esac
    mkdir -p "$(dirname "$FAKE_EXPECTED_XRAY_RUST_BIN")"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$FAKE_EXPECTED_XRAY_RUST_BIN"
    chmod +x "$FAKE_EXPECTED_XRAY_RUST_BIN"
    printf '%s\n' 'release-xray-rust-build' >>"$FAKE_INVOCATION_LOG"
    printf 'build|command=%s\n' "$*" >>"$FAKE_CARGO_LOG"
    ;;
  run)
    engine="$(option_value --engine)"
    workload="$(option_value --workload)"
    xray_rust_bin="$(option_value --xray-rust-bin)"
    xray_core_bin="$(option_value --xray-core-bin)"
    out_dir="$(option_value --out-dir)"

    [[ "$engine" == "xray-rust" || "$engine" == "xray-core" ]] || \
      die "unexpected scheduled engine: $engine"
    [[ "$xray_rust_bin" == "$FAKE_EXPECTED_XRAY_RUST_BIN" ]] || \
      die "unexpected xray-rust binary: $xray_rust_bin"
    [[ -x "$xray_rust_bin" ]] || die "xray-rust binary was not built: $xray_rust_bin"
    [[ -x "$xray_core_bin" ]] || die "xray-core binary was not built: $xray_core_bin"

    case "$workload" in
      many-idle-flows)
        [[ "$out_dir" == */"many-idle-flows-$engine" ]] || \
          die "unexpected many-idle output directory: $out_dir"
        assert_args "scheduled many-idle run" \
          run --locked --release -p xray-bench -- run \
          --engine "$engine" --workload many-idle-flows \
          --xray-rust-bin "$xray_rust_bin" --xray-core-bin "$xray_core_bin" \
          --no-auto-build --runs 1 --connections 100 --duration-ms 1000 \
          --out-dir "$out_dir"
        printf 'resource:%s:many-idle-flows\n' "$engine" >>"$FAKE_INVOCATION_LOG"
        printf 'resource|engine=%s|workload=many-idle-flows|xray_rust_bin=%s|xray_core_bin=%s|no_auto_build=true|runs=1|connections=100|duration_ms=1000|out=%s\n' \
          "$engine" "$xray_rust_bin" "$xray_core_bin" "$out_dir" >>"$FAKE_CARGO_LOG"
        ;;
      stream-transport)
        [[ "$out_dir" == */"xhttp-held-open-$engine" ]] || \
          die "unexpected XHTTP output directory: $out_dir"
        assert_args "scheduled XHTTP held-open run" \
          run --locked --release -p xray-bench -- run \
          --engine "$engine" --workload stream-transport --stream-transport xhttp-h2 \
          --traffic held-open --xhttp-mode stream-one \
          --xray-rust-bin "$xray_rust_bin" --xray-core-bin "$xray_core_bin" \
          --no-auto-build --runs 1 --connections 32 --iterations 1 \
          --duration-ms 2000 --settle-ms 500 --sample-interval-ms 100 \
          --payload-size 16384 --run-timeout-ms 120000 \
          --out-dir "$out_dir"
        printf 'resource:%s:xhttp-h2-held-open\n' "$engine" >>"$FAKE_INVOCATION_LOG"
        printf 'resource|engine=%s|workload=xhttp-h2-held-open|xray_rust_bin=%s|xray_core_bin=%s|no_auto_build=true|runs=1|connections=32|iterations=1|duration_ms=2000|settle_ms=500|sample_interval_ms=100|payload_size=16384|run_timeout_ms=120000|out=%s\n' \
          "$engine" "$xray_rust_bin" "$xray_core_bin" "$out_dir" >>"$FAKE_CARGO_LOG"
        ;;
      *)
        die "unexpected scheduled workload: $workload"
        ;;
    esac
    ;;
  *)
    printf 'unexpected cargo invocation: %s\n' "$*" >&2
    exit 99
    ;;
esac
EOF

chmod +x "$FAKE_BIN/git" "$FAKE_BIN/go" "$FAKE_BIN/rustc" "$FAKE_BIN/cargo"

PATH="$FAKE_BIN:$PATH" \
  XRAY_CORE_CHECKOUT="$FAKE_CORE_LINK" \
  CARGO_TARGET_DIR="$FAKE_TARGET" \
  FAKE_CARGO_LOG="$FAKE_CARGO_LOG" \
  FAKE_GO_LOG="$FAKE_GO_LOG" \
  FAKE_CORE_PATH_LOG="$FAKE_CORE_PATH_LOG" \
  FAKE_INVOCATION_LOG="$TEST_ROOT/invocations.log" \
  FAKE_EXPECTED_XRAY_RUST_BIN="$FAKE_TARGET/release/xray-rust" \
  FAKE_EXPECTED_CARGO_TARGET_MODE='set' \
  FAKE_EXPECTED_CARGO_TARGET_VALUE="$FAKE_TARGET" \
  FAKE_EXPECTED_CORE="$FAKE_CORE" \
  FAKE_GIT_REVISION="$EXPECTED_XRAY_CORE_REVISION" \
  FAKE_GIT_STATUS_OUTPUT='' \
  XRAY_CORE_EXPECTED_REVISION='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  GOFLAGS='contaminated-goflags' \
  GOEXPERIMENT='contaminated-goexperiment' \
  GOENV='contaminated-goenv' \
  GOWORK='contaminated-gowork' \
  GOTOOLCHAIN='contaminated-gotoolchain' \
  CGO_ENABLED=1 \
  bash "$SCRIPT_UNDER_TEST" >/dev/null

scheduled_xray_core_binary="$(<"$FAKE_CORE_PATH_LOG")"
scheduled_tmp="$(dirname "$scheduled_xray_core_binary")"
scheduled_xray_rust_binary="$FAKE_TARGET/release/xray-rust"

assert_line_count() {
  local expected_count="$1"
  local expected_line="$2"
  local actual_count
  actual_count="$(grep -Fxc -- "$expected_line" "$FAKE_CARGO_LOG" || true)"
  if [[ "$actual_count" -ne "$expected_count" ]]; then
    printf 'expected %s occurrence(s), found %s: %s\n' \
      "$expected_count" "$actual_count" "$expected_line" >&2
    exit 100
  fi
}

assert_prefix_count() {
  local expected_count="$1"
  local prefix="$2"
  local actual_count
  actual_count="$(grep -c "^$prefix" "$FAKE_CARGO_LOG" || true)"
  if [[ "$actual_count" -ne "$expected_count" ]]; then
    printf 'expected %s %s record(s), found %s\n' \
      "$expected_count" "$prefix" "$actual_count" >&2
    exit 101
  fi
}

assert_line_count 1 \
  "test|command=test --locked -p xray-core-rs --test local_xray_interop_tests -- --ignored --nocapture --test-threads=1|fingerprints=$BROAD_FINGERPRINTS|burst_fingerprints=hellofirefox_99|burst_flows=32|xhttp_cases=all|goflags=unset|goexperiment=unset|core_expected_revision=unset|goenv=off|gowork=off|gotoolchain=local|cgo=0"
assert_line_count 1 \
  'build|command=build --locked --release -p xray-cli --bin xray-rust'

for engine in xray-rust xray-core; do
  assert_line_count 1 \
    "resource|engine=$engine|workload=many-idle-flows|xray_rust_bin=$scheduled_xray_rust_binary|xray_core_bin=$scheduled_xray_core_binary|no_auto_build=true|runs=1|connections=100|duration_ms=1000|out=$scheduled_tmp/many-idle-flows-$engine"
  assert_line_count 1 \
    "resource|engine=$engine|workload=xhttp-h2-held-open|xray_rust_bin=$scheduled_xray_rust_binary|xray_core_bin=$scheduled_xray_core_binary|no_auto_build=true|runs=1|connections=32|iterations=1|duration_ms=2000|settle_ms=500|sample_interval_ms=100|payload_size=16384|run_timeout_ms=120000|out=$scheduled_tmp/xhttp-held-open-$engine"
done

assert_prefix_count 1 'test|'
assert_prefix_count 1 'build|'
assert_prefix_count 4 'resource|'
assert_prefix_count 6 'invoke|'

expected_invocations=$'xray-core-build\nserial-ignored-interop\nrelease-xray-rust-build\nresource:xray-rust:many-idle-flows\nresource:xray-rust:xhttp-h2-held-open\nresource:xray-core:many-idle-flows\nresource:xray-core:xhttp-h2-held-open'
if [[ "$(<"$TEST_ROOT/invocations.log")" != "$expected_invocations" ]]; then
  echo 'scheduled interop operations ran out of order' >&2
  exit 102
fi

expected_go_log="build|core=$FAKE_CORE|output=$scheduled_xray_core_binary|goflags=unset|goexperiment=unset|goenv=off|gowork=off|gotoolchain=local|cgo=0"
if [[ "$(<"$FAKE_GO_LOG")" != "$expected_go_log" ]]; then
  echo 'scheduled Xray-core build was not pinned and hermetic' >&2
  exit 103
fi

if [[ -e "$scheduled_tmp" ]]; then
  echo "scheduled interop temporary directory was not cleaned up: $scheduled_tmp" >&2
  exit 104
fi

# Use a fixture-local script root so the unset/default target case cannot write
# into the repository's real target directory.
run_target_dir_case() {
  local case_name="$1"
  local target_mode="$2"
  local case_root="$TEST_ROOT/success-$case_name"
  local case_workspace="$case_root/workspace"
  local case_cargo_log="$case_root/cargo.log"
  local case_go_log="$case_root/go.log"
  local case_core_path_log="$case_root/xray-core-path.log"
  local case_invocation_log="$case_root/invocations.log"
  local case_script="$case_workspace/scripts/check-scheduled-pinned-interop.sh"
  local expected_xray_rust_binary
  local expected_target_mode
  local expected_target_value=''
  local target_env=()

  mkdir -p "$case_workspace/scripts" "$case_root/tmp"
  cp "$SCRIPT_UNDER_TEST" "$case_script"

  case "$target_mode" in
    unset)
      target_env=(-u CARGO_TARGET_DIR)
      expected_target_mode='unset'
      expected_xray_rust_binary="$case_workspace/target/release/xray-rust"
      ;;
    relative)
      expected_target_value='relative-cargo-target'
      expected_target_mode='set'
      target_env=("CARGO_TARGET_DIR=$expected_target_value")
      expected_xray_rust_binary="$case_workspace/$expected_target_value/release/xray-rust"
      ;;
    *)
      echo "unexpected target test mode: $target_mode" >&2
      exit 105
      ;;
  esac

  env "${target_env[@]}" \
    PATH="$FAKE_BIN:$PATH" \
    TMPDIR="$case_root/tmp" \
    XRAY_CORE_CHECKOUT="$FAKE_CORE_LINK" \
    FAKE_CARGO_LOG="$case_cargo_log" \
    FAKE_GO_LOG="$case_go_log" \
    FAKE_CORE_PATH_LOG="$case_core_path_log" \
    FAKE_INVOCATION_LOG="$case_invocation_log" \
    FAKE_EXPECTED_XRAY_RUST_BIN="$expected_xray_rust_binary" \
    FAKE_EXPECTED_CARGO_TARGET_MODE="$expected_target_mode" \
    FAKE_EXPECTED_CARGO_TARGET_VALUE="$expected_target_value" \
    FAKE_EXPECTED_CORE="$FAKE_CORE" \
    FAKE_GIT_REVISION="$EXPECTED_XRAY_CORE_REVISION" \
    FAKE_GIT_STATUS_OUTPUT='' \
    XRAY_CORE_EXPECTED_REVISION='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
    GOFLAGS='contaminated-goflags' \
    GOEXPERIMENT='contaminated-goexperiment' \
    GOENV='contaminated-goenv' \
    GOWORK='contaminated-gowork' \
    GOTOOLCHAIN='contaminated-gotoolchain' \
    CGO_ENABLED=1 \
    bash "$case_script" >/dev/null

  local case_xray_core_binary
  local case_scheduled_tmp
  local resource_count
  local resolved_binary_count
  case_xray_core_binary="$(<"$case_core_path_log")"
  case_scheduled_tmp="$(dirname "$case_xray_core_binary")"
  resource_count="$(grep -c '^resource|' "$case_cargo_log" || true)"
  resolved_binary_count="$(grep -Fc "|xray_rust_bin=$expected_xray_rust_binary|" "$case_cargo_log" || true)"

  if [[ "$resource_count" -ne 4 || "$resolved_binary_count" -ne 4 ]]; then
    echo "$case_name target fixture did not pass the resolved xray-rust binary to all resource runs" >&2
    exit 106
  fi
  if [[ "$(grep -c '^invoke|' "$case_cargo_log" || true)" -ne 6 ]]; then
    echo "$case_name target fixture did not preserve Cargo command cardinality" >&2
    exit 107
  fi
  if [[ "$(<"$case_invocation_log")" != "$expected_invocations" ]]; then
    echo "$case_name target fixture ran scheduled operations out of order" >&2
    exit 108
  fi
  if [[ "$(<"$case_go_log")" != "build|core=$FAKE_CORE|output=$case_xray_core_binary|goflags=unset|goexperiment=unset|goenv=off|gowork=off|gotoolchain=local|cgo=0" ]]; then
    echo "$case_name target fixture did not keep the Xray-core build hermetic" >&2
    exit 109
  fi
  if [[ -e "$case_scheduled_tmp" ]]; then
    echo "$case_name target fixture leaked its scheduled temporary directory" >&2
    exit 110
  fi
}

run_target_dir_case default unset
run_target_dir_case relative relative

MISMATCH_CARGO_LOG="$TEST_ROOT/mismatch-cargo.log"
MISMATCH_OUTPUT="$TEST_ROOT/mismatch-output.log"
set +e
PATH="$FAKE_BIN:$PATH" \
  XRAY_CORE_CHECKOUT="$FAKE_CORE_LINK" \
  CARGO_TARGET_DIR="$TEST_ROOT/mismatch-target" \
  FAKE_CARGO_LOG="$MISMATCH_CARGO_LOG" \
  FAKE_GO_LOG="$TEST_ROOT/mismatch-go.log" \
  FAKE_CORE_PATH_LOG="$TEST_ROOT/mismatch-xray-core-path.log" \
  FAKE_EXPECTED_CORE="$FAKE_CORE" \
  FAKE_GIT_REVISION='0123456789abcdef0123456789abcdef01234567' \
  bash "$SCRIPT_UNDER_TEST" >"$MISMATCH_OUTPUT" 2>&1
mismatch_status=$?
set -e

if [[ "$mismatch_status" -eq 0 ]]; then
  echo 'scheduled interop accepted a mismatched Xray-core revision' >&2
  exit 105
fi
if ! grep -Fq "expected $EXPECTED_XRAY_CORE_REVISION" "$MISMATCH_OUTPUT"; then
  echo 'scheduled interop mismatch did not name the expected pinned revision' >&2
  exit 106
fi
if [[ -s "$MISMATCH_CARGO_LOG" ]]; then
  echo 'scheduled interop invoked Cargo before rejecting a mismatched Xray-core revision' >&2
  exit 107
fi

DIRTY_CARGO_LOG="$TEST_ROOT/dirty-cargo.log"
DIRTY_GO_LOG="$TEST_ROOT/dirty-go.log"
DIRTY_INVOCATION_LOG="$TEST_ROOT/dirty-invocations.log"
DIRTY_OUTPUT="$TEST_ROOT/dirty-output.log"
set +e
PATH="$FAKE_BIN:$PATH" \
  XRAY_CORE_CHECKOUT="$FAKE_CORE_LINK" \
  CARGO_TARGET_DIR="$TEST_ROOT/dirty-target" \
  FAKE_CARGO_LOG="$DIRTY_CARGO_LOG" \
  FAKE_GO_LOG="$DIRTY_GO_LOG" \
  FAKE_CORE_PATH_LOG="$TEST_ROOT/dirty-xray-core-path.log" \
  FAKE_INVOCATION_LOG="$DIRTY_INVOCATION_LOG" \
  FAKE_EXPECTED_CORE="$FAKE_CORE" \
  FAKE_GIT_REVISION="$EXPECTED_XRAY_CORE_REVISION" \
  FAKE_GIT_STATUS_OUTPUT='?? local-untracked-file' \
  bash "$SCRIPT_UNDER_TEST" >"$DIRTY_OUTPUT" 2>&1
dirty_status=$?
set -e

if [[ "$dirty_status" -eq 0 ]]; then
  echo 'scheduled interop accepted a dirty Xray-core checkout' >&2
  exit 108
fi
if ! grep -Fq 'Xray-core checkout has uncommitted or untracked changes' "$DIRTY_OUTPUT"; then
  echo 'scheduled interop dirty-checkout failure was not diagnostic' >&2
  exit 109
fi
if [[ -s "$DIRTY_GO_LOG" || -s "$DIRTY_INVOCATION_LOG" ]]; then
  echo 'scheduled interop built Xray-core before rejecting a dirty checkout' >&2
  exit 110
fi
if [[ -s "$DIRTY_CARGO_LOG" ]]; then
  echo 'scheduled interop invoked Cargo before rejecting a dirty Xray-core checkout' >&2
  exit 111
fi

echo 'scheduled pinned interop is broad, hermetic, and resource-bounded'

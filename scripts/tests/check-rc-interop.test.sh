#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SCRIPT_UNDER_TEST="$WORKSPACE_ROOT/scripts/check-rc-interop.sh"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT

EXPECTED_XRAY_CORE_REVISION="5ca6f4b7d4dc20a881d4330e498892697627ec0c"
HOSTILE_XRAY_CORE_EXPECTED_REVISION="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

FAKE_BIN="$TEST_ROOT/bin"
FAKE_CORE="$TEST_ROOT/Xray-core"
FAKE_TARGET="$TEST_ROOT/target"
FAKE_CARGO_LOG="$TEST_ROOT/cargo.log"
mkdir -p "$FAKE_BIN" "$FAKE_CORE"

cat >"$FAKE_BIN/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"rev-parse --verify HEAD"* ]]; then
  printf '%s\n' "$FAKE_GIT_REVISION"
  exit 0
fi
printf 'unexpected git invocation: %s\n' "$*" >&2
exit 90
EOF

cat >"$FAKE_BIN/go" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "version" ]]; then
  printf '%s\n' 'go version go-test linux/amd64'
  exit 0
fi

output=''
while (( $# > 0 )); do
  if [[ "$1" == "-o" ]]; then
    shift
    output="${1:-}"
  fi
  shift || true
done
[[ -n "$output" ]] || {
  echo 'fake go build did not receive -o' >&2
  exit 91
}
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf '\''xray|%s\n'\'' "$*" >>"$FAKE_CARGO_LOG"' \
  'exit 0' >"$output"
chmod +x "$output"
EOF

cat >"$FAKE_BIN/rustc" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' 'rustc test'
EOF

cat >"$FAKE_BIN/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf 'invoke|%s\n' "$*" >>"$FAKE_CARGO_LOG"

case "${1:-}" in
  test)
    if [[ "$*" == *"--test local_xray_interop_tests"* ]]; then
      [[ "$*" == *"-- --ignored --nocapture --test-threads=1"* ]] || {
        echo 'RC interop Cargo invocation did not run the ignored suite serially' >&2
        exit 91
      }
      [[ -z "${XRAY_CORE_EXPECTED_REVISION+x}" ]] || {
        echo 'RC ignored interop inherited XRAY_CORE_EXPECTED_REVISION' >&2
        exit 92
      }
      printf '%s\n' ignored-interop >>"$FAKE_CARGO_LOG"
    fi
    exit 0
    ;;
  build)
    [[ "$*" == *"--locked --release -p xray-cli --bin xray-rust"* ]] || {
      printf 'unexpected xray-rust build command: %s\n' "$*" >&2
      exit 92
    }
    mkdir -p "$CARGO_TARGET_DIR/release"
    printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$CARGO_TARGET_DIR/release/xray-rust"
    chmod +x "$CARGO_TARGET_DIR/release/xray-rust"
    ;;
  run)
    xray_rust_bin=''
    xray_core_bin=''
    no_auto_build='false'
    args=("$@")
    for (( index = 0; index < ${#args[@]}; index++ )); do
      case "${args[index]}" in
        --xray-rust-bin)
          (( index += 1 ))
          xray_rust_bin="${args[index]:-}"
          ;;
        --xray-core-bin)
          (( index += 1 ))
          xray_core_bin="${args[index]:-}"
          ;;
        --no-auto-build)
          no_auto_build='true'
          ;;
      esac
    done

    [[ "$no_auto_build" == 'true' ]] || {
      echo 'RC interop benchmark must disable implicit builds' >&2
      exit 93
    }
    [[ -n "$xray_rust_bin" ]] || {
      echo 'RC interop benchmark did not pass --xray-rust-bin' >&2
      exit 94
    }
    [[ "$xray_rust_bin" == "$CARGO_TARGET_DIR/release/xray-rust" ]] || {
      printf 'unexpected xray-rust binary: %s\n' "$xray_rust_bin" >&2
      exit 95
    }
    [[ -x "$xray_rust_bin" ]] || {
      printf 'xray-rust binary was not built: %s\n' "$xray_rust_bin" >&2
      exit 96
    }
    [[ -x "$xray_core_bin" ]] || {
      printf 'xray-core binary was not built: %s\n' "$xray_core_bin" >&2
      exit 97
    }
    printf '%s\n' run >>"$FAKE_CARGO_LOG"
    ;;
  *)
    printf 'unexpected cargo invocation: %s\n' "$*" >&2
    exit 98
    ;;
esac
EOF

chmod +x "$FAKE_BIN/git" "$FAKE_BIN/go" "$FAKE_BIN/rustc" "$FAKE_BIN/cargo"

PATH="$FAKE_BIN:$PATH" \
  XRAY_CORE_CHECKOUT="$FAKE_CORE" \
  CARGO_TARGET_DIR="$FAKE_TARGET" \
  FAKE_CARGO_LOG="$FAKE_CARGO_LOG" \
  FAKE_GIT_REVISION="$EXPECTED_XRAY_CORE_REVISION" \
  XRAY_CORE_EXPECTED_REVISION="$HOSTILE_XRAY_CORE_EXPECTED_REVISION" \
  bash "$SCRIPT_UNDER_TEST" >/dev/null

[[ "$(grep -c '^run$' "$FAKE_CARGO_LOG")" -eq 2 ]] || {
  echo 'RC interop gate did not run both bounded UDP workloads' >&2
  exit 99
}
[[ "$(grep -c '^ignored-interop$' "$FAKE_CARGO_LOG")" -eq 1 ]] || {
  echo 'RC interop gate did not run exactly one ignored interop suite' >&2
  exit 100
}
[[ "$(grep -c '^xray|run -test -format json$' "$FAKE_CARGO_LOG")" -eq 1 ]] || {
  echo 'RC interop gate did not validate the Phase 2 fixture with Xray-core' >&2
  exit 101
}
for oracle_filter in dns_over_ caching_dns_ configured_dns_ managed_dns_over_; do
  if ! grep -Fq "$oracle_filter" "$FAKE_CARGO_LOG"; then
    printf 'RC interop gate did not run DNS oracle filter %s\n' "$oracle_filter" >&2
    exit 101
  fi
done

MISMATCH_CARGO_LOG="$TEST_ROOT/mismatch-cargo.log"
MISMATCH_OUTPUT="$TEST_ROOT/mismatch-output.log"
set +e
PATH="$FAKE_BIN:$PATH" \
  XRAY_CORE_CHECKOUT="$FAKE_CORE" \
  CARGO_TARGET_DIR="$TEST_ROOT/mismatch-target" \
  FAKE_CARGO_LOG="$MISMATCH_CARGO_LOG" \
  FAKE_GIT_REVISION="0123456789abcdef0123456789abcdef01234567" \
  XRAY_CORE_EXPECTED_REVISION="$HOSTILE_XRAY_CORE_EXPECTED_REVISION" \
  bash "$SCRIPT_UNDER_TEST" >"$MISMATCH_OUTPUT" 2>&1
mismatch_status=$?
set -e

if [[ "$mismatch_status" -eq 0 ]]; then
  echo 'RC interop accepted a mismatched Xray-core revision' >&2
  exit 102
fi
if ! grep -Fq "expected $EXPECTED_XRAY_CORE_REVISION" "$MISMATCH_OUTPUT"; then
  echo 'RC interop mismatch did not name the literal release pin' >&2
  exit 103
fi
if [[ -s "$MISMATCH_CARGO_LOG" ]]; then
  echo 'RC interop invoked Cargo before rejecting a mismatched Xray-core revision' >&2
  exit 104
fi

echo 'RC interop sanitizes hostile revision overrides and uses an explicit freshly built release binary'

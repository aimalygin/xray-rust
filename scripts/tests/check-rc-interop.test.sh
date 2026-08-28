#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SCRIPT_UNDER_TEST="$WORKSPACE_ROOT/scripts/check-rc-interop.sh"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT

FAKE_BIN="$TEST_ROOT/bin"
FAKE_CORE="$TEST_ROOT/Xray-core"
FAKE_TARGET="$TEST_ROOT/target"
FAKE_CARGO_LOG="$TEST_ROOT/cargo.log"
mkdir -p "$FAKE_BIN" "$FAKE_CORE"

cat >"$FAKE_BIN/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *"rev-parse --verify HEAD"* ]]; then
  printf '%s\n' '5ca6f4b7d4dc20a881d4330e498892697627ec0c'
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
printf '%s\n' '#!/usr/bin/env bash' 'exit 0' >"$output"
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

case "${1:-}" in
  test)
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
  bash "$SCRIPT_UNDER_TEST" >/dev/null

[[ "$(grep -c '^run$' "$FAKE_CARGO_LOG")" -eq 2 ]] || {
  echo 'RC interop gate did not run both bounded UDP workloads' >&2
  exit 99
}

echo 'RC interop uses an explicit freshly built release binary'

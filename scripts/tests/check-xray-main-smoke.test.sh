#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
SCRIPT_UNDER_TEST="$WORKSPACE_ROOT/scripts/check-xray-main-smoke.sh"
TEST_ROOT="$(mktemp -d)"
TEST_ROOT="$(cd "$TEST_ROOT" && pwd -P)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT

[[ -f "$SCRIPT_UNDER_TEST" ]] || {
  echo "missing script under test: $SCRIPT_UNDER_TEST" >&2
  exit 1
}

VALID_REVISION='0123456789abcdef0123456789abcdef01234567'
MISMATCH_REVISION='89abcdef0123456789abcdef0123456789abcdef'

FAKE_BIN="$TEST_ROOT/bin"
FAKE_CORE="$TEST_ROOT/Xray core"
FAKE_CORE_LINK="$TEST_ROOT/Xray-core-link"
FAKE_GIT_LOG="$TEST_ROOT/git.log"
FAKE_CARGO_LOG="$TEST_ROOT/cargo.log"
RUN_FROM="$TEST_ROOT/run from here"
mkdir -p "$FAKE_BIN" "$FAKE_CORE" "$RUN_FROM"
ln -s "$FAKE_CORE" "$FAKE_CORE_LINK"

cat >"$FAKE_BIN/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf 'git' >>"$FAKE_GIT_LOG"
printf '|%s' "$@" >>"$FAKE_GIT_LOG"
printf '\n' >>"$FAKE_GIT_LOG"

if (( $# == 5 )) &&
  [[ "$1" == '-C' ]] &&
  [[ "$2" == "$FAKE_EXPECTED_CORE" ]] &&
  [[ "$3" == 'rev-parse' ]] &&
  [[ "$4" == '--verify' ]] &&
  [[ "$5" == 'HEAD' ]]; then
  printf '%s\n' "$FAKE_GIT_REVISION"
  exit 0
fi

printf 'unexpected git invocation: %s\n' "$*" >&2
exit 90
EOF

cat >"$FAKE_BIN/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "$*" >&2
  exit 91
}

expected=(
  test --locked -p xray-core-rs
  --test local_xray_interop_tests
  rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases
  -- --ignored --nocapture --test-threads=1
)
actual=("$@")

(( ${#actual[@]} == ${#expected[@]} )) ||
  die "unexpected Cargo argument count: ${actual[*]}"
for (( index = 0; index < ${#expected[@]}; index++ )); do
  [[ "${actual[index]}" == "${expected[index]}" ]] ||
    die "unexpected Cargo arguments: ${actual[*]}"
done

[[ "$PWD" == "$FAKE_EXPECTED_WORKSPACE_ROOT" ]] ||
  die "Cargo did not run from the repository root: $PWD"
[[ -z "${GOFLAGS+x}" ]] || die 'Cargo inherited GOFLAGS'
[[ -z "${GOEXPERIMENT+x}" ]] || die 'Cargo inherited GOEXPERIMENT'
[[ "${GOENV:-}" == 'off' ]] || die 'Cargo did not receive GOENV=off'
[[ "${GOWORK:-}" == 'off' ]] || die 'Cargo did not receive GOWORK=off'
[[ "${GOTOOLCHAIN:-}" == 'local' ]] || die 'Cargo did not receive GOTOOLCHAIN=local'
[[ "${CGO_ENABLED:-}" == '0' ]] || die 'Cargo did not receive CGO_ENABLED=0'
[[ "${XRAY_CORE_CHECKOUT:-}" == "$FAKE_EXPECTED_CORE" ]] ||
  die "Cargo received an uncanonicalized Xray-core checkout: ${XRAY_CORE_CHECKOUT:-unset}"
[[ "${XRAY_CORE_EXPECTED_REVISION:-}" == "$FAKE_GIT_REVISION" ]] ||
  die "Cargo received the wrong expected revision: ${XRAY_CORE_EXPECTED_REVISION:-unset}"
[[ "${XRAY_XHTTP_INTEROP_CASES:-}" == 'h2-tls-stream-one' ]] ||
  die "Cargo received unexpected XHTTP cases: ${XRAY_XHTTP_INTEROP_CASES:-unset}"

printf 'cargo' >>"$FAKE_CARGO_LOG"
printf '|%s' "$@" >>"$FAKE_CARGO_LOG"
printf '|checkout=%s|expected_revision=%s|xhttp_cases=%s\n' \
  "$XRAY_CORE_CHECKOUT" \
  "$XRAY_CORE_EXPECTED_REVISION" \
  "$XRAY_XHTTP_INTEROP_CASES" >>"$FAKE_CARGO_LOG"
EOF

chmod +x "$FAKE_BIN/git" "$FAKE_BIN/cargo"

reset_logs() {
  : >"$FAKE_GIT_LOG"
  : >"$FAKE_CARGO_LOG"
}

run_smoke() {
  local output_file="$1"
  shift
  (
    cd "$RUN_FROM"
    env "$@" \
      PATH="$FAKE_BIN:$PATH" \
      FAKE_EXPECTED_CORE="$FAKE_CORE" \
      FAKE_EXPECTED_WORKSPACE_ROOT="$WORKSPACE_ROOT" \
      FAKE_GIT_LOG="$FAKE_GIT_LOG" \
      FAKE_CARGO_LOG="$FAKE_CARGO_LOG" \
      bash "$SCRIPT_UNDER_TEST"
  ) >"$output_file" 2>&1
}

assert_no_tools_invoked() {
  local context="$1"
  [[ ! -s "$FAKE_GIT_LOG" ]] || {
    echo "$context invoked Git" >&2
    exit 92
  }
  [[ ! -s "$FAKE_CARGO_LOG" ]] || {
    echo "$context invoked Cargo" >&2
    exit 93
  }
}

reset_logs
missing_output="$TEST_ROOT/missing-expected.log"
if run_smoke "$missing_output" \
  -u XRAY_CORE_EXPECTED_REVISION \
  XRAY_CORE_CHECKOUT="$FAKE_CORE_LINK" \
  FAKE_GIT_REVISION="$VALID_REVISION"; then
  echo 'Xray-core main smoke accepted a missing XRAY_CORE_EXPECTED_REVISION' >&2
  exit 94
fi
grep -Fq 'XRAY_CORE_EXPECTED_REVISION' "$missing_output" || {
  echo 'missing expected revision failure was not diagnostic' >&2
  exit 95
}
assert_no_tools_invoked 'missing expected revision validation'

invalid_revisions=(
  main
  HEAD
  0123456
  0123456789ABCDEF0123456789ABCDEF01234567
  0123456789abcdef0123456789abcdef0123456g
)
for invalid_revision in "${invalid_revisions[@]}"; do
  reset_logs
  invalid_output="$TEST_ROOT/invalid-${invalid_revision}.log"
  if run_smoke "$invalid_output" \
    XRAY_CORE_CHECKOUT="$FAKE_CORE_LINK" \
    XRAY_CORE_EXPECTED_REVISION="$invalid_revision" \
    FAKE_GIT_REVISION="$VALID_REVISION"; then
    printf 'Xray-core main smoke accepted invalid expected revision: %s\n' \
      "$invalid_revision" >&2
    exit 96
  fi
  grep -Fq \
    'XRAY_CORE_EXPECTED_REVISION must be an exact 40-character lowercase hexadecimal commit' \
    "$invalid_output" || {
    printf 'invalid expected revision failure was not diagnostic: %s\n' \
      "$invalid_revision" >&2
    exit 97
  }
  assert_no_tools_invoked "invalid expected revision validation ($invalid_revision)"
done

reset_logs
mismatch_output="$TEST_ROOT/mismatch.log"
if run_smoke "$mismatch_output" \
  XRAY_CORE_CHECKOUT="$FAKE_CORE_LINK" \
  XRAY_CORE_EXPECTED_REVISION="$VALID_REVISION" \
  FAKE_GIT_REVISION="$MISMATCH_REVISION"; then
  echo 'Xray-core main smoke accepted a mismatched checkout revision' >&2
  exit 98
fi
grep -Fq "$MISMATCH_REVISION" "$mismatch_output" || {
  echo 'revision mismatch failure did not name the actual revision' >&2
  exit 99
}
grep -Fq "$VALID_REVISION" "$mismatch_output" || {
  echo 'revision mismatch failure did not name the expected revision' >&2
  exit 100
}
expected_git_log="git|-C|$FAKE_CORE|rev-parse|--verify|HEAD"
[[ "$(<"$FAKE_GIT_LOG")" == "$expected_git_log" ]] || {
  echo 'revision mismatch did not resolve exactly one canonical checkout HEAD' >&2
  exit 101
}
[[ ! -s "$FAKE_CARGO_LOG" ]] || {
  echo 'revision mismatch invoked Cargo before failing' >&2
  exit 102
}

reset_logs
success_output="$TEST_ROOT/success.log"
run_smoke "$success_output" \
  XRAY_CORE_CHECKOUT="$FAKE_CORE_LINK" \
  XRAY_CORE_EXPECTED_REVISION="$VALID_REVISION" \
  FAKE_GIT_REVISION="$VALID_REVISION" \
  GOFLAGS='contaminated-goflags' \
  GOEXPERIMENT='contaminated-goexperiment' \
  GOENV='contaminated-goenv' \
  GOWORK='contaminated-gowork' \
  GOTOOLCHAIN='contaminated-gotoolchain' \
  CGO_ENABLED=1

expected_output="Xray-core main smoke revision: $VALID_REVISION"
[[ "$(<"$success_output")" == "$expected_output" ]] || {
  echo 'success output did not contain the exact full tested revision' >&2
  exit 103
}
[[ "$(<"$FAKE_GIT_LOG")" == "$expected_git_log" ]] || {
  echo 'success did not resolve exactly one canonical checkout HEAD' >&2
  exit 104
}
expected_cargo_log="cargo|test|--locked|-p|xray-core-rs|--test|local_xray_interop_tests|rust_socks_client_reaches_echo_server_through_local_xray_vless_xhttp_selected_cases|--|--ignored|--nocapture|--test-threads=1|checkout=$FAKE_CORE|expected_revision=$VALID_REVISION|xhttp_cases=h2-tls-stream-one"
[[ "$(<"$FAKE_CARGO_LOG")" == "$expected_cargo_log" ]] || {
  echo 'success did not run exactly one focused, hermetic Cargo test' >&2
  exit 105
}

echo 'Xray-core main smoke is revision-exact, hermetic, and focused'

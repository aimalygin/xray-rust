#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly MODE="${1:-all}"
readonly NIGHTLY="nightly-2026-05-22"

run_model() {
  cargo test --locked -p xray-core-rs --test routing_policy_concurrency_model
}

run_miri() {
  MIRIFLAGS="-Zmiri-strict-provenance" \
    cargo "+$NIGHTLY" miri test --locked -p xray-routing --lib domain_matcher::tests
  MIRIFLAGS="-Zmiri-strict-provenance" \
    cargo "+$NIGHTLY" miri test --locked -p xray-routing --lib ip_filter::tests
  MIRIFLAGS="-Zmiri-strict-provenance" \
    cargo "+$NIGHTLY" miri test --locked -p xray-routing --lib ip_range_set::tests
  MIRIFLAGS="-Zmiri-strict-provenance" \
    cargo "+$NIGHTLY" miri test --locked -p xray-routing --lib \
      domain_host_index::tests::exact_names_win_over_earlier_broader_matchers
  MIRIFLAGS="-Zmiri-strict-provenance" \
    cargo "+$NIGHTLY" miri test --locked -p xray-config --test model_tests
}

run_asan() {
  local host_target
  host_target="$(rustc "+$NIGHTLY" -vV | awk '/^host:/ { print $2 }')"
  if [[ -z "$host_target" ]]; then
    echo 'failed to resolve the nightly host target for ASan' >&2
    exit 1
  fi

  RUSTFLAGS="-Zsanitizer=address" \
    cargo "+$NIGHTLY" test \
      -Zbuild-std \
      --target "$host_target" \
      --locked \
      -p xray-config \
      -p xray-proxy \
      -p xray-vless-encryption \
      -p xray-transport \
      -p xray-tun \
      -p xray-core-rs \
      -p xray-ffi \
      --lib
  RUSTFLAGS="-Zsanitizer=address" \
    cargo "+$NIGHTLY" test \
      -Zbuild-std \
      --target "$host_target" \
      --locked \
      -p xray-ffi \
      --test ffi_tests
}

run_fuzz() (
  local seconds="${XRAY_V05_FUZZ_SECONDS:-60}"
  if [[ ! "$seconds" =~ ^[1-9][0-9]*$ ]]; then
    echo 'XRAY_V05_FUZZ_SECONDS must be a positive integer' >&2
    exit 1
  fi

  local fuzz_root
  local fuzz_parent="${XRAY_FUZZ_EVIDENCE_DIR:-${TMPDIR:-/tmp}}"
  mkdir -p "$fuzz_parent"
  fuzz_root="$(mktemp -d "$fuzz_parent/xray-v05-fuzz.XXXXXX")"
  # Keep reproducers on failure, and keep every CI campaign's evidence. Only
  # successful local runs without an explicit evidence directory are temporary.
  trap 'status=$?; if [[ "$status" == 0 && -z "${XRAY_FUZZ_EVIDENCE_DIR:-}" ]]; then rm -rf -- "$fuzz_root"; else echo "fuzz evidence retained at $fuzz_root"; fi; exit "$status"' EXIT
  {
    git rev-parse HEAD
    git rev-parse 'HEAD^{tree}'
    printf 'seconds_per_target=%s\n' "$seconds"
  } >"$fuzz_root/campaign.txt"

  local target
  for target in \
    config_json \
    dns_wire \
    vless_wire \
    inbound_wire \
    quic_sniff \
    xhttp_framing \
    tun_queue \
    vless_encryption_records \
    vless_encryption_handshake \
    ffi_lifecycle; do
    local corpus_dir="$fuzz_root/corpus/$target"
    local artifact_dir="$fuzz_root/artifacts/$target"
    mkdir -p "$corpus_dir" "$artifact_dir"
    cp -R "$WORKSPACE_ROOT/fuzz/corpus/$target/." "$corpus_dir/"

    local max_len=65536
    local timeout=10
    if [[ "$target" == "ffi_lifecycle" ]]; then
      max_len=16384
      timeout=15
    fi
    # ThinLTO can discard dependency coverage registration on the pinned
    # toolchain. Keep cross-crate counters and symbols for actionable crashes.
    CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_STRIP=none \
    cargo "+$NIGHTLY" fuzz run "$target" "$corpus_dir" -- \
      -max_total_time="$seconds" \
      -max_len="$max_len" \
      -timeout="$timeout" \
      -print_final_stats=1 \
      -verbosity=0 \
      -artifact_prefix="$artifact_dir/"
  done
)

cd "$WORKSPACE_ROOT"
case "$MODE" in
  all)
    run_model
    run_miri
    run_asan
    run_fuzz
    ;;
  model) run_model ;;
  miri) run_miri ;;
  asan) run_asan ;;
  fuzz) run_fuzz ;;
  *)
    echo 'usage: scripts/run-v05-host-hardening.sh [all|model|miri|asan|fuzz]' >&2
    exit 1
    ;;
esac

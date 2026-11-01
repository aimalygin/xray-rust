#!/usr/bin/env bash
set -euo pipefail

# Runs every fuzz target once over its seed corpus with an ordinary libFuzzer
# build. The ASan campaigns run only on release gates, so a target whose
# assertions no longer hold for the current code otherwise surfaces only there.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
artifacts="$(mktemp -d "${TMPDIR:-/tmp}/xray-fuzz-replay.XXXXXX")"
trap 'rm -rf "$artifacts"' EXIT

cargo build --locked --manifest-path "$ROOT/Cargo.toml" -p xray-rust-fuzz --bins
bin_dir="${CARGO_TARGET_DIR:-$ROOT/target}/debug"

status=0
for source in "$ROOT"/fuzz/fuzz_targets/*.rs; do
  target="$(basename "$source" .rs)"
  corpus="$ROOT/fuzz/corpus/$target"
  if [[ ! -d "$corpus" ]]; then
    echo "fuzz target $target has no seed corpus at fuzz/corpus/$target" >&2
    status=1
    continue
  fi
  # -runs=0 executes the corpus without mutating it; crash inputs go to the
  # temporary directory instead of the working directory.
  if ! "$bin_dir/$target" -runs=0 -timeout=10 \
    -artifact_prefix="$artifacts/$target-" "$corpus" >"$artifacts/$target.log" 2>&1; then
    echo "fuzz target $target fails on its seed corpus:" >&2
    tail -n 30 "$artifacts/$target.log" >&2
    status=1
  fi
done
exit "$status"

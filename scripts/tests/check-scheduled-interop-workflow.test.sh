#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
WORKFLOW="${SCHEDULED_INTEROP_WORKFLOW_UNDER_TEST:-$WORKSPACE_ROOT/.github/workflows/ci.yml}"

die() {
  echo "$*" >&2
  exit 1
}

job_body() {
  local job="$1"
  awk -v header="^  $job:[[:space:]]*(#.*)?$" '
    $0 ~ header { capture = 1; print; next }
    capture && /^  [A-Za-z0-9_-]+:/ { exit }
    capture { print }
  ' "$WORKFLOW"
}

normalize_yaml_body() {
  local body="$1"
  awk '
    function indentation(value, leading) {
      leading = value
      sub(/[^ ].*$/, "", leading)
      return length(leading)
    }
    function flush_scalar_blanks() {
      while (pending_scalar_blanks > 0) {
        print ""
        pending_scalar_blanks--
      }
    }
    function strip_structural_comment(value, result, index_, char_, next_) {
      result = ""
      in_single_quote = 0
      in_double_quote = 0
      for (index_ = 1; index_ <= length(value); index_++) {
        char_ = substr(value, index_, 1)
        next_ = substr(value, index_ + 1, 1)

        if (in_double_quote) {
          result = result char_
          if (char_ == "\\") {
            if (index_ < length(value)) {
              index_++
              result = result substr(value, index_, 1)
            }
          } else if (char_ == "\"") {
            in_double_quote = 0
          }
          continue
        }

        if (in_single_quote) {
          result = result char_
          if (char_ == single_quote) {
            if (next_ == single_quote) {
              index_++
              result = result next_
            } else {
              in_single_quote = 0
            }
          }
          continue
        }

        if (char_ == "\"") {
          in_double_quote = 1
        } else if (char_ == single_quote) {
          in_single_quote = 1
        } else if (char_ == "#" &&
                   (index_ == 1 ||
                    substr(value, index_ - 1, 1) ~ /[[:space:]]/)) {
          sub(/[[:space:]]+$/, "", result)
          return result
        }
        result = result char_
      }
      return result
    }
    BEGIN {
      single_quote = sprintf("%c", 39)
    }
    {
      raw = $0
      if (in_scalar) {
        if (raw ~ /^[[:space:]]*$/) {
          pending_scalar_blanks++
          next
        }
        if (indentation(raw) > scalar_indent) {
          flush_scalar_blanks()
          print raw
          next
        }
        pending_scalar_blanks = 0
        in_scalar = 0
      }

      if (raw ~ /^[[:space:]]*#/ || raw ~ /^[[:space:]]*$/) {
        next
      }
      line = strip_structural_comment(raw)
      sub(/[[:space:]]+$/, "", line)
      if (line ~ /^[[:space:]]*$/) {
        next
      }
      print line
      if (line ~ /:[[:space:]]*[|>][-+0-9]*[[:space:]]*$/) {
        in_scalar = 1
        scalar_indent = indentation(raw)
        pending_scalar_blanks = 0
      }
    }
  ' <<<"$body"
}

require_exact() {
  local body="$1"
  local line="$2"
  local message="$3"
  grep -Fxq -- "$line" <<<"$body" || die "$message"
}

assert_equal() {
  local label="$1"
  local actual="$2"
  local expected="$3"
  if [[ "$actual" == "$expected" ]]; then
    return
  fi

  echo "$label differs from its reviewed canonical policy" >&2
  awk '
    FNR == NR {
      expected[FNR] = $0
      expected_count = FNR
      next
    }
    {
      actual[FNR] = $0
      actual_count = FNR
    }
    END {
      count = expected_count > actual_count ? expected_count : actual_count
      for (line = 1; line <= count; line++) {
        if (expected[line] != actual[line] ||
            line > expected_count || line > actual_count) {
          expected_line = line <= expected_count ? expected[line] : "<end>"
          actual_line = line <= actual_count ? actual[line] : "<end>"
          print "  first difference at line " line
          print "  expected: " expected_line
          print "  actual:   " actual_line
          exit
        }
      }
    }
  ' <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2
  exit 1
}

needs_body() {
  local body="$1"
  awk '
    $0 == "    needs:" { capture = 1 }
    capture && $0 != "    needs:" && $0 !~ /^      - / { exit }
    capture { print }
  ' <<<"$body"
}

top_level_lines() {
  local body="$1"
  awk '/^[^[:space:]]/ { print }' <<<"$body"
}

job_header_lines() {
  local body="$1"
  awk '
    $0 == "jobs:" { in_jobs = 1; next }
    in_jobs && /^  [^[:space:]]/ { print }
  ' <<<"$body"
}

job_field_lines() {
  local body="$1"
  awk '/^    [^[:space:]]/ { print }' <<<"$body"
}

expected_header="$(cat <<'EXPECTED'
name: CI
on:
  pull_request:
  push:
    branches: [main]
    tags: ["v*"]
  schedule:
    - cron: "17 6 * * 1"
permissions:
  contents: read
concurrency:
  group: ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}
  cancel-in-progress: ${{ !startsWith(github.ref, 'refs/tags/') }}
env:
  CARGO_TERM_COLOR: always
EXPECTED
)"

expected_top_level="$(cat <<'EXPECTED'
name: CI
on:
permissions:
concurrency:
env:
jobs:
EXPECTED
)"

expected_job_headers="$(cat <<'EXPECTED'
  release-metadata:
  secrets:
  rust:
  go-oracles:
  rc-interop:
  scheduled-pinned-interop:
  xray-core-main-smoke:
  fuzz-smoke:
  apple:
  android:
  supply-chain:
  publish-prerelease:
EXPECTED
)"

expected_rc_interop="$(cat <<'EXPECTED'
  rc-interop:
    if: needs.release-metadata.outputs.is_rc == 'true'
    needs: release-metadata
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    steps:
      - name: Check out release candidate
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - name: Check out pinned Xray-core oracle
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          repository: XTLS/Xray-core
          ref: 5ca6f4b7d4dc20a881d4330e498892697627ec0c
          path: Xray-core
          persist-credentials: false
      - name: Install pinned Go toolchain
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
        with:
          go-version: "1.26.5"
          cache-dependency-path: Xray-core/go.sum
      - name: Install pinned Rust toolchain
        run: rustup toolchain install 1.96.0 --profile minimal
      - name: Select pinned Rust toolchain
        run: rustup default 1.96.0
      - name: Run release-candidate interoperability gate
        env:
          XRAY_CORE_CHECKOUT: ${{ github.workspace }}/Xray-core
        run: bash scripts/check-rc-interop.sh
EXPECTED
)"

expected_scheduled_pinned="$(cat <<'EXPECTED'
  scheduled-pinned-interop:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-24.04
    timeout-minutes: 90
    steps:
      - name: Check out scheduled xray-rust revision
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - name: Check out pinned Xray-core oracle
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          repository: XTLS/Xray-core
          ref: 5ca6f4b7d4dc20a881d4330e498892697627ec0c
          path: Xray-core
          persist-credentials: false
      - name: Install pinned Go toolchain
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
        with:
          go-version: "1.26.5"
          cache-dependency-path: Xray-core/go.sum
      - name: Install pinned Rust toolchain
        run: rustup toolchain install 1.96.0 --profile minimal
      - name: Select pinned Rust toolchain
        run: rustup default 1.96.0
      - name: Run broad pinned interoperability and resource gate
        env:
          XRAY_CORE_CHECKOUT: ${{ github.workspace }}/Xray-core
        run: bash scripts/check-scheduled-pinned-interop.sh
EXPECTED
)"

expected_main_smoke="$(cat <<'EXPECTED'
  xray-core-main-smoke:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-24.04
    timeout-minutes: 30
    continue-on-error: true
    steps:
      - name: Check out scheduled xray-rust revision
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - name: Check out Xray-core main
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          repository: XTLS/Xray-core
          ref: main
          path: Xray-core
          persist-credentials: false
      - name: Resolve Xray-core main revision
        id: xray
        run: |
          revision="$(git -C Xray-core rev-parse --verify HEAD)"
          if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then
            echo "Xray-core main resolved to invalid revision: $revision" >&2
            exit 1
          fi
          echo "revision=$revision" >>"$GITHUB_OUTPUT"
          printf 'Xray-core main revision: `%s`\n' "$revision" >>"$GITHUB_STEP_SUMMARY"
      - name: Install pinned Go toolchain
        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e
        with:
          go-version: "1.26.5"
          cache-dependency-path: Xray-core/go.sum
      - name: Install pinned Rust toolchain
        run: rustup toolchain install 1.96.0 --profile minimal
      - name: Select pinned Rust toolchain
        run: rustup default 1.96.0
      - name: Run focused Xray-core main compatibility smoke
        env:
          XRAY_CORE_CHECKOUT: ${{ github.workspace }}/Xray-core
          XRAY_CORE_EXPECTED_REVISION: ${{ steps.xray.outputs.revision }}
        run: bash scripts/check-xray-main-smoke.sh
      - name: Report warning-only compatibility failure
        if: failure()
        run: echo "::warning title=Xray-core main compatibility smoke failed::revision=${{ steps.xray.outputs.revision }} run=${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"
EXPECTED
)"

expected_rust="$(cat <<'EXPECTED'
  rust:
    runs-on: ubuntu-24.04
    timeout-minutes: 45
    steps:
      - name: Check out repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - name: Check repository scripts
        run: |
          for script in scripts/*.sh scripts/tests/*.sh; do
            bash -n "$script"
          done
          bash scripts/tests/check-release-version.test.sh
          bash scripts/tests/check-prerelease-workflow.test.sh
          bash scripts/tests/check-rc-interop.test.sh
          bash scripts/tests/check-scheduled-pinned-interop.test.sh
          bash scripts/tests/check-xray-main-smoke.test.sh
          bash scripts/tests/check-scheduled-interop-workflow.test.sh
          bash scripts/tests/check-public-fixtures.test.sh
          bash scripts/tests/check-benchmark-publication.test.sh
          bash scripts/tests/bench-xhttp-memory.test.sh
          if [[ -f docs/benchmarks/results/2026-08-29-v26.7.28/manifest.json ]]; then
            python3 scripts/check-benchmark-publication.py docs/benchmarks/results/2026-08-29-v26.7.28
          fi
      - name: Install pinned Rust toolchain
        run: rustup toolchain install 1.96.0 --profile minimal --component clippy,rustfmt
      - name: Select pinned Rust toolchain
        run: rustup default 1.96.0
      - name: Check formatting
        run: cargo fmt --all -- --check
      - name: Lint
        run: cargo clippy --workspace --all-targets --all-features --locked -- -D warnings -W clippy::perf -W clippy::suspicious
      - name: Test
        run: cargo test --workspace --exclude xray-rust-fuzz --all-targets --locked
      - name: Build public API documentation
        env:
          RUSTDOCFLAGS: -D warnings
        run: cargo doc --workspace --no-deps --locked
      - name: Test mobile build-script guards
        run: bash scripts/tests/check-mobile-toolchains.test.sh
EXPECTED
)"

expected_publish_needs="$(cat <<'EXPECTED'
    needs:
      - release-metadata
      - secrets
      - rust
      - go-oracles
      - rc-interop
      - fuzz-smoke
      - apple
      - android
      - supply-chain
EXPECTED
)"

expected_publish_fields="$(cat <<'EXPECTED'
    if: needs.release-metadata.outputs.is_rc == 'true'
    needs:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    permissions:
    steps:
EXPECTED
)"

workflow_header="$(awk '/^jobs:/ { exit } { print }' "$WORKFLOW")"
normalized_header="$(normalize_yaml_body "$workflow_header")"
assert_equal 'workflow header' "$normalized_header" "$expected_header"
require_exact "$normalized_header" '  schedule:' 'CI workflow does not declare a schedule event'
require_exact "$normalized_header" '  group: ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}' 'CI concurrency does not isolate scheduled runs from pushes'

workflow_body="$(<"$WORKFLOW")"
normalized_workflow="$(normalize_yaml_body "$workflow_body")"
assert_equal 'workflow top-level structure' "$(top_level_lines "$normalized_workflow")" "$expected_top_level"
assert_equal 'workflow job list' "$(job_header_lines "$normalized_workflow")" "$expected_job_headers"

rc_interop_job="$(job_body rc-interop)"
scheduled_pinned_job="$(job_body scheduled-pinned-interop)"
main_smoke_job="$(job_body xray-core-main-smoke)"
publish_job="$(job_body publish-prerelease)"
rust_job="$(job_body rust)"
[[ -n "$rc_interop_job" ]] || die 'RC interoperability job is missing'
[[ -n "$scheduled_pinned_job" ]] || die 'scheduled pinned interoperability job is missing'
[[ -n "$main_smoke_job" ]] || die 'Xray-core main smoke job is missing'
[[ -n "$publish_job" ]] || die 'prerelease publication job is missing'
[[ -n "$rust_job" ]] || die 'Rust CI job is missing'

assert_equal 'RC interoperability job' "$(normalize_yaml_body "$rc_interop_job")" "$expected_rc_interop"
assert_equal 'scheduled pinned interoperability job' "$(normalize_yaml_body "$scheduled_pinned_job")" "$expected_scheduled_pinned"
assert_equal 'Xray-core main smoke job' "$(normalize_yaml_body "$main_smoke_job")" "$expected_main_smoke"

normalized_publish_job="$(normalize_yaml_body "$publish_job")"
assert_equal 'prerelease publication fields' "$(job_field_lines "$normalized_publish_job")" "$expected_publish_fields"
assert_equal 'prerelease publication dependencies' "$(needs_body "$normalized_publish_job")" "$expected_publish_needs"

normalized_rust_job="$(normalize_yaml_body "$rust_job")"
assert_equal 'Rust CI job' "$normalized_rust_job" "$expected_rust"

echo 'scheduled interoperability workflow matches its reviewed canonical policy'

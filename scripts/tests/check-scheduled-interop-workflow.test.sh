#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
WORKFLOW="${SCHEDULED_INTEROP_WORKFLOW_UNDER_TEST:-$WORKSPACE_ROOT/.github/workflows/ci.yml}"
PINNED_XRAY_REVISION='5ca6f4b7d4dc20a881d4330e498892697627ec0c'
CHECKOUT_ACTION='        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1'
SETUP_GO_ACTION='        uses: actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0'

die() {
  echo "$*" >&2
  exit 1
}

job_body() {
  local job="$1"
  awk -v header="  $job:" '
    $0 == header { capture = 1 }
    capture && $0 != header && /^  [A-Za-z0-9_-]+:/ { exit }
    capture { print }
  ' "$WORKFLOW"
}

step_body() {
  local body="$1"
  local step="$2"
  awk -v header="      - name: $step" '
    $0 == header { capture = 1 }
    capture && $0 != header && /^      - name:/ { exit }
    capture { print }
  ' <<<"$body"
}

require_exact() {
  local body="$1"
  local line="$2"
  local message="$3"
  grep -Fxq -- "$line" <<<"$body" || die "$message"
}

without_comments() {
  local body="$1"
  awk '
    /^[[:space:]]*#/ { next }
    {
      sub(/[[:space:]]+#.*/, "")
      if ($0 !~ /^[[:space:]]*$/) {
        print
      }
    }
  ' <<<"$body"
}

reject_text() {
  local body="$1"
  local text="$2"
  local message="$3"
  local active_body
  active_body="$(without_comments "$body")"
  if grep -Fq -- "$text" <<<"$active_body"; then
    die "$message"
  fi
}

exact_count() {
  local body="$1"
  local line="$2"
  awk -v needle="$line" '$0 == needle { count++ } END { print count + 0 }' <<<"$body"
}

checkout_count() {
  local body="$1"
  awk '
    index($0, "uses: actions/checkout@") { count++ }
    END { print count + 0 }
  ' <<<"$(without_comments "$body")"
}

contains_count() {
  local body="$1"
  local text="$2"
  awk -v needle="$text" '
    index($0, needle) { count++ }
    END { print count + 0 }
  ' <<<"$(without_comments "$body")"
}

yaml_key_count() {
  local body="$1"
  local key="$2"
  awk -v key="$key" '
    BEGIN {
      single_quote = sprintf("%c", 39)
      quote = "[\"" single_quote "]?"
      pattern = "(^|[,{][[:space:]]*)" quote key quote \
        "[[:space:]]*:[[:space:]]*"
    }
    {
      line = $0
      sub(/^[[:space:]]*/, "", line)
      if (line ~ pattern) {
        count++
      }
    }
    END { print count + 0 }
  ' <<<"$(without_comments "$body")"
}

env_key_count() {
  local body="$1"
  local key="$2"
  awk -v key="$key" '
    function trim(value) {
      sub(/^[[:space:]]*/, "", value)
      sub(/[[:space:]]*$/, "", value)
      return value
    }
    function indentation(value, leading) {
      leading = value
      sub(/[^ ].*$/, "", leading)
      return length(leading)
    }
    function mapping_key(value, separator, name, first, last) {
      value = trim(value)
      separator = index(value, ":")
      if (!separator) {
        return ""
      }
      name = trim(substr(value, 1, separator - 1))
      first = substr(name, 1, 1)
      last = substr(name, length(name), 1)
      if ((first == "\"" || first == single_quote) && last == first) {
        name = substr(name, 2, length(name) - 2)
      }
      return name
    }
    BEGIN {
      single_quote = sprintf("%c", 39)
      quote = "[\"" single_quote "]?"
      flow_pattern = "(^|[,{][[:space:]]*)" quote key quote \
        "[[:space:]]*:[[:space:]]*"
      env_indent = -1
    }
    {
      raw = $0
      indent = indentation(raw)
      line = trim(raw)

      if (env_indent >= 0 && indent <= env_indent) {
        env_indent = -1
      }
      if (env_indent >= 0 && indent == env_indent + 2 && \
          mapping_key(line) == key) {
        count++
      }

      if ((indent == 0 || indent == 4 || indent == 8) && \
          mapping_key(line) == "env") {
        value = trim(substr(line, index(line, ":") + 1))
        if (value ~ flow_pattern) {
          count++
        }
        if (value == "") {
          env_indent = indent
        }
      }
    }
    END { print count + 0 }
  ' <<<"$(without_comments "$body")"
}

checkout_path_count() {
  local body="$1"
  awk '/^          path:/ { count++ } END { print count + 0 }' <<<"$body"
}

line_number_exact() {
  local body="$1"
  local line="$2"
  local occurrence="${3:-1}"
  awk -v needle="$line" -v occurrence="$occurrence" '
    $0 == needle {
      seen++
      if (seen == occurrence) {
        print NR
        exit
      }
    }
  ' <<<"$body"
}

scheduled_pinned_job="$(job_body scheduled-pinned-interop)"
[[ -n "$scheduled_pinned_job" ]] || \
  die 'scheduled pinned interoperability job is missing'

main_smoke_job="$(job_body xray-core-main-smoke)"
[[ -n "$main_smoke_job" ]] || \
  die 'Xray-core main smoke job is missing'

rust_job="$(job_body rust)"
rc_interop_job="$(job_body rc-interop)"
publish_job="$(job_body publish-prerelease)"
[[ -n "$rust_job" ]] || die 'Rust CI job is missing'
[[ -n "$rc_interop_job" ]] || die 'RC interoperability job is missing'
[[ -n "$publish_job" ]] || die 'prerelease publication job is missing'

workflow_body="$(<"$WORKFLOW")"
[[ "$(env_key_count "$workflow_body" GOTOOLCHAIN)" == 0 ]] || \
  die 'CI workflow overrides the pinned Go toolchain'
[[ "$(env_key_count "$workflow_body" RUSTUP_TOOLCHAIN)" == 0 ]] || \
  die 'CI workflow overrides the pinned Rust toolchain'

workflow_header="$(awk '/^jobs:/ { exit } { print }' "$WORKFLOW")"
require_exact "$workflow_header" '  schedule:' \
  'CI workflow does not declare a schedule event'
grep -Eq '^    - cron: ' <<<"$workflow_header" || \
  die 'CI workflow schedule has no cron trigger'
require_exact \
  "$workflow_header" \
  '  group: ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}' \
  'CI concurrency does not isolate scheduled runs from pushes'

require_exact "$scheduled_pinned_job" "    if: github.event_name == 'schedule'" \
  'scheduled pinned interoperability is not schedule-only'
require_exact "$scheduled_pinned_job" '    runs-on: ubuntu-24.04' \
  'scheduled pinned interoperability does not use Ubuntu 24.04'
require_exact "$scheduled_pinned_job" '    timeout-minutes: 90' \
  'scheduled pinned interoperability does not have a 90-minute bound'
reject_text "$scheduled_pinned_job" 'continue-on-error:' \
  'scheduled pinned interoperability is non-blocking'

pinned_source_checkout="$(step_body "$scheduled_pinned_job" 'Check out scheduled xray-rust revision')"
pinned_core_checkout="$(step_body "$scheduled_pinned_job" 'Check out pinned Xray-core oracle')"
[[ -n "$pinned_source_checkout" && -n "$pinned_core_checkout" ]] || \
  die 'scheduled pinned checkout steps are missing'
[[ "$(yaml_key_count "$pinned_source_checkout" ref)" == 0 ]] || \
  die 'scheduled pinned xray-rust checkout overrides the scheduled event revision'
require_exact "$pinned_core_checkout" "          ref: $PINNED_XRAY_REVISION" \
  'scheduled pinned Xray-core checkout does not use the audited commit'

[[ "$(checkout_count "$scheduled_pinned_job")" == 2 ]] || \
  die 'scheduled pinned interoperability must perform exactly two checkouts'
[[ "$(exact_count "$scheduled_pinned_job" "$CHECKOUT_ACTION")" == 2 ]] || \
  die 'scheduled pinned interoperability does not pin both checkout actions'
require_exact "$scheduled_pinned_job" '          repository: XTLS/Xray-core' \
  'scheduled pinned interoperability does not check out XTLS/Xray-core'
require_exact "$scheduled_pinned_job" "          ref: $PINNED_XRAY_REVISION" \
  'scheduled pinned interoperability does not pin the audited Xray-core commit'
require_exact "$scheduled_pinned_job" '          path: Xray-core' \
  'scheduled pinned interoperability does not use the Xray-core checkout path'
[[ "$(exact_count "$scheduled_pinned_job" '          path: Xray-core')" == 1 ]] || \
  die 'scheduled pinned interoperability has an ambiguous Xray-core path'
[[ "$(checkout_path_count "$scheduled_pinned_job")" == 1 ]] || \
  die 'scheduled pinned interoperability does not leave xray-rust at the workspace root'

pinned_first_checkout="$(line_number_exact "$scheduled_pinned_job" "$CHECKOUT_ACTION" 1)"
pinned_second_checkout="$(line_number_exact "$scheduled_pinned_job" "$CHECKOUT_ACTION" 2)"
pinned_repository="$(line_number_exact "$scheduled_pinned_job" '          repository: XTLS/Xray-core')"
[[ "$pinned_first_checkout" =~ ^[0-9]+$ && "$pinned_second_checkout" =~ ^[0-9]+$ && "$pinned_repository" =~ ^[0-9]+$ ]] || \
  die 'scheduled pinned checkout ordering markers are missing'
(( pinned_first_checkout < pinned_second_checkout && pinned_second_checkout < pinned_repository )) || \
  die 'scheduled pinned job does not check out xray-rust before Xray-core'

require_exact "$scheduled_pinned_job" "$SETUP_GO_ACTION" \
  'scheduled pinned interoperability does not pin the Go setup action'
require_exact "$scheduled_pinned_job" '          go-version: "1.26.5"' \
  'scheduled pinned interoperability does not use Go 1.26.5'
require_exact "$scheduled_pinned_job" \
  '        run: rustup toolchain install 1.96.0 --profile minimal' \
  'scheduled pinned interoperability does not install Rust 1.96.0'
require_exact "$scheduled_pinned_job" \
  '        run: rustup default 1.96.0' \
  'scheduled pinned interoperability does not select Rust 1.96.0'
[[ "$(contains_count "$scheduled_pinned_job" 'uses: actions/setup-go@')" == 1 ]] || \
  die 'scheduled pinned interoperability does not have exactly one Go setup action'
[[ "$(exact_count "$scheduled_pinned_job" "$SETUP_GO_ACTION")" == 1 ]] || \
  die 'scheduled pinned interoperability has an ambiguous pinned Go setup action'
[[ "$(contains_count "$scheduled_pinned_job" '          go-version:')" == 1 ]] || \
  die 'scheduled pinned interoperability does not have exactly one Go version'
[[ "$(exact_count "$scheduled_pinned_job" '          go-version: "1.26.5"')" == 1 ]] || \
  die 'scheduled pinned interoperability has an ambiguous Go 1.26.5 pin'
[[ "$(contains_count "$scheduled_pinned_job" 'rustup toolchain install')" == 1 ]] || \
  die 'scheduled pinned interoperability does not have exactly one Rust install'
[[ "$(exact_count "$scheduled_pinned_job" '        run: rustup toolchain install 1.96.0 --profile minimal')" == 1 ]] || \
  die 'scheduled pinned interoperability has an ambiguous Rust 1.96.0 install'
[[ "$(contains_count "$scheduled_pinned_job" 'rustup default')" == 1 ]] || \
  die 'scheduled pinned interoperability does not have exactly one Rust selection'
[[ "$(exact_count "$scheduled_pinned_job" '        run: rustup default 1.96.0')" == 1 ]] || \
  die 'scheduled pinned interoperability has an ambiguous Rust 1.96.0 selection'
require_exact "$scheduled_pinned_job" \
  '          XRAY_CORE_CHECKOUT: ${{ github.workspace }}/Xray-core' \
  'scheduled pinned interoperability does not pass the absolute Xray-core checkout'
require_exact "$scheduled_pinned_job" \
  '        run: bash scripts/check-scheduled-pinned-interop.sh' \
  'scheduled pinned interoperability does not call its dedicated script'
reject_text "$scheduled_pinned_job" 'check-rc-interop.sh' \
  'scheduled pinned interoperability calls the release gate'
reject_text "$scheduled_pinned_job" 'check-xray-main-smoke.sh' \
  'scheduled pinned interoperability calls the upstream-main smoke'

require_exact "$main_smoke_job" "    if: github.event_name == 'schedule'" \
  'Xray-core main smoke is not schedule-only'
require_exact "$main_smoke_job" '    runs-on: ubuntu-24.04' \
  'Xray-core main smoke does not use Ubuntu 24.04'
require_exact "$main_smoke_job" '    timeout-minutes: 30' \
  'Xray-core main smoke does not have a 30-minute bound'
require_exact "$main_smoke_job" '    continue-on-error: true' \
  'Xray-core main smoke is not warning-only at job scope'
[[ "$(exact_count "$main_smoke_job" '    continue-on-error: true')" == 1 ]] || \
  die 'Xray-core main smoke has an ambiguous continue-on-error policy'

main_source_checkout="$(step_body "$main_smoke_job" 'Check out scheduled xray-rust revision')"
main_core_checkout="$(step_body "$main_smoke_job" 'Check out Xray-core main')"
[[ -n "$main_source_checkout" && -n "$main_core_checkout" ]] || \
  die 'Xray-core main checkout steps are missing'
[[ "$(yaml_key_count "$main_source_checkout" ref)" == 0 ]] || \
  die 'Xray-core main smoke xray-rust checkout overrides the scheduled event revision'
require_exact "$main_core_checkout" '          ref: main' \
  'Xray-core main checkout does not explicitly follow main'

[[ "$(checkout_count "$main_smoke_job")" == 2 ]] || \
  die 'Xray-core main smoke must perform exactly two checkouts'
[[ "$(exact_count "$main_smoke_job" "$CHECKOUT_ACTION")" == 2 ]] || \
  die 'Xray-core main smoke does not pin both checkout actions'
require_exact "$main_smoke_job" '          repository: XTLS/Xray-core' \
  'Xray-core main smoke does not check out XTLS/Xray-core'
require_exact "$main_smoke_job" '          ref: main' \
  'Xray-core main smoke does not explicitly follow main'
require_exact "$main_smoke_job" '          path: Xray-core' \
  'Xray-core main smoke does not use the Xray-core checkout path'
[[ "$(exact_count "$main_smoke_job" '          path: Xray-core')" == 1 ]] || \
  die 'Xray-core main smoke has an ambiguous Xray-core path'
[[ "$(checkout_path_count "$main_smoke_job")" == 1 ]] || \
  die 'Xray-core main smoke does not leave xray-rust at the workspace root'

main_first_checkout="$(line_number_exact "$main_smoke_job" "$CHECKOUT_ACTION" 1)"
main_second_checkout="$(line_number_exact "$main_smoke_job" "$CHECKOUT_ACTION" 2)"
main_repository="$(line_number_exact "$main_smoke_job" '          repository: XTLS/Xray-core')"
[[ "$main_first_checkout" =~ ^[0-9]+$ && "$main_second_checkout" =~ ^[0-9]+$ && "$main_repository" =~ ^[0-9]+$ ]] || \
  die 'Xray-core main checkout ordering markers are missing'
(( main_first_checkout < main_second_checkout && main_second_checkout < main_repository )) || \
  die 'Xray-core main job does not check out xray-rust before Xray-core'

require_exact "$main_smoke_job" "$SETUP_GO_ACTION" \
  'Xray-core main smoke does not pin the Go setup action'
require_exact "$main_smoke_job" '          go-version: "1.26.5"' \
  'Xray-core main smoke does not use Go 1.26.5'
require_exact "$main_smoke_job" \
  '        run: rustup toolchain install 1.96.0 --profile minimal' \
  'Xray-core main smoke does not install Rust 1.96.0'
require_exact "$main_smoke_job" \
  '        run: rustup default 1.96.0' \
  'Xray-core main smoke does not select Rust 1.96.0'
[[ "$(contains_count "$main_smoke_job" 'uses: actions/setup-go@')" == 1 ]] || \
  die 'Xray-core main smoke does not have exactly one Go setup action'
[[ "$(exact_count "$main_smoke_job" "$SETUP_GO_ACTION")" == 1 ]] || \
  die 'Xray-core main smoke has an ambiguous pinned Go setup action'
[[ "$(contains_count "$main_smoke_job" '          go-version:')" == 1 ]] || \
  die 'Xray-core main smoke does not have exactly one Go version'
[[ "$(exact_count "$main_smoke_job" '          go-version: "1.26.5"')" == 1 ]] || \
  die 'Xray-core main smoke has an ambiguous Go 1.26.5 pin'
[[ "$(contains_count "$main_smoke_job" 'rustup toolchain install')" == 1 ]] || \
  die 'Xray-core main smoke does not have exactly one Rust install'
[[ "$(exact_count "$main_smoke_job" '        run: rustup toolchain install 1.96.0 --profile minimal')" == 1 ]] || \
  die 'Xray-core main smoke has an ambiguous Rust 1.96.0 install'
[[ "$(contains_count "$main_smoke_job" 'rustup default')" == 1 ]] || \
  die 'Xray-core main smoke does not have exactly one Rust selection'
[[ "$(exact_count "$main_smoke_job" '        run: rustup default 1.96.0')" == 1 ]] || \
  die 'Xray-core main smoke has an ambiguous Rust 1.96.0 selection'
main_revision_step="$(step_body "$main_smoke_job" 'Resolve Xray-core main revision')"
[[ -n "$main_revision_step" ]] || \
  die 'Xray-core main revision step is missing'
require_exact "$main_revision_step" '        id: xray' \
  'Xray-core main revision step does not expose id xray'
require_exact "$main_revision_step" \
  '          revision="$(git -C Xray-core rev-parse --verify HEAD)"' \
  'Xray-core main revision step does not resolve checkout HEAD'
require_exact "$main_revision_step" \
  '          if [[ ! "$revision" =~ ^[0-9a-f]{40}$ ]]; then' \
  'Xray-core main revision step does not validate a full lowercase SHA'
require_exact "$main_revision_step" \
  '          echo "revision=$revision" >>"$GITHUB_OUTPUT"' \
  'Xray-core main revision step does not publish its output'
summary_write='          printf '\''Xray-core main revision: `%s`\n'\'' "$revision" >>"$GITHUB_STEP_SUMMARY"'
active_main_revision_step="$(without_comments "$main_revision_step")"
require_exact "$active_main_revision_step" "$summary_write" \
  'Xray-core main summary does not append the validated revision'
[[ "$(grep -Fxc -- "$summary_write" <<<"$active_main_revision_step")" == 1 ]] || \
  die 'Xray-core main summary has an ambiguous validated revision write'
require_exact "$main_smoke_job" \
  '          XRAY_CORE_CHECKOUT: ${{ github.workspace }}/Xray-core' \
  'Xray-core main smoke does not pass the absolute Xray-core checkout'
require_exact "$main_smoke_job" \
  '          XRAY_CORE_EXPECTED_REVISION: ${{ steps.xray.outputs.revision }}' \
  'Xray-core main smoke does not pass its resolved revision to the test'
require_exact "$main_smoke_job" \
  '        run: bash scripts/check-xray-main-smoke.sh' \
  'Xray-core main smoke does not call its dedicated script'

active_main_smoke_job="$(without_comments "$main_smoke_job")"
failure_line="$(line_number_exact "$active_main_smoke_job" '        if: failure()')"
warning_command='        run: echo "::warning title=Xray-core main compatibility smoke failed::revision=${{ steps.xray.outputs.revision }} run=${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"'
warning_line="$(line_number_exact "$active_main_smoke_job" "$warning_command")"
last_job_line="$(awk 'NF { line = NR } END { print line }' <<<"$active_main_smoke_job")"
[[ "$failure_line" =~ ^[0-9]+$ && "$warning_line" =~ ^[0-9]+$ ]] || \
  die 'Xray-core main smoke warning step is missing'
(( failure_line + 1 == warning_line && warning_line == last_job_line )) || \
  die 'Xray-core main smoke does not end with the exact failure-only warning'

publish_needs="$(
  without_comments "$publish_job" |
  awk '
    /^    needs[[:space:]]*:/ {
      capture = 1
      print
      next
    }
    capture && /^      / {
      print
      next
    }
    capture { exit }
  '
)"
[[ -n "$publish_needs" ]] || \
  die 'prerelease publication dependencies are missing'
if grep -Fq 'scheduled-pinned-interop' <<<"$publish_needs"; then
  die 'scheduled pinned interoperability blocks prerelease publication'
fi
if grep -Fq 'xray-core-main-smoke' <<<"$publish_needs"; then
  die 'Xray-core main smoke blocks prerelease publication'
fi
if grep -Eq '[&*][[:alnum:]_-]+' <<<"$publish_needs"; then
  die 'prerelease publication dependencies use a YAML anchor or alias'
fi

require_exact "$rc_interop_job" "          ref: $PINNED_XRAY_REVISION" \
  'RC interoperability no longer pins the audited Xray-core commit'
require_exact "$rc_interop_job" '        run: bash scripts/check-rc-interop.sh' \
  'RC interoperability no longer calls its dedicated release script'
reject_text "$rc_interop_job" 'check-scheduled-pinned-interop.sh' \
  'RC interoperability calls the scheduled pinned script'
reject_text "$rc_interop_job" 'check-xray-main-smoke.sh' \
  'RC interoperability calls the upstream-main smoke script'

for script_test in \
  check-scheduled-pinned-interop.test.sh \
  check-xray-main-smoke.test.sh \
  check-scheduled-interop-workflow.test.sh; do
  require_exact "$rust_job" "          bash scripts/tests/$script_test" \
    "Rust CI job does not run $script_test"
done

echo 'scheduled interoperability workflow policy is isolated, pinned, and warning-safe'

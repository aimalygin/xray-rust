#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
WORKFLOW="$WORKSPACE_ROOT/.github/workflows/ci.yml"

die() {
  echo "$*" >&2
  exit 1
}

publish_job="$(
  awk '
    /^  publish-prerelease:/ { capture = 1 }
    capture { print }
  ' "$WORKFLOW"
)"

job_body() {
  local job="$1"
  awk -v header="  $job:" '
    $0 == header { capture = 1 }
    capture && $0 != header && /^  [A-Za-z0-9_-]+:/ { exit }
    capture { print }
  ' "$WORKFLOW"
}

require_text() {
  local text="$1"
  local message="$2"
  grep -Fq -- "$text" <<<"$publish_job" || die "$message"
}

require_text '--json isDraft,isPrerelease,name,body' \
  "prerelease retries do not validate draft/channel/title/notes state"
require_text 'refusing to mutate a non-prerelease GitHub release' \
  "prerelease retries do not reject stable GitHub releases"
require_text 'refusing to mutate a prerelease whose title or notes do not match' \
  "prerelease retries do not reject mismatched release metadata"
require_text 'refusing to mutate a release with unexpected asset' \
  "prerelease retries do not reject unexpected assets"
require_text 'cmp --silent' \
  "prerelease retries do not byte-compare existing assets"
require_text 'Published prerelease and both assets already match' \
  "published prerelease retries are not idempotent"
require_text 'gh release upload "$RELEASE_TAG"' \
  "draft prerelease retries cannot upload missing assets"
require_text '--draft=false' \
  "verified draft prereleases are not finalized"
require_text '--prerelease=true' \
  "finalized RC releases are not explicitly kept as prereleases"
require_text '--latest=false' \
  "RC releases can be promoted to latest"
require_text '- rc-interop' \
  "prerelease publication is not blocked on the RC interoperability job"
require_text '- fuzz-smoke' \
  "prerelease publication is not blocked on the fuzz-smoke job"
require_text 'verify_remote_tag() {' \
  "prerelease mutation does not define an exact remote-tag verifier"

line_number() {
  local text="$1"
  local occurrence="${2:-1}"
  awk -v needle="$text" -v occurrence="$occurrence" '
    index($0, needle) == 1 {
      seen++
      if (seen == occurrence) {
        print NR
        exit
      }
    }
  ' <<<"$publish_job"
}

line_number_exact() {
  local text="$1"
  local occurrence="${2:-1}"
  awk -v needle="$text" -v occurrence="$occurrence" '
    $0 == needle {
      seen++
      if (seen == occurrence) {
        print NR
        exit
      }
    }
  ' <<<"$publish_job"
}

create_verify_line="$(line_number_exact '            verify_remote_tag' 1)"
create_line="$(line_number '            gh release create "$RELEASE_TAG"')"
published_verify_line="$(line_number_exact '            verify_remote_tag' 2)"
published_exit_line="$(line_number '            echo "Published prerelease and both assets already match')"
archive_verify_line="$(line_number_exact '            verify_remote_tag' 3)"
archive_upload_line="$(line_number '            gh release upload "$RELEASE_TAG"' 1)"
checksums_verify_line="$(line_number_exact '            verify_remote_tag' 4)"
checksums_upload_line="$(line_number '            gh release upload "$RELEASE_TAG"' 2)"
finalize_verify_line="$(line_number_exact '          verify_remote_tag' 1)"
finalize_line="$(line_number '          gh release edit "$RELEASE_TAG"')"
post_finalize_verify_line="$(line_number_exact '          verify_remote_tag' 2)"
final_check_line="$(line_number '          final_json="$(')"

for line in \
  "$create_verify_line" "$create_line" \
  "$published_verify_line" "$published_exit_line" \
  "$archive_verify_line" "$archive_upload_line" \
  "$checksums_verify_line" "$checksums_upload_line" \
  "$finalize_verify_line" "$finalize_line" \
  "$post_finalize_verify_line" "$final_check_line"; do
  [[ "$line" =~ ^[0-9]+$ ]] || die "prerelease remote-tag verification ordering marker is missing"
done

(( create_verify_line < create_line )) || \
  die "remote tag is not verified immediately before prerelease creation"
(( published_verify_line < published_exit_line )) || \
  die "already-published prerelease retries do not reverify the remote tag"
(( archive_verify_line < archive_upload_line )) || \
  die "remote tag is not reverified before source archive upload"
(( checksums_verify_line < checksums_upload_line )) || \
  die "remote tag is not reverified before checksum upload"
(( finalize_verify_line < finalize_line )) || \
  die "remote tag is not reverified immediately before prerelease finalization"
(( finalize_line < post_finalize_verify_line && post_finalize_verify_line < final_check_line )) || \
  die "remote tag is not reverified after prerelease finalization"

rc_interop_job="$(job_body rc-interop)"
[[ -n "$rc_interop_job" ]] || die "RC interoperability job is missing"
grep -Fxq '          ref: 5ca6f4b7d4dc20a881d4330e498892697627ec0c' <<<"$rc_interop_job" || \
  die "RC interoperability does not pin the audited Xray-core commit"
grep -Fxq '        run: bash scripts/check-rc-interop.sh' <<<"$rc_interop_job" || \
  die "RC interoperability script is not part of the tag workflow"
grep -Fq 'bash scripts/tests/check-rc-interop.test.sh' "$WORKFLOW" || \
  die "clean-target RC interoperability regression test is not part of CI"
grep -Fq 'cargo +nightly-2026-05-22 install cargo-fuzz --version 0.13.2 --locked' "$WORKFLOW" || \
  die "RC fuzz gate does not pin cargo-fuzz"
grep -Fq 'cargo +nightly-2026-05-22 fuzz run ffi_lifecycle' "$WORKFLOW" || \
  die "RC fuzz gate omits the FFI lifecycle target"
grep -Fq 'cargo test --workspace --exclude xray-rust-fuzz --all-targets --locked' "$WORKFLOW" || \
  die "ordinary workspace tests can execute unbounded libFuzzer targets"

if grep -Fq -- '--clobber' <<<"$publish_job"; then
  die "prerelease retries can overwrite an existing asset"
fi

# Inspect exactly the jobs that gate or perform RC publication. Jobs outside
# this dependency closure may later implement a stable-only registry release
# without weakening the source-only RC path.
publish_needs=()
while IFS= read -r job; do
  publish_needs+=("$job")
done < <(
  awk '
    /^    needs:/ { in_needs = 1; next }
    in_needs && /^      - / {
      line = $0
      sub(/^      - /, "", line)
      print line
      next
    }
    in_needs { exit }
  ' <<<"$publish_job"
)

rc_path="$(job_body release-metadata)"
for job in "${publish_needs[@]}" publish-prerelease; do
  body="$(job_body "$job")"
  [[ -n "$body" ]] || die "missing RC publication dependency job: $job"
  rc_path+=$'\n'
  rc_path+="$body"
done

workflow_defaults="$(awk '/^jobs:/ { exit } { print }' "$WORKFLOW")"
rc_permission_scope="$workflow_defaults"$'\n'"$rc_path"
registry_write_permission_pattern="(permissions:[[:space:]]*['\"]?write-all|packages:[[:space:]]*['\"]?write['\"]?)"
if grep -Eq "$registry_write_permission_pattern" <<<"$rc_permission_scope"; then
  die "RC publication path grants package-registry write permission"
fi

registry_publish_pattern='(^|[;&|[:space:]])(cargo[[:space:]]+publish|npm[[:space:]]+publish|pnpm[[:space:]]+publish|yarn([[:space:]]+npm)?[[:space:]]+publish|mvn([^[:space:]]*[[:space:]]+)*deploy[^;&|[:space:]]*|([^[:space:]]*/)?gradlew?([^[:space:]]*[[:space:]]+)*publish[^;&|[:space:]]*|twine[[:space:]]+upload|gem[[:space:]]+push|pod[[:space:]]+trunk[[:space:]]+push|dotnet[[:space:]]+nuget[[:space:]]+push|nuget[[:space:]]+push|docker([^[:space:]]*[[:space:]]+)*(push|--push))([;&|[:space:]]|$)'
if grep -Eiq "$registry_publish_pattern" <<<"$rc_path"; then
  die "RC publication path can publish to a package registry"
fi

echo "verified idempotent source-only prerelease workflow policy"

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
require_text '- host-hardening' \
  "prerelease publication is not blocked on the host-hardening job"
require_text '- controlled-network' \
  "prerelease publication is not blocked on controlled-network evidence"
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
grep -Fxq '          ref: 676eaf66f8f05d4d558ee7a74b4736623d3feeb9' <<<"$rc_interop_job" || \
  die "RC interoperability does not pin the audited Xray-core commit"
grep -Fxq '        run: bash scripts/check-rc-interop.sh' <<<"$rc_interop_job" || \
  die "RC interoperability script is not part of the tag workflow"
grep -Fq 'bash scripts/tests/check-rc-interop.test.sh' "$WORKFLOW" || \
  die "clean-target RC interoperability regression test is not part of CI"
grep -Fq 'cargo +nightly-2026-05-22 install cargo-fuzz --version 0.13.2 --locked' "$WORKFLOW" || \
  die "RC fuzz gate does not pin cargo-fuzz"
grep -Fq 'bash scripts/run-v05-host-hardening.sh fuzz' "$WORKFLOW" || \
  die "RC fuzz gate does not run the extended hardening campaign"
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

# Execute the actual workflow classifier: a manual run (even on an RC tag)
# must run verification without acquiring publication privileges.
classifier="$(
  awk '
    /- name: Classify candidate/ { capture = 1; next }
    capture && /        run: \|/ { script = 1; next }
    script && /^          / { sub(/^          /, ""); print; next }
    script && /^      - name:/ { exit }
  ' "$WORKFLOW"
)"
[[ -n "$classifier" ]] || die "candidate classifier is missing"
classifier_output="$(mktemp)"
trap 'rm -f "$classifier_output"' EXIT

check_classification() {
  local event="$1" ref="$2" expected_rc="$3" expected_gates="$4" expected_bind="$5"
  : >"$classifier_output"
  (
    cd "$WORKSPACE_ROOT"
    export GITHUB_EVENT_NAME="$event" GITHUB_REF="$ref"
    export RELEASE_TAG="${ref#refs/*/}" GITHUB_OUTPUT="$classifier_output"
    bash -eu -o pipefail -c "$classifier"
  )
  grep -Fxq "is_rc=$expected_rc" "$classifier_output" || die "unsafe RC classification: $event $ref"
  grep -Fxq "run_release_gates=$expected_gates" "$classifier_output" || die "wrong candidate gates: $event $ref"
  grep -Fxq "bind_candidate_ci=$expected_bind" "$classifier_output" || die "wrong candidate binding: $event $ref"
  if [[ "$expected_rc" == false ]] && grep -q '^artifact_name=' "$classifier_output"; then
    die "verification-only candidate creates a publication artifact: $event $ref"
  fi
}

check_classification push refs/tags/v0.6.0-rc.1 true true false
check_classification push refs/tags/v0.9.1 false false true
check_classification push refs/tags/v0.10.0 false false true
check_classification push refs/heads/v0.6.0-rc.1 false false false
check_classification push refs/heads/main false false false
check_classification workflow_dispatch refs/heads/main false true false
check_classification workflow_dispatch refs/tags/v0.6.0-rc.1 false true false
check_classification workflow_dispatch refs/tags/v0.9.1 false true false
check_classification schedule refs/heads/main false false false
check_classification pull_request refs/pull/1/merge false false false

for job in rc-interop host-hardening fuzz-smoke controlled-network; do
  grep -Fxq "    if: needs.release-metadata.outputs.run_release_gates == 'true'" <<<"$(job_body "$job")" || \
    die "$job is not enabled for candidate verification"
done
for job in publish-prerelease; do
  grep -Fxq "    if: needs.release-metadata.outputs.is_rc == 'true'" <<<"$(job_body "$job")" || \
    die "$job is not restricted to RC tag publication"
done

grep -Fxq "    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')" <<<"$(job_body release-evidence)" || \
  die "a release tag is not gated on release evidence"
grep -Fq 'bash scripts/check-release-evidence.sh' <<<"$(job_body release-evidence)" || \
  die "release boundary does not revalidate candidate or promotion evidence"

# The release-evidence job finds its inputs by the profile the selector
# prints: the workflow file, the artifact and the archive inside it. A minor
# version whose profile has no such workflow would fail only at its tag.
evidence_job="$(job_body release-evidence)"
grep -Fq '/actions/workflows/$EVIDENCE_PROFILE-release-evidence.yml/runs' <<<"$evidence_job" || \
  die "release boundary does not look up the profile's evidence workflow"
grep -Fxq '            --name "$EVIDENCE_PROFILE-release-evidence-$CANDIDATE_COMMIT" \' <<<"$evidence_job" || \
  die "release boundary does not download the profile's evidence artifact"
grep -Fxq '          archive="$RUNNER_TEMP/release-evidence/$EVIDENCE_PROFILE-release-evidence.zip"' <<<"$evidence_job" || \
  die "release boundary does not revalidate the profile's evidence archive"
for release in 0.6.0:v06 0.7.0:v07 0.8.1:v08 0.9.0:v09 0.10.0:v010; do
  profile="$(bash "$WORKSPACE_ROOT/scripts/release-evidence-profile.sh" "v${release%%:*}")"
  [[ "$profile" == "${release##*:}" ]] || die "v${release%%:*} selects evidence profile $profile"
  evidence_workflow="$WORKSPACE_ROOT/.github/workflows/$profile-release-evidence.yml"
  [[ -f "$evidence_workflow" ]] || die "evidence profile $profile has no workflow"
  grep -Fxq "          name: $profile-release-evidence-\${{ github.sha }}" "$evidence_workflow" || \
    die "$profile evidence workflow does not publish the artifact a tag downloads"
  grep -Fxq "            \${{ runner.temp }}/$profile-release-evidence.zip" "$evidence_workflow" || \
    die "$profile evidence workflow does not keep the archive a tag revalidates"
  grep -Fq "scripts/check-$profile-release-evidence." "$evidence_workflow" || \
    die "$profile evidence workflow does not run its own policy"
  grep -Fq "  $profile) " "$WORKSPACE_ROOT/scripts/check-release-evidence.sh" || \
    die "release boundary has no policy for evidence profile $profile"
done

# A stable tag skips exactly the gates its candidate run proved, and only
# after its own history scan and evidence pass does it bind to that run.
stable_tag_skip="    if: github.event_name != 'push' || github.ref_type != 'tag' || contains(github.ref_name, '-rc.')"
for job in rust go-oracles apple android supply-chain; do
  grep -Fxq "$stable_tag_skip" <<<"$(job_body "$job")" || \
    die "$job does not run for every event except a stable tag push"
done
candidate_job="$(job_body candidate-ci)"
grep -Fxq "    if: needs.release-metadata.outputs.bind_candidate_ci == 'true'" <<<"$candidate_job" || \
  die "candidate binding is not restricted to stable tags"
for job in release-metadata release-evidence secrets; do
  grep -Fxq "      - $job" <<<"$candidate_job" || die "candidate binding does not wait for $job"
done
grep -Fq 'python3 scripts/verify-candidate-ci.py . "$RELEASE_TAG"' <<<"$candidate_job" || \
  die "candidate binding does not verify the candidate run"
grep -Fq 'name: source-tag-validation' <<<"$candidate_job" || \
  die "candidate binding does not retain its source verification record"
secrets_job="$(job_body secrets)"
grep -Fq -- '--log-opts="$log_opts"' <<<"$secrets_job" || die "secret scan scope is not selected per event"
grep -Fxq '          log_opts=--all' <<<"$secrets_job" || die "branch secret scan does not cover all branches"
grep -Fxq '            log_opts=HEAD' <<<"$secrets_job" || die "tag secret scan does not cover the tag ancestry"

echo "verified idempotent source-only prerelease workflow policy and candidate isolation"

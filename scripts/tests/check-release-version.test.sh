#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_UNDER_TEST="$WORKSPACE_ROOT/scripts/check-release-version.sh"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT

make_fixture() {
  local fixture="$1"
  local version="${2:-0.1.0}"
  mkdir -p "$fixture/scripts"
  cp "$SCRIPT_UNDER_TEST" "$fixture/scripts/check-release-version.sh"
  printf '%s\n' \
    '[workspace]' \
    '' \
    '[workspace.package]' \
    "version = \"$version\"" \
    >"$fixture/Cargo.toml"
  printf '%s\n' \
    '# Changelog' \
    '' \
    '## Unreleased' \
    '' \
    "## $version - 2026-08-02" \
    >"$fixture/CHANGELOG.md"
  git -C "$fixture" init -q
  git -C "$fixture" config user.email "release-test@example.invalid"
  git -C "$fixture" config user.name "Release Test"
  git -C "$fixture" add Cargo.toml CHANGELOG.md scripts/check-release-version.sh
  git -C "$fixture" commit -qm "test fixture"
  git -C "$fixture" tag -am "Release $version" "v$version"
}

expect_failure() {
  local expected="$1"
  shift
  local output
  if output="$("$@" 2>&1)"; then
    echo "expected command to fail: $*" >&2
    exit 1
  fi
  if [[ "$output" != *"$expected"* ]]; then
    echo "expected failure containing '$expected', got: $output" >&2
    exit 1
  fi
}

valid_fixture="$TEST_ROOT/valid"
make_fixture "$valid_fixture"
"$valid_fixture/scripts/check-release-version.sh" refs/tags/v0.1.0 >/dev/null
GITHUB_REF_NAME=v0.1.0 "$valid_fixture/scripts/check-release-version.sh" >/dev/null

prerelease_fixture="$TEST_ROOT/prerelease"
make_fixture "$prerelease_fixture" 0.4.1-rc.1
"$prerelease_fixture/scripts/check-release-version.sh" v0.4.1-rc.1 >/dev/null

expect_failure \
  "does not match workspace version" \
  "$valid_fixture/scripts/check-release-version.sh" v0.2.0

missing_changelog_fixture="$TEST_ROOT/missing-changelog"
make_fixture "$missing_changelog_fixture"
printf '%s\n' '# Changelog' '## Unreleased' >"$missing_changelog_fixture/CHANGELOG.md"
git -C "$missing_changelog_fixture" add CHANGELOG.md
git -C "$missing_changelog_fixture" commit -qm "remove release heading"
expect_failure \
  "has no dated section" \
  "$missing_changelog_fixture/scripts/check-release-version.sh" v0.1.0

dirty_fixture="$TEST_ROOT/dirty"
make_fixture "$dirty_fixture"
printf '%s\n' '# dirty' >>"$dirty_fixture/Cargo.toml"
expect_failure \
  "requires a clean Git worktree" \
  "$dirty_fixture/scripts/check-release-version.sh" v0.1.0

lightweight_fixture="$TEST_ROOT/lightweight"
make_fixture "$lightweight_fixture"
git -C "$lightweight_fixture" tag -d v0.1.0 >/dev/null
git -C "$lightweight_fixture" tag v0.1.0
expect_failure \
  "release tag must be annotated" \
  "$lightweight_fixture/scripts/check-release-version.sh" v0.1.0

missing_tag_fixture="$TEST_ROOT/missing-tag"
make_fixture "$missing_tag_fixture"
git -C "$missing_tag_fixture" tag -d v0.1.0 >/dev/null
expect_failure \
  "release tag does not exist" \
  "$missing_tag_fixture/scripts/check-release-version.sh" v0.1.0

wrong_commit_fixture="$TEST_ROOT/wrong-commit"
make_fixture "$wrong_commit_fixture"
printf '%s\n' '# unrelated committed file' >"$wrong_commit_fixture/extra.txt"
git -C "$wrong_commit_fixture" add extra.txt
git -C "$wrong_commit_fixture" commit -qm "advance fixture head"
expect_failure \
  "does not point at the checked-out commit" \
  "$wrong_commit_fixture/scripts/check-release-version.sh" v0.1.0

echo "release version checks passed"

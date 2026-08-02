#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="${1:-${GITHUB_REF_NAME:-}}"

if [[ "$TAG" == refs/tags/* ]]; then
  TAG="${TAG#refs/tags/}"
fi

if [[ -z "$TAG" ]]; then
  echo "usage: $0 <release-tag>" >&2
  exit 1
fi

VERSION="$({
  awk '
    $0 == "[workspace.package]" {
      in_workspace_package = 1
      next
    }
    /^\[/ {
      in_workspace_package = 0
    }
    in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
      line = $0
      sub(/^[^=]*=[[:space:]]*"/, "", line)
      sub(/"[[:space:]]*$/, "", line)
      print line
      exit
    }
  ' "$WORKSPACE_ROOT/Cargo.toml"
} || true)"

if [[ -z "$VERSION" ]]; then
  echo "workspace.package.version is missing from Cargo.toml" >&2
  exit 1
fi

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "workspace package version is not valid SemVer: $VERSION" >&2
  exit 1
fi

EXPECTED_TAG="v$VERSION"
if [[ "$TAG" != "$EXPECTED_TAG" ]]; then
  echo "release tag $TAG does not match workspace version $VERSION; expected $EXPECTED_TAG" >&2
  exit 1
fi

VERSION_PATTERN="${VERSION//./\\.}"
VERSION_PATTERN="${VERSION_PATTERN//+/\\+}"
if ! grep -Eq "^## \\[$VERSION_PATTERN\\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$|^## $VERSION_PATTERN - [0-9]{4}-[0-9]{2}-[0-9]{2}$" \
  "$WORKSPACE_ROOT/CHANGELOG.md"; then
  echo "CHANGELOG.md has no dated section for $VERSION" >&2
  exit 1
fi

if [[ -n "$(git -C "$WORKSPACE_ROOT" status --porcelain --untracked-files=normal)" ]]; then
  echo "release verification requires a clean Git worktree" >&2
  exit 1
fi

echo "verified release tag $TAG for workspace version $VERSION"

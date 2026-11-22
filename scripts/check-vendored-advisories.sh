#!/usr/bin/env bash
# Checks the upstream release under each vendored crate against the RustSec
# advisory database.
#
# `cargo audit` reads Cargo.lock, where the crates in vendor/ are path
# dependencies without a registry source and a fork is a git source, so it
# never matches an advisory against them. This script writes a lockfile that
# lists each of them as the crates.io release it was taken from, audits that,
# and fails on any advisory the vendored copy does not carry a fix for. A
# backported fix is acknowledged below with the vendored directory, the
# advisory and the upstream change; rebasing a crate onto a fixed release
# makes the acknowledgement stale, which the script reports so it can be
# removed.
#
# Usage: scripts/check-vendored-advisories.sh [extra cargo-audit options]
#   e.g. --no-fetch to reuse the local advisory database offline.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/xray-vendor-advisories.XXXXXX")"
trap 'rm -rf "$temporary"' EXIT

# <vendored directory> <advisory> <the upstream fix the copy carries>, one per
# line, for example:
#   vendor/shaped-rustls RUSTSEC-2026-0348 rustls 1aa987af, b10cdb0d (0.23.46): strict brotli
# None at present: the rustls fork carried four until it took rustls 0.23.46.
readonly ACKNOWLEDGED='
'

if ! cargo audit --version >/dev/null 2>&1; then
  echo 'cargo-audit is required: cargo install cargo-audit --locked' >&2
  exit 2
fi

# The vendored manifests are crates.io-normalized (or, for git sources,
# expanded) and keep upstream's package name and version.
lockfile="$temporary/Cargo.lock"
printf '# Upstream releases of vendored and git dependencies, for cargo audit only.\nversion = 4\n' >"$lockfile"
for manifest in "$ROOT"/vendor/*/Cargo.toml; do
  read -r name version < <(
    awk '
      /^\[package\]/ { in_package = 1; next }
      /^\[/ { in_package = 0 }
      in_package && $1 == "name" { gsub(/"/, "", $3); name = $3 }
      in_package && $1 == "version" { gsub(/"/, "", $3); version = $3 }
      END { print name, version }
    ' "$manifest"
  )
  if [[ -z "$name" || -z "$version" ]]; then
    echo "cannot read the package name and version of $manifest" >&2
    exit 1
  fi
  # The workspace must build this copy, not a registry release of it.
  if ! awk -v name="$name" -v version="$version" '
      /^\[\[package\]\]/ { if (n == name && v == version && !s) found = 1; n = v = ""; s = 0 }
      $1 == "name" { gsub(/"/, "", $3); n = $3 }
      $1 == "version" { gsub(/"/, "", $3); v = $3 }
      $1 == "source" { s = 1 }
      END { if (n == name && v == version && !s) found = 1; exit !found }
    ' "$ROOT/Cargo.lock"; then
    echo "Cargo.lock has no path package $name $version for $manifest" >&2
    exit 1
  fi
  printf '\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' \
    "$name" "$version" >>"$lockfile"
  directory="${manifest%/Cargo.toml}"
  echo "${directory#"$ROOT"/} = $name $version" >>"$temporary/crates"
done
# A git dependency is invisible to cargo audit in the same way.
awk '
  /^\[\[package\]\]/ { n = v = "" }
  $1 == "name" { gsub(/"/, "", $3); n = $3 }
  $1 == "version" { gsub(/"/, "", $3); v = $3 }
  $1 == "source" && $3 ~ /^"git\+/ { gsub(/"/, "", $3); print n, v, $3 }
' "$ROOT/Cargo.lock" | while read -r name version source; do
  printf '\n[[package]]\nname = "%s"\nversion = "%s"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n' \
    "$name" "$version" >>"$lockfile"
  echo "$source = $name $version" >>"$temporary/crates"
done
cat "$temporary/crates"

# cargo audit exits non-zero when it finds something; the JSON report decides.
cargo audit --file "$lockfile" --json "$@" >"$temporary/report.json" || true

python3 -I - "$temporary/report.json" "$temporary/crates" "$ACKNOWLEDGED" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as report_file:
    try:
        report = json.load(report_file)
    except json.JSONDecodeError:
        sys.exit("cargo audit produced no report")

# "<origin> = <name> <version>", one per audited package
origins = {}
with open(sys.argv[2], encoding="utf-8") as crates_file:
    for line in crates_file:
        origin, package = line.rstrip("\n").split(" = ")
        origins[tuple(package.split())] = origin

acknowledged = {}
for line in sys.argv[3].strip().splitlines():
    origin, advisory, reason = line.split(maxsplit=2)
    acknowledged[(origin, advisory)] = reason

findings = []
for vulnerability in report["vulnerabilities"]["list"]:
    findings.append((vulnerability["package"], vulnerability["advisory"]))
for kind, warnings in report.get("warnings", {}).items():
    for warning in warnings:
        advisory = warning.get("advisory") or {"id": kind, "title": kind}
        findings.append((warning["package"], advisory))

unfixed = []
seen = set()
for package, advisory in findings:
    origin = origins.get((package["name"], package["version"]), "Cargo.lock")
    key = (origin, advisory["id"])
    seen.add(key)
    label = (
        f'{origin} ({package["name"]} {package["version"]}): '
        f'{advisory["id"]} {advisory.get("title", "")}'
    )
    if key in acknowledged:
        print(f"backported  {label}\n            {acknowledged[key]}")
    else:
        unfixed.append(label)

for key, reason in acknowledged.items():
    if key not in seen:
        print(f"stale acknowledgement: {key[0]} {key[1]} no longer matches; remove it ({reason})")

if unfixed:
    print("\nadvisories against vendored or git dependencies without a vendored fix:", file=sys.stderr)
    for label in unfixed:
        print(f"  {label}", file=sys.stderr)
    print(
        "Rebase the crate onto a fixed release, or backport the fix and acknowledge it in "
        "scripts/check-vendored-advisories.sh.",
        file=sys.stderr,
    )
    sys.exit(1)
print("no unfixed advisories against vendored or git dependencies")
PY

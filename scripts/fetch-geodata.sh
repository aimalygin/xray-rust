#!/usr/bin/env bash
set -euo pipefail

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEFAULT_OUTPUT_DIR="$WORKSPACE_ROOT/platform/apple/XrayClient/dat"

# Keep these URLs immutable. Updating either tag also requires updating the
# corresponding SHA-256 digest and THIRD_PARTY_NOTICES.md.
GEOIP_VERSION="202607171233"
GEOIP_SHA256="b71d1999439dde2de2d2b6844a2befa50c50211ff739785c005ca7c230a17d6a"
GEOIP_URL="https://github.com/v2fly/geoip/releases/download/$GEOIP_VERSION/geoip.dat"
GEOIP_MAX_BYTES=67108864

GEOSITE_VERSION="20260727084448"
GEOSITE_SHA256="d6787cf3d08b86402640e8c2a7a18c8d64b31944ffa5274d8a6e154c8f3ddc07"
GEOSITE_URL="https://github.com/v2fly/domain-list-community/releases/download/$GEOSITE_VERSION/dlc.dat"
GEOSITE_MAX_BYTES=16777216

OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"
GEOIP_TEMP=""
GEOSITE_TEMP=""

usage() {
  cat <<EOF
Usage: scripts/fetch-geodata.sh [--output-dir DIR]

Download pinned, checksum-verified V2Fly routing data.

Options:
  --output-dir DIR  Install into DIR instead of:
                    $DEFAULT_OUTPUT_DIR
  -h, --help        Show this help.
EOF
}

fail() {
  echo "fetch-geodata: $*" >&2
  exit 1
}

cleanup() {
  if [[ -n "$GEOIP_TEMP" ]]; then
    rm -f -- "$GEOIP_TEMP"
  fi
  if [[ -n "$GEOSITE_TEMP" ]]; then
    rm -f -- "$GEOSITE_TEMP"
  fi
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required command: $1"
}

reject_symlink_components() {
  local path="$1"
  local current="/"
  local component
  local components=()

  if [[ "$path" != /* ]]; then
    path="$PWD/$path"
  fi

  IFS="/" read -r -a components <<<"$path"
  for component in "${components[@]}"; do
    case "$component" in
      ""|.)
        continue
        ;;
      ..)
        fail "output path must not contain '..': $OUTPUT_DIR"
        ;;
    esac

    current="${current%/}/$component"
    if [[ -L "$current" ]]; then
      fail "output path contains a symbolic link: $current"
    fi
  done
}

validate_output_dir() {
  [[ -n "$OUTPUT_DIR" ]] || fail "output directory must not be empty"
  if [[ "$OUTPUT_DIR" == *$'\n'* || "$OUTPUT_DIR" == *$'\r'* ]]; then
    fail "output directory must not contain line breaks"
  fi

  reject_symlink_components "$OUTPUT_DIR"
  mkdir -p -- "$OUTPUT_DIR"
  reject_symlink_components "$OUTPUT_DIR"

  OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd -P)"
  [[ "$OUTPUT_DIR" != "/" ]] || fail "refusing to install geodata into filesystem root"
  [[ -w "$OUTPUT_DIR" ]] || fail "output directory is not writable: $OUTPUT_DIR"

  local destination
  for destination in "$OUTPUT_DIR/geoip.dat" "$OUTPUT_DIR/geosite.dat"; do
    if [[ -L "$destination" ]]; then
      fail "refusing to replace symbolic link: $destination"
    fi
    if [[ -e "$destination" && ! -f "$destination" ]]; then
      fail "refusing to replace non-regular file: $destination"
    fi
  done
}

sha256_file() {
  local path="$1"
  local digest
  local unused

  if command -v shasum >/dev/null 2>&1; then
    read -r digest unused < <(shasum -a 256 "$path")
  elif command -v sha256sum >/dev/null 2>&1; then
    read -r digest unused < <(sha256sum "$path")
  else
    fail "missing SHA-256 tool: install shasum or sha256sum"
  fi

  printf '%s\n' "$digest"
}

verify_file() {
  local path="$1"
  local expected_sha256="$2"
  local max_bytes="$3"
  local label="$4"
  local actual_bytes
  local actual_sha256

  actual_bytes="$(wc -c <"$path" | tr -d '[:space:]')"
  [[ "$actual_bytes" =~ ^[0-9]+$ ]] || fail "could not determine size of $label"
  if ((actual_bytes == 0 || actual_bytes > max_bytes)); then
    fail "$label has unsafe size: $actual_bytes bytes"
  fi

  actual_sha256="$(sha256_file "$path")"
  if [[ "$actual_sha256" != "$expected_sha256" ]]; then
    fail "$label checksum mismatch (expected $expected_sha256, got $actual_sha256)"
  fi
}

download_file() {
  local url="$1"
  local destination="$2"
  local max_bytes="$3"

  curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --proto '=https' \
    --tlsv1.2 \
    --retry 3 \
    --retry-delay 1 \
    --connect-timeout 20 \
    --max-time 300 \
    --max-filesize "$max_bytes" \
    --output "$destination" \
    "$url"
}

parse_args() {
  while (($# > 0)); do
    case "$1" in
      --output-dir)
        (($# >= 2)) || fail "--output-dir requires a directory"
        OUTPUT_DIR="$2"
        shift 2
        ;;
      --output-dir=*)
        OUTPUT_DIR="${1#*=}"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        fail "unknown argument: $1"
        ;;
    esac
  done
}

main() {
  parse_args "$@"
  require_command curl
  require_command mktemp
  require_command mv
  require_command chmod
  require_command wc
  require_command tr
  validate_output_dir

  trap cleanup EXIT HUP INT TERM
  GEOIP_TEMP="$(mktemp "$OUTPUT_DIR/.geoip.dat.download.XXXXXX")"
  GEOSITE_TEMP="$(mktemp "$OUTPUT_DIR/.geosite.dat.download.XXXXXX")"

  echo "Downloading geoip.dat (V2Fly geoip $GEOIP_VERSION)..."
  download_file "$GEOIP_URL" "$GEOIP_TEMP" "$GEOIP_MAX_BYTES"
  verify_file "$GEOIP_TEMP" "$GEOIP_SHA256" "$GEOIP_MAX_BYTES" "geoip.dat"

  echo "Downloading geosite.dat (V2Fly domain-list-community $GEOSITE_VERSION)..."
  download_file "$GEOSITE_URL" "$GEOSITE_TEMP" "$GEOSITE_MAX_BYTES"
  verify_file "$GEOSITE_TEMP" "$GEOSITE_SHA256" "$GEOSITE_MAX_BYTES" "geosite.dat"

  chmod 0644 "$GEOIP_TEMP" "$GEOSITE_TEMP"

  # Both downloads are validated before either destination is changed. Each
  # rename is atomic because its temporary file lives in the destination dir.
  mv -f -- "$GEOIP_TEMP" "$OUTPUT_DIR/geoip.dat"
  GEOIP_TEMP=""
  mv -f -- "$GEOSITE_TEMP" "$OUTPUT_DIR/geosite.dat"
  GEOSITE_TEMP=""

  echo "Installed verified geodata into $OUTPUT_DIR"
}

main "$@"

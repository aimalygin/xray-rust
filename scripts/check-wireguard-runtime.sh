#!/usr/bin/env bash
set -euo pipefail
# The runtime guard also verifies the adopted engine and its bounded IP adapter.
exec bash "$(dirname "${BASH_SOURCE[0]}")/check-wireguard-adapter-prototype.sh" "$@"

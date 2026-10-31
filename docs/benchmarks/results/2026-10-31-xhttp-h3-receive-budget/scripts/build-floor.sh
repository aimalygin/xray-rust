#!/bin/bash
set -euo pipefail
/runs/build-ab.sh floor
sha256sum /target/bin/xray-rust-rb-floor

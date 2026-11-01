#!/bin/bash
set -euo pipefail
/runs/build-ab.sh timed
sha256sum /target/bin/xray-rust-rb-timed

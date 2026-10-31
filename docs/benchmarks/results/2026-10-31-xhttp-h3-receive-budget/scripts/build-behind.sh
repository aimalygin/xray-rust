#!/bin/bash
# Builds the third variant and names the first A/B's "after" binary "cap".
set -euo pipefail
/runs/build-ab.sh behind
cp /target/bin/xray-rust-rb-after /target/bin/xray-rust-rb-cap
sha256sum /target/bin/xray-rust-rb-before /target/bin/xray-rust-rb-cap /target/bin/xray-rust-rb-behind

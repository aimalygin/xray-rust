#!/bin/bash
# build-ab.sh <variant>: release build of xray-rust from /ab/<variant> (a git
# archive export) into its own new target dir /target/rb-<variant>.
set -euo pipefail
v=$1
test ! -e /target/rb-$v || { echo "target dir /target/rb-$v exists"; exit 1; }
cp -a /ab/$v /tmp/src-$v
cd /tmp/src-$v
CARGO_TARGET_DIR=/target/rb-$v cargo build --locked --offline --release -p xray-cli --bin xray-rust 2>&1 | tail -1
cp /target/rb-$v/release/xray-rust /target/bin/xray-rust-rb-$v
sha256sum /target/bin/xray-rust-rb-$v

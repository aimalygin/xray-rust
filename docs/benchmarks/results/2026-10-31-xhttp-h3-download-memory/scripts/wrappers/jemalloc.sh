#!/bin/sh
LD_PRELOAD=/usr/lib/aarch64-linux-gnu/libjemalloc.so.2 exec /target/bin/xray-rust-after "$@"

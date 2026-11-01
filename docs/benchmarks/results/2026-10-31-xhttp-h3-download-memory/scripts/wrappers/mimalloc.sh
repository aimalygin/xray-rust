#!/bin/sh
LD_PRELOAD=/usr/lib/aarch64-linux-gnu/libmimalloc.so.2 exec /target/bin/xray-rust-after "$@"

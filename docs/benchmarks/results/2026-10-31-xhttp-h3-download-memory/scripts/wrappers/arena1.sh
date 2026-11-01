#!/bin/sh
MALLOC_ARENA_MAX=1 exec /target/bin/xray-rust-after "$@"

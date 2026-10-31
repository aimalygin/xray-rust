#!/bin/sh
MALLOC_ARENA_MAX=4 exec /target/bin/xray-rust-after "$@"

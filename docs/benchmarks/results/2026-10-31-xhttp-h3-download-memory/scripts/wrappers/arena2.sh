#!/bin/sh
MALLOC_ARENA_MAX=2 exec /target/bin/xray-rust-after "$@"

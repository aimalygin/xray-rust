#!/bin/sh
GLIBC_TUNABLES=glibc.malloc.mmap_threshold=131072:glibc.malloc.trim_threshold=131072 exec /target/bin/xray-rust-after "$@"

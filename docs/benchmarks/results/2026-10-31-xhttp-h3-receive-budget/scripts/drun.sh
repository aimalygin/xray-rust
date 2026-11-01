#!/bin/bash
# drun.sh <cmd...>: runs a command in the bench image with the bench mounts.
SP=/private/tmp/claude-501/-Users-antonmalygin-xray-rust--claude-worktrees-beautiful-dijkstra-bf07ae/9f34f254-3a4d-41c5-94d6-78e2c4a31a68/scratchpad
exec docker run --rm -v xray-h3-target:/target -v xray-h3-cargo-home:/cargo-home -e CARGO_HOME=/cargo-home \
  -v "$SP/linux/bin":/xbin -v "$SP/linux/runs":/runs -v "$SP/linux/ab":/ab "${DOCKER_EXTRA[@]}" xray-h3-bench:netem "$@"

#!/bin/bash
# The two helper binaries tools/shared/shared_fixture_v09.py runs (TOOLS/vless-keys and
# TOOLS/download-bridge-lan), built as scripts/run-v06-feature-benchmarks.py builds them:
# `go build -mod=readonly` inside the pinned Xray-core checkout, from the candidate's
# tools/vless-encryption-oracle and tools/xhttp-download-oracle. The candidate's bridge
# already listens on XRAY_FIXTURE_BIND, so 0.9.0's download-bridge-lan-bind.patch is not applied.
set -euo pipefail
O=<stand>
CANDIDATE=$O/candidate
XSRC=<release-dir-0100>/xray-core/src
test "$(git -C "$CANDIDATE" rev-parse 'HEAD^{tree}')" = d430ce5f1c106b48ba9ecc55a25455f0a201c50f
test "$(git -C "$XSRC" rev-parse HEAD)" = 676eaf66f8f05d4d558ee7a74b4736623d3feeb9
test -z "$(git -C "$XSRC" status --porcelain)"
export GOENV=off GOWORK=off GOCACHE=$HOME/Library/Caches/go-build GOMODCACHE=$HOME/go/pkg/mod
export GOPROXY=file://$HOME/go/pkg/mod/cache/download,https://proxy.golang.org
GO=$HOME/sdk/go1.27.3/bin/go
cd "$XSRC"
$GO build -mod=readonly -o $O/tools/shared/bin/vless-keys "$CANDIDATE/tools/vless-encryption-oracle/main.go"
$GO build -mod=readonly -o $O/tools/shared/bin/download-bridge-lan \
  "$CANDIDATE/tools/xhttp-download-oracle/main.go" "$CANDIDATE/tools/xhttp-download-oracle/bridge.go"
shasum -a 256 $O/tools/shared/bin/vless-keys $O/tools/shared/bin/download-bridge-lan

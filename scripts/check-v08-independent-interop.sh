#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
readonly TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "$TEST_ROOT"' EXIT
cd "$WORKSPACE_ROOT"

# Same source pin as the existing benchmark reference. Never update the
# module checkout or accept an arbitrary executable as independent evidence.
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off \
  go mod download -json github.com/sagernet/sing-box@v1.13.20 > "$TEST_ROOT/source.json"
readonly SOURCE_DIR="$(python3 - "$TEST_ROOT/source.json" <<'PY'
import json, sys
from pathlib import Path
source = json.loads(Path(sys.argv[1]).read_text())
assert source['Path'] == 'github.com/sagernet/sing-box'
assert source['Version'] == 'v1.13.20'
assert source['Sum'] == 'h1:2PfQuwVsV3rbvvOqoJOc1K2CY5xe5b9BL/TmIlGoCPE='
assert source['GoModSum'] == 'h1:QkfLSGwPZB5adT5zF6PL6bPKRBVkS4tCIVv/zbM9WHA='
assert source['Origin']['Hash'] == '56f91dfeabd6f4edbd437dfcc1e5b0ebc856b778'
print(source['Dir'])
PY
)"
env -u GOFLAGS -u GOEXPERIMENT GOENV=off GOWORK=off CGO_ENABLED=0 \
  go -C "$SOURCE_DIR" build -mod=readonly -trimpath -o "$TEST_ROOT/sing-box" ./cmd/sing-box
mkdir -p target/v08-independent
python3 - "$TEST_ROOT" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
root = Path(sys.argv[1])
source = json.loads((root / 'source.json').read_text())
evidence = {key: source[key] for key in ('Path', 'Version', 'Sum', 'GoModSum', 'Origin')}
evidence['binary_sha256'] = hashlib.sha256((root / 'sing-box').read_bytes()).hexdigest()
evidence['build_info'] = subprocess.check_output(['go', 'version', '-m', str(root / 'sing-box')], text=True)
Path('target/v08-independent/reference.json').write_text(json.dumps(evidence, indent=2) + '\n')
PY
export XRAY_CLIENT_PROTOCOL_BINARY="$TEST_ROOT/sing-box"
export XRAY_CLIENT_PROTOCOL_REFERENCE=sing-box
cargo test --locked -p xray-core-rs \
  --test trojan_runtime_tests --test shadowsocks_runtime_tests --test vmess_runtime_tests \
  -- --ignored --nocapture
for protocol in trojan shadowsocks vmess; do
  cargo test --locked -p xray-core-rs --test runtime_data_path_tests \
    "${protocol}_runtime_tun_" -- --ignored --nocapture
done
cargo test --locked -p xray-core-rs --test mux_runtime_tests \
  mux_runtime_ipv6_and_domain_datagrams -- --ignored --nocapture

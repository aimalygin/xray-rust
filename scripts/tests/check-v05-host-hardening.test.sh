#!/usr/bin/env bash
set -euo pipefail

readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
readonly WORKFLOW="$WORKSPACE_ROOT/.github/workflows/ci.yml"
readonly HARDENING="$WORKSPACE_ROOT/scripts/run-v05-host-hardening.sh"
readonly NETEM="$WORKSPACE_ROOT/scripts/run-v05-controlled-network.sh"

die() {
  echo "$*" >&2
  exit 1
}

for target in \
  config_json dns_wire vless_wire inbound_wire quic_sniff xhttp_framing tun_queue ffi_lifecycle; do
  grep -Fq "name = \"$target\"" "$WORKSPACE_ROOT/fuzz/Cargo.toml" || \
    die "fuzz manifest omits $target"
  grep -Fq "fuzz run \"\$target\"" "$HARDENING" || \
    grep -Fq "    $target" "$HARDENING" || \
    die "extended fuzz campaign omits $target"
done

grep -Fq 'miri test --locked -p xray-routing --lib domain_matcher::tests' "$HARDENING" || \
  die 'host hardening omits Miri routing coverage'
grep -Fq -- '-Zsanitizer=address' "$HARDENING" || \
  die 'host hardening omits AddressSanitizer coverage'
grep -Fq 'routing_policy_concurrency_model' "$HARDENING" || \
  die 'host hardening omits the routing publication concurrency model'

grep -Fq '5ca6f4b7d4dc20a881d4330e498892697627ec0c' "$NETEM" || \
  die 'controlled-network gate does not pin Xray-core'
grep -Fq 'tc qdisc replace dev lo root netem' "$NETEM" || \
  die 'controlled-network gate does not install netem'
grep -Fq 'tc qdisc del dev lo root' "$NETEM" || \
  die 'controlled-network gate does not clean up netem'
grep -Fq 'requires a clean xray-rust checkout' "$NETEM" || \
  die 'controlled-network evidence is not bound to a clean candidate checkout'
for transport in ws httpupgrade grpc xhttp-h1 xhttp-h2 xhttp-h3; do
  grep -Fq "$transport" "$NETEM" || die "controlled-network gate omits $transport"
done
grep -Fq -- '--traffic held-open' "$NETEM" || \
  die 'controlled-network gate omits long-lived XHTTP sessions'

grep -Fq '  host-hardening:' "$WORKFLOW" || die 'host-hardening CI job is missing'
grep -Fq '  controlled-network:' "$WORKFLOW" || die 'controlled-network CI job is missing'
grep -Fq '      - host-hardening' "$WORKFLOW" || \
  die 'RC publication does not depend on host hardening'
grep -Fq '      - controlled-network' "$WORKFLOW" || \
  die 'RC publication does not depend on controlled-network evidence'

echo 'verified v0.5 host hardening and controlled-network RC gates'

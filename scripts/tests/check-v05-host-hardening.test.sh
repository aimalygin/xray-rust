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
  config_json dns_wire vless_wire inbound_wire quic_sniff xhttp_framing tun_queue vless_encryption_records vless_encryption_handshake ffi_lifecycle; do
  grep -Fq "name = \"$target\"" "$WORKSPACE_ROOT/fuzz/Cargo.toml" || \
    die "fuzz manifest omits $target"
  grep -Fq "    $target" "$HARDENING" || \
    die "extended fuzz campaign omits $target"
done

grep -Fq 'CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_STRIP=none' "$HARDENING" || \
  die 'fuzz campaign must preserve dependency coverage and crash symbols'

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

test_root="$(mktemp -d)"
trap 'rm -rf -- "$test_root"' EXIT
mkdir -p "$test_root/bin"
cat >"$test_root/bin/cargo" <<'SH'
#!/usr/bin/env bash
for argument in "$@"; do
  if [[ "$argument" == -artifact_prefix=* ]]; then
    printf 'synthetic reproducer\n' >"${argument#-artifact_prefix=}crash-test"
    exit 17
  fi
done
exit 99
SH
chmod +x "$test_root/bin/cargo"
set +e
PATH="$test_root/bin:$PATH" XRAY_FUZZ_EVIDENCE_DIR="$test_root/evidence" \
  bash "$HARDENING" fuzz >"$test_root/output" 2>&1
status=$?
set -e
[[ "$status" == 17 ]] || die "fuzz wrapper lost the failing target's status"
reproducers=("$test_root"/evidence/xray-v05-fuzz.*/artifacts/config_json/crash-test)
[[ "${#reproducers[@]}" == 1 && -f "${reproducers[0]}" ]] || \
  die 'fuzz wrapper discarded the crash reproducer'
grep -Fq 'fuzz evidence retained at' "$test_root/output" || \
  die 'fuzz wrapper did not report the retained evidence'

echo 'verified v0.5 host hardening and controlled-network RC gates'

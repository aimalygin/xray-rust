#!/usr/bin/env bash
set -euo pipefail
# Run only inside a disposable Linux network namespace/container. CI uses
# sudo unshare --net; do not set this flag on an operator's normal network.
[[ $(uname -s) == Linux && $(id -u) == 0 && ${XRAY_TPROXY_ISOLATED_NETWORK:-} == 1 ]] || {
  echo 'Requires an isolated Linux network namespace, root, and XRAY_TPROXY_ISOLATED_NETWORK=1' >&2; exit 1;
}
readonly WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cleanup() {
  for tool in iptables ip6tables; do
    "$tool" -t mangle -D OUTPUT -j XRAY_TEST_OUT 2>/dev/null || true
    "$tool" -t mangle -D PREROUTING -j XRAY_TEST_PRE 2>/dev/null || true
    "$tool" -t mangle -F XRAY_TEST_OUT 2>/dev/null || true
    "$tool" -t mangle -F XRAY_TEST_PRE 2>/dev/null || true
    "$tool" -t mangle -X XRAY_TEST_OUT 2>/dev/null || true
    "$tool" -t mangle -X XRAY_TEST_PRE 2>/dev/null || true
  done
  ip rule del priority 10420 fwmark 0x420 table 10420 2>/dev/null || true
  ip -6 rule del priority 10420 fwmark 0x420 table 10420 2>/dev/null || true
  ip route del local default dev lo table 10420 2>/dev/null || true
  ip -6 route del local default dev lo table 10420 2>/dev/null || true
  ip -6 addr del fd42:7872:6179::2/128 dev lo 2>/dev/null || true
  ip -6 addr del fd42:7872:6179::3/128 dev lo 2>/dev/null || true
}
trap cleanup EXIT
ip link set lo up
ip -6 addr add fd42:7872:6179::2/128 dev lo nodad
ip -6 addr add fd42:7872:6179::3/128 dev lo nodad
ip rule add priority 10420 fwmark 0x420 table 10420
ip route add local default dev lo table 10420
ip -6 rule add priority 10420 fwmark 0x420 table 10420
ip -6 route add local default dev lo table 10420
for tool in iptables ip6tables; do
  "$tool" -t mangle -N XRAY_TEST_OUT
  "$tool" -t mangle -N XRAY_TEST_PRE
  "$tool" -t mangle -A OUTPUT -j XRAY_TEST_OUT
  "$tool" -t mangle -A PREROUTING -j XRAY_TEST_PRE
  for protocol in tcp udp; do
    "$tool" -t mangle -A XRAY_TEST_OUT -m owner --uid-owner 65534 -p "$protocol" --dport 18080 -j MARK --set-mark 0x420
    "$tool" -t mangle -A XRAY_TEST_PRE -m mark --mark 0x420 -p "$protocol" --dport 18080 -j TPROXY --on-port 15000 --tproxy-mark 0x420
  done
done
cd "$WORKSPACE_ROOT"
if [[ -n ${XRAY_TPROXY_TEST_BINARY:-} ]]; then
  "$XRAY_TPROXY_TEST_BINARY" --ignored --nocapture
else
  cargo test --locked -p xray-core-rs --test tproxy_tests -- --ignored --nocapture
fi

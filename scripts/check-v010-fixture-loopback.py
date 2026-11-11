#!/usr/bin/env python3
"""Host-only preflight of the v0.10 device fixtures before a phone is involved.

The checks of check-v09-fixture-loopback.py, for the v0.10 suites: each
generated client config runs in the candidate CLI with a local SOCKS ingress
instead of TUN, against the fixture's pinned Xray-core server on 127.0.0.1.
A case with ``settleSeconds`` waits that long first, as the device harnesses
do. The reverse bridge is the candidate CLI itself: its probe traffic enters
the portal, comes back down the tunnel and leaves through its own freedom.
The xicmp suite needs raw ICMP sockets for Xray-core's server: root, or Linux
with CAP_NET_RAW. This is not device evidence and never changes host routes.
"""
import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("fixture_loopback", ROOT / "scripts/check-v09-fixture-loopback.py")
loopback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loopback)

loopback.SUITES = {
    # suite: (fixture script, extra fixture arguments)
    "v010": ("run-v07-apple-protocol-fixture.py", ["--protocol", "v010"]),
    "smoke-v010": ("run-v07-apple-protocol-fixture.py", ["--protocol", "smoke-v010"]),
    "xicmp": ("run-v07-apple-protocol-fixture.py", ["--protocol", "xicmp"]),
}
loopback.WARMUP_SUITES = ()
loopback.KEPT = {"server.log", "xdrive-standin.log"}
# The datagrams the Apple probe sends, unless a case names smaller ones.
loopback.UDP_PAYLOADS = (1392, 1372)

if __name__ == "__main__":
    # --xdrive-standin <binary> goes on to the fixture, which otherwise builds one.
    if "--xdrive-standin" in sys.argv:
        at = sys.argv.index("--xdrive-standin")
        loopback.FIXTURE_ARGUMENTS = sys.argv[at:at + 2]
        del sys.argv[at:at + 2]
    sys.exit(loopback.main())

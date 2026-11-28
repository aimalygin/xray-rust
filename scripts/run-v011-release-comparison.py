#!/usr/bin/env python3
"""Measure every carrier 0.10.1 shipped on a build of the published v0.10.1
tag and on the candidate, in one run, and write the "release-comparison"
artifact of the v0.11 evidence profile.

The v0.10 collector (run-v010-release-comparison.py) with v0.11's policy:
the baseline is v0.10.1, and the fourteen carriers are 0.9.0's twelve legacy
protocols plus VLESS over mKCP and MASQUE over HTTP/3, each configured as
its device fixture configures it. mKCP and MASQUE run the carrier-paced work
of the v0.10 protocol comparison. Both clients and the driver are builds
made by build-isolated-release.py in one campaign directory: bin/baseline
(the v0.10.1 tag), bin/candidate and bin/harness.

The verdicts and budgets are the checker's (check-v011-release-evidence.py).
Only a complete run (every carrier, at least five repeats, the full work
size) writes the artifact; anything less writes a diagnostic document.
REALITY's decoy handshake needs www.google.com:443 reachable from this host.
"""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / filename)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


collector = module("collector", "run-v010-release-comparison.py")
policy = module("policy_v011", "check-v011-release-evidence.py")
legacy_server = collector.write_server
# The carriers v0.10 added, beside the twelve of the legacy fixture.
CARRIERS = ("mkcp", "masque")


def write_server(directory):
    """The legacy fixture's server and clients, with mKCP and MASQUE added on
    ports of their own, each carrier's keys in its own directory."""
    server, configs = legacy_server(directory)
    for carrier in CARRIERS:
        part = directory / carrier
        part.mkdir(mode=0o700)
        client, carrier_server = collector.comparison.carrier_configs(carrier, part, collector.bench.port())
        server["inbounds"].extend(carrier_server["inbounds"])
        configs[carrier] = {"outbounds": client["outbounds"]}
    return server, configs


collector.policy = policy
collector.PROTOCOLS = policy.COMPARISON_CARRIERS
collector.write_server = write_server
collector.EXTRA_FILES = [Path(__file__).resolve()]
collector.__doc__ = __doc__

if __name__ == "__main__":
    collector.main()

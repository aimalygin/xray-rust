"""Guard the v0.10 carrier comparison suite and the release-comparison collector."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


collector = module("release_comparison", "run-v010-release-comparison.py")
launcher = module("client", "v08-reference-client.py")
preparer = module("preparer", "prepare-v08-protocol-comparison.py")
comparison, policy = collector.comparison, collector.policy
OPENSSL = shutil.which("openssl")
REVISION, TREE = "a" * 40, "b" * 40
METRICS = ("throughput", "latency", "memory")


class CarrierSuiteTests(unittest.TestCase):
    def profile(self, name, directory):
        client, server = comparison.configs(name, directory, 12345)
        client["inbounds"] = [{"protocol": "socks", "listen": "127.0.0.1", "port": 23456}]
        return client, server

    def test_the_suite_yields_exactly_the_measurements_the_checker_adds_for_v010(self):
        groups = comparison.MEASUREMENT_GROUPS["v010"]
        produced = {f"{group}-{metric}" for group in groups for metric in METRICS}
        added = set(policy.POLICY.measurement_comparisons) - set(policy.COMMON.MEASUREMENT_COMPARISONS)
        self.assertEqual(produced, added)
        self.assertEqual(set(groups), policy.FULL_PROTOCOLS)
        self.assertEqual(sorted(p for profiles in groups.values() for p in profiles),
                         sorted(comparison.V010_PROFILES))

    def test_two_carriers_run_the_usual_axes_against_xray_alone(self):
        cases = comparison.cases(comparison.V010_PROFILES)
        self.assertEqual(len(cases), 20)
        self.assertEqual(len({c["id"] for c in cases}), 20)
        axes = lambda profile: {(c["traffic"], c["connections"], c["payload_size"]) for c in cases
                                if c["profile"] == profile}
        self.assertEqual(axes("mkcp-vless"), axes("masque-h3"))
        self.assertEqual(comparison.SUITE_CLIENTS["v010"], ("candidate", "xray"))
        for suite in ("v08", "v09"):
            self.assertEqual(comparison.SUITE_CLIENTS[suite], ("candidate", "xray", "singbox"))

    def test_carrier_paced_work_fits_the_drivers_two_minutes(self):
        def work(profile, smoke=False):
            sizes = {}
            for case in comparison.cases([profile], smoke):
                kind = "latency" if case["traffic"] in ("tcp-latency", "udp") else "bulk"
                sizes.setdefault(kind, set()).add(case["iterations"])
            return sizes
        self.assertEqual(work("trojan-tls"), {"bulk": {4096}, "latency": {1000}})
        self.assertEqual(work("mkcp-vless"), {"bulk": {512}, "latency": {200}})
        self.assertEqual(work("masque-h3"), {"bulk": {1024}, "latency": {1000}})
        # mKCP: 32 MiB a flow at a few MiB/s, 200 round trips near 100 ms each.
        self.assertLessEqual(comparison.CARRIER_WORK["mkcp"]["latency"] * 0.11, 30)
        for profile in ("trojan-tls", "mkcp-vless", "masque-h3"):
            self.assertEqual(work(profile, smoke=True), {"bulk": {4}, "latency": {10}})

    def test_mkcp_profile_is_plain_vless_at_default_capacities(self):
        with tempfile.TemporaryDirectory() as temp:
            client, server = self.profile("mkcp-vless", Path(temp))
            self.assertEqual(sorted(p.name for p in Path(temp).iterdir()), [])
        outbound, inbound = client["outbounds"][0], server["inbounds"][0]
        self.assertEqual((outbound["protocol"], outbound["streamSettings"]), ("vless", {"network": "kcp"}))
        self.assertEqual(inbound["streamSettings"], {"network": "kcp"})
        self.assertEqual((outbound["settings"]["address"], outbound["settings"]["port"], inbound["port"]),
                         ("127.0.0.1", 12345, 12345))
        self.assertEqual(inbound["settings"]["clients"], [{"id": outbound["settings"]["id"]}])
        self.assertEqual(launcher.translate(client, "xray", "", "v010"), (client, ["run", "-config"], "xray"))

    @unittest.skipUnless(OPENSSL, "openssl is required for the MASQUE certificate")
    def test_masque_profile_is_authenticated_and_pinned_to_the_fixture_certificate(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            client, server = self.profile("masque-h3", directory)
            der = subprocess.check_output(["openssl", "x509", "-in", str(directory / "tls.crt"), "-outform", "DER"])
            outbound, inbound = client["outbounds"][0], server["inbounds"][0]
            stream = outbound["streamSettings"]
            self.assertEqual((outbound["protocol"], stream["network"], stream["tlsSettings"]["alpn"]),
                             ("masque", "masque", ["h3"]))
            self.assertEqual(stream["tlsSettings"]["pinnedPeerCertSha256"], hashlib.sha256(der).hexdigest())
            self.assertEqual(inbound["settings"]["users"],
                             [{"email": stream["masqueSettings"]["user"], "pass": stream["masqueSettings"]["pass"]}])
            self.assertEqual(launcher.translate(client, "xray", directory / "tls.crt", "v010")[2], "xray")
            stream["tlsSettings"]["pinnedPeerCertSha256"] = "00" * 32
            with self.assertRaisesRegex(ValueError, "does not match"):
                launcher.translate(client, "xray", directory / "tls.crt", "v010")

    def test_singbox_and_altered_carrier_profiles_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            client, _ = self.profile("mkcp-vless", Path(temp))
            with self.assertRaisesRegex(ValueError, "neither mKCP nor MASQUE"):
                launcher.translate(client, "singbox", "", "v010")
            # The carrier belongs to its own suite, and the older suites keep theirs.
            with self.assertRaises(ValueError):
                launcher.translate(client, "xray", "", "v09")
            vmess, _ = self.profile("vmess-aes128", Path(temp))
            with self.assertRaises(ValueError):
                launcher.translate(vmess, "xray", "", "v010")
            for change in ("mask", "capacity", "flow", "tls", "mux", "address"):
                client, _ = self.profile("mkcp-vless", Path(temp))
                outbound = client["outbounds"][0]
                if change == "mask":
                    outbound["streamSettings"]["finalmask"] = {"udp": [{"type": "salamander"}]}
                elif change == "capacity":
                    outbound["streamSettings"]["kcpSettings"] = {"uplinkCapacity": 100}
                elif change == "flow":
                    outbound["settings"]["flow"] = "xtls-rprx-vision"
                elif change == "tls":
                    outbound["streamSettings"]["security"] = "tls"
                elif change == "mux":
                    outbound["mux"] = {"enabled": True}
                else:
                    outbound["settings"]["address"] = "192.0.2.1"
                with self.assertRaises(ValueError, msg=change):
                    launcher.translate(client, "xray", "", "v010")

    def test_preparer_takes_isolated_build_records_and_refuses_unclean_ones(self):
        record = {"commit": REVISION, "tree": TREE, "rustc": "rustc 1.96.0", "cargo": "cargo 1.96.0",
                  "command": "cargo build --locked --release -p xray-cli", "incremental": False,
                  "rustflags": None, "path": "/x", "sha256": "c" * 64, "isolated_target": True,
                  "lock_sha256": "d" * 64, "workspace_packages_compiled": ["crates/xray-cli"]}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "candidate.json"
            path.write_text(json.dumps(record))
            self.assertEqual(preparer.build_identity(path), {
                "commit": REVISION, "tree": TREE, "rustc": "rustc 1.96.0", "incremental": False,
                "build_arguments": record["command"], "sha256": "c" * 64})
            for field, value in (("rustflags", "-C target-cpu=native"), ("incremental", True),
                                 ("isolated_target", False)):
                path.write_text(json.dumps({**record, field: value}))
                with self.assertRaisesRegex(ValueError, "not a clean isolated build"):
                    preparer.build_identity(path)
            # A record of the older single-build kind is taken as it is.
            older = {"commit": REVISION, "tree": TREE, "rustc": "r", "build_arguments": "b",
                     "incremental": False, "sha256": "e" * 64}
            path.write_text(json.dumps(older))
            self.assertEqual(preparer.build_identity(path), older)


def measured(**scaled):
    """Five steady samples a side; ``vmess_throughput=0.8`` scales one candidate."""
    base = {"throughput": [100.0, 101.0, 99.0, 100.0, 102.0], "latency": [500.0, 510.0, 495.0, 505.0, 500.0],
            "memory": [20.0, 20.5, 19.5, 20.0, 20.2]}
    return {protocol: {metric: {"baseline": list(values),
                                "candidate": [v * scaled.get(f"{protocol}_{metric}".replace("-", "_"), 1.0)
                                              for v in values]}
                       for metric, values in base.items()}
            for protocol in policy.LEGACY_PROTOCOLS}


def encoded(document):
    return (json.dumps(document, indent=2) + "\n").encode()


class ReleaseComparisonTests(unittest.TestCase):
    def test_writer_output_passes_the_checker(self):
        document = collector.release_comparison(measured(), REVISION, TREE)
        policy.validate_release_comparison(encoded(document), REVISION, TREE, b"")
        self.assertEqual(document["baseline"], policy.BASELINE)
        self.assertEqual(document["candidate"], {"revision": REVISION, "tree": TREE})
        self.assertEqual({row["id"] for row in document["measurements"]}, policy.COMPARISON_MEASUREMENTS)
        self.assertEqual(len(document["measurements"]), 36)
        self.assertEqual({row["verdict"] for row in document["measurements"]}, {"within-budget"})
        self.assertEqual(collector.regressions(document), [])
        self.assertLess(len(encoded(document)), policy.MAX_COMPARISON_BYTES)
        # Another candidate's document does not pass for this one.
        with self.assertRaisesRegex(policy.COMMON.ValidationError, "candidate does not match"):
            policy.validate_release_comparison(encoded(document), "c" * 40, TREE, b"")

    def test_a_slower_candidate_is_a_regression_the_release_must_name(self):
        document = collector.release_comparison(
            measured(vmess_throughput=0.8, xhttp_h3_latency=1.2, wireguard_memory=1.2), REVISION, TREE)
        verdicts = {row["id"]: row["verdict"] for row in document["measurements"]}
        slower = ["vmess-throughput", "wireguard-memory", "xhttp-h3-latency"]
        self.assertEqual(sorted(collector.regressions(document)), slower)
        self.assertEqual({name for name, verdict in verdicts.items() if verdict == "regression"}, set(slower))
        with self.assertRaisesRegex(policy.COMMON.ValidationError, "does not name the regression"):
            policy.validate_release_comparison(encoded(document), REVISION, TREE, b"")
        policy.validate_release_comparison(encoded(document), REVISION, TREE, " ".join(slower).encode())
        # A faster, leaner candidate is not a regression in any direction.
        better = collector.release_comparison(
            measured(vmess_throughput=1.5, xhttp_h3_latency=0.5, wireguard_memory=0.5), REVISION, TREE)
        self.assertEqual(collector.regressions(better), [])

    def test_budgets_are_the_checkers_and_not_a_copy(self):
        near = measured(vmess_throughput=0.95, vmess_latency=1.05, vmess_memory=1.05)
        self.assertEqual(collector.regressions(collector.release_comparison(near, REVISION, TREE)), [])
        with patch.dict(policy.COMPARISON_BUDGETS, {"throughput": ("at-least", 99), "latency": ("at-most", 101),
                                                    "memory": ("at-most", 101)}):
            tightened = collector.release_comparison(near, REVISION, TREE)
            self.assertEqual(collector.regressions(tightened),
                             ["vmess-throughput", "vmess-latency", "vmess-memory"])
            policy.validate_release_comparison(encoded(tightened), REVISION, TREE, b"vmess-throughput vmess-latency vmess-memory")

    def test_samples_are_bulk_throughput_latency_p95_and_the_larger_peak_memory(self):
        results = {}
        for repeat in (1, 2):
            for version, scale in (("baseline", 1), ("candidate", 2)):
                results[("trojan-full-duplex", version, repeat)] = {
                    "throughput_mib_s": 100.0 * scale + repeat, "latency_us": None, "peak_rss_kib": 2048 * scale}
                results[("trojan-tcp-latency", version, repeat)] = {
                    "throughput_mib_s": 1.0, "latency_us": {"p50": 1.0, "p95": 300.0 * scale + repeat},
                    "peak_rss_kib": 4096 * scale}
        self.assertEqual(collector.samples(results, ["trojan"], (1, 2)), {"trojan": {
            "throughput": {"baseline": [101.0, 102.0], "candidate": [201.0, 202.0]},
            "latency": {"baseline": [301.0, 302.0], "candidate": [601.0, 602.0]},
            "memory": {"baseline": [4.0, 4.0], "candidate": [8.0, 8.0]}}})

    def test_only_a_complete_run_writes_the_artifact(self):
        run = {"smoke": False, "repeats": 5, "protocols": sorted(policy.LEGACY_PROTOCOLS)}
        self.assertTrue(collector.complete(run))
        self.assertTrue(collector.complete({**run, "repeats": 7}))
        for change in ({"smoke": True}, {"repeats": 4}, {"protocols": ["trojan", "vmess"]}):
            self.assertFalse(collector.complete({**run, **change}), change)
        self.assertNotEqual(collector.ARTIFACT, collector.DIAGNOSTIC)

    def test_every_legacy_protocol_runs_one_flow_of_each_workload(self):
        cases = collector.cases(sorted(policy.LEGACY_PROTOCOLS))
        self.assertEqual(len(cases), 24)
        self.assertEqual({c["protocol"] for c in cases}, policy.LEGACY_PROTOCOLS)
        self.assertEqual({(c["traffic"], c["connections"], c["path"]) for c in cases},
                         {("full-duplex", 1, "socks"), ("tcp-latency", 1, "socks")})
        self.assertEqual({c["iterations"] for c in collector.cases(["trojan"], smoke=True)}, {4, 10})
        self.assertEqual(set(collector.UNITS), set(policy.COMPARISON_BUDGETS))

    def test_build_order_alternates_by_protocol_and_by_repeat(self):
        for index in range(4):
            orders = [collector.order(index, repeat) for repeat in range(1, 5)]
            for name in collector.VERSIONS:
                self.assertEqual(sum(order[0] == name for order in orders), 2)
            self.assertNotEqual(collector.order(index, 1), collector.order(index + 1, 1))

    def campaign(self, directory, **changes):
        """bin/ and build/ as build-isolated-release.py leaves them."""
        commits = {"baseline": (policy.BASELINE["revision"], policy.BASELINE["tree"]),
                   "candidate": (REVISION, TREE), "harness": (REVISION, TREE)}
        for name, (commit, tree) in commits.items():
            binary = directory / "bin" / name
            binary.parent.mkdir(exist_ok=True)
            binary.write_bytes(name.encode())
            record = {"commit": commit, "tree": tree, "incremental": False, "rustflags": None,
                      "isolated_target": True, "sha256": hashlib.sha256(name.encode()).hexdigest(),
                      "path": str(binary), **changes.get(name, {})}
            (directory / "build").mkdir(exist_ok=True)
            (directory / "build" / (name + ".json")).write_text(json.dumps(record))
        return directory

    def test_baseline_must_be_the_published_tag_and_every_build_isolated(self):
        with tempfile.TemporaryDirectory() as temp:
            found = collector.builds(self.campaign(Path(temp)))
            self.assertEqual(found["candidate"]["commit"], REVISION)
            self.assertEqual(Path(found["baseline"]["path"]), (Path(temp) / "bin/baseline").resolve())
        for changes, message in (
                ({"baseline": {"commit": "c" * 40}}, "not the published v0.9.0"),
                ({"baseline": {"tree": "c" * 40}}, "not the published v0.9.0"),
                ({"candidate": {"rustflags": "-C target-cpu=native"}}, "candidate is not a clean isolated build"),
                ({"baseline": {"isolated_target": False}}, "baseline is not a clean isolated build"),
                ({"harness": {"incremental": True}}, "harness is not a clean isolated build"),
                ({"candidate": {"sha256": "0" * 64}}, "candidate differs from its recorded build"),
                ({"harness": {"commit": "d" * 40}}, "driver must be built from the candidate")):
            with tempfile.TemporaryDirectory() as temp, self.assertRaisesRegex(ValueError, message):
                collector.builds(self.campaign(Path(temp), **changes))

    def envelope(self, labels):
        cases = []
        for label in labels:
            outbound = {"tag": "proxy", "protocol": label, "settings": {}}
            if label == "wireguard":
                outbound["settings"] = {"peers": [{"endpoint": "127.0.0.1:1", "allowedIPs": ["198.51.100.0/24"]}]}
            config = {"inbounds": [{"protocol": "tun"}], "dns": {"servers": ["127.0.0.1"]},
                      "routing": {"rules": []}, "outbounds": [outbound]}
            cases.append({"format": "wireguard" if label == "wireguard" else "config", "label": label,
                          "configJSON": json.dumps(config)})
        return {"cases": cases}

    def test_client_configs_keep_each_outbound_alone_and_need_all_twelve(self):
        configs = collector.client_configs(self.envelope(sorted(policy.LEGACY_PROTOCOLS)))
        self.assertEqual(set(configs), policy.LEGACY_PROTOCOLS)
        for label, config in configs.items():
            self.assertEqual(list(config), ["outbounds"], label)
        self.assertEqual(configs["wireguard"]["outbounds"][0]["settings"]["peers"][0]["allowedIPs"], ["0.0.0.0/0"])
        with self.assertRaisesRegex(RuntimeError, "does not cover"):
            collector.client_configs(self.envelope(sorted(policy.LEGACY_PROTOCOLS - {"hysteria2"})))


if __name__ == "__main__":
    unittest.main()

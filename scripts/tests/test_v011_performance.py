"""Guard the v0.11 full-set comparison suite and the release comparison against 0.10.1."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


release = module("v011_release", "run-v011-release-comparison.py")
collector, policy = release.collector, release.policy
comparison = collector.comparison
launcher = module("v011_launcher", "v08-reference-client.py")
REVISION, TREE = "a" * 40, "b" * 40


def fake_openssl(*args, **kwargs):
    return b"k" * 48


def generated(profile):
    """The suite's client and server configs for one profile, keys faked."""
    directory = tempfile.TemporaryDirectory()
    root = Path(directory.name)
    with patch.object(comparison.device, "openssl", side_effect=fake_openssl), \
            patch.object(comparison.acceptance.fixture, "openssl", side_effect=fake_openssl), \
            patch.object(comparison.acceptance.subprocess, "check_output", side_effect=fake_openssl):
        client, server = comparison.configs(profile, root, 41500)
    directory.cleanup()
    return client, server


def socks(client):
    return {**client, "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": 41501}]}


class FullSetSuiteTests(unittest.TestCase):
    def test_the_suite_yields_exactly_the_measurements_the_checker_adds_for_v011(self):
        groups = comparison.MEASUREMENT_GROUPS["v011"]
        self.assertEqual(set(groups), policy.FULL_PROTOCOLS)
        added = set(policy.POLICY.measurement_comparisons) - set(policy.COMMON.MEASUREMENT_COMPARISONS)
        self.assertEqual(added, {f"{group}-{metric}" for group in groups for metric in ("throughput", "latency", "memory")})
        self.assertEqual(comparison.SUITE_CLIENTS["v011"], ("candidate", "xray"))

    def test_each_profile_is_its_device_fixtures_case_on_the_loopback(self):
        client, server = generated("vless-reality")
        outbound, = client["outbounds"]
        self.assertEqual(outbound["streamSettings"]["security"], "reality")
        self.assertEqual(outbound["settings"]["vnext"][0]["users"][0]["flow"], "xtls-rprx-vision")
        self.assertEqual(server["inbounds"][0]["port"], 41500)
        client, server = generated("hysteria2")
        self.assertEqual(client["outbounds"][0]["protocol"], "hysteria")
        self.assertNotIn("disableChromeParrot", json.dumps(client))
        client, server = generated("wireguard")
        peer, = client["outbounds"][0]["settings"]["peers"]
        self.assertEqual(peer["allowedIPs"], ["0.0.0.0/0", "::/0"])
        self.assertEqual(peer["endpoint"], "127.0.0.1:41500")
        for profile in comparison.V011_PROFILES:
            client, server = generated(profile)
            self.assertEqual(set(client), {"log", "outbounds"})
            self.assertEqual(server["outbounds"], [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}])
        self.assertEqual(comparison.SERVER_WARMUP_SECONDS, {"vless-reality": 8})

    def test_the_launcher_hands_xray_the_profiles_and_refuses_anything_else(self):
        with patch.object(launcher, "pinned", return_value={}):
            for profile in comparison.V011_PROFILES:
                config, args, kind = launcher.translate(socks(generated(profile)[0]), "xray", "cert", "v011")
                self.assertEqual((args, kind), (["run", "-config"], "xray"))
            reality = socks(generated("vless-reality")[0])
            with self.assertRaisesRegex(ValueError, "Xray-core client alone"):
                launcher.translate(reality, "singbox", "cert", "v011")
            no_vision = json.loads(json.dumps(reality))
            no_vision["outbounds"][0]["settings"]["vnext"][0]["users"][0].pop("flow")
            with self.assertRaisesRegex(ValueError, "REALITY with Vision"):
                launcher.translate(no_vision, "xray", "cert", "v011")
            muxed = json.loads(json.dumps(reality))
            muxed["outbounds"][0]["mux"] = {"enabled": True}
            with self.assertRaisesRegex(ValueError, "no mask, socket option or Mux"):
                launcher.translate(muxed, "xray", "cert", "v011")
            remote = socks(generated("wireguard")[0])
            remote["outbounds"][0]["settings"]["peers"][0]["endpoint"] = "192.0.2.1:51820"
            with self.assertRaisesRegex(ValueError, "WireGuard on the loopback"):
                launcher.translate(remote, "xray", "cert", "v011")


class ReleaseComparisonTests(unittest.TestCase):
    def test_the_collector_runs_v011s_policy_over_fourteen_carriers(self):
        self.assertIs(collector.policy, policy)
        self.assertEqual(set(collector.PROTOCOLS), policy.COMPARISON_CARRIERS)
        self.assertEqual(len(collector.PROTOCOLS), 14)
        self.assertEqual(policy.BASELINE["version"], "0.10.1")
        self.assertIn(Path(release.__file__).resolve(), collector.EXTRA_FILES)
        self.assertIs(collector.write_server, release.write_server)

    def test_mkcp_and_masque_run_carrier_paced_work(self):
        cases = {case["id"]: case["iterations"] for case in collector.cases(["mkcp", "masque", "trojan"])}
        self.assertEqual(cases["mkcp-full-duplex"], comparison.CARRIER_WORK["mkcp"]["bulk"])
        self.assertEqual(cases["mkcp-tcp-latency"], comparison.CARRIER_WORK["mkcp"]["latency"])
        self.assertEqual(cases["masque-full-duplex"], comparison.CARRIER_WORK["masque"]["bulk"])
        self.assertEqual((cases["trojan-full-duplex"], cases["trojan-tcp-latency"]), (4096, 1000))

    def test_the_server_carries_every_carrier_with_each_ones_client(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(comparison.device, "openssl", side_effect=fake_openssl), \
                patch.object(collector.acceptance.fixture, "openssl", side_effect=fake_openssl), \
                patch.object(collector.acceptance.subprocess, "check_output", side_effect=fake_openssl), \
                patch.object(comparison, "certificate", return_value=([{"certificateFile": "c", "keyFile": "k"}], "f" * 64)):
            server, configs = release.write_server(Path(directory))
        self.assertEqual(set(configs), policy.COMPARISON_CARRIERS)
        protocols = [inbound["protocol"] for inbound in server["inbounds"]]
        self.assertIn("masque", protocols)
        self.assertEqual(configs["mkcp"]["outbounds"][0]["streamSettings"]["network"], "kcp")
        ports = [inbound["port"] for inbound in server["inbounds"]]
        self.assertEqual(len(ports), len(set(ports)))

    def test_writer_output_passes_the_v011_checker_and_a_complete_run_needs_all_fourteen(self):
        measured = {carrier: {metric: {"baseline": [100.0] * 5, "candidate": [100.0] * 5}
                              for metric in policy.COMPARISON_BUDGETS} for carrier in policy.COMPARISON_CARRIERS}
        document = collector.release_comparison(measured, REVISION, TREE)
        policy.validate_release_comparison((json.dumps(document) + "\n").encode(), REVISION, TREE, b"")
        self.assertEqual(document["baseline"], policy.BASELINE)
        run = {"smoke": False, "repeats": 5, "protocols": sorted(policy.COMPARISON_CARRIERS)}
        self.assertTrue(collector.complete(run))
        self.assertFalse(collector.complete({**run, "protocols": sorted(policy.COMPARISON_CARRIERS - {"masque"})}))

    def test_the_baseline_must_be_the_published_v0101_tag(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name, commit, tree in [("baseline", policy.BASELINE["revision"], policy.BASELINE["tree"]),
                                       ("candidate", REVISION, TREE), ("harness", REVISION, TREE)]:
                (root / "bin").mkdir(exist_ok=True)
                (root / "build").mkdir(exist_ok=True)
                (root / "bin" / name).write_bytes(name.encode())
                (root / "build" / (name + ".json")).write_text(json.dumps({
                    "commit": commit, "tree": tree, "incremental": False, "rustflags": None,
                    "isolated_target": True, "sha256": hashlib.sha256(name.encode()).hexdigest()}))
            self.assertEqual(collector.builds(root)["baseline"]["commit"], policy.BASELINE["revision"])
            record = json.loads((root / "build/baseline.json").read_text())
            record["commit"] = "c" * 40
            (root / "build/baseline.json").write_text(json.dumps(record))
            with self.assertRaisesRegex(ValueError, "not the published v0.10.1"):
                collector.builds(root)


if __name__ == "__main__":
    unittest.main()

"""Guard matched wire settings and the completeness of the v0.8 comparison."""
import base64
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


collector = module("comparison", "run-v08-protocol-comparison.py")
launcher = module("client", "v08-reference-client.py")
blocks = module("blocks", "run-v08-comparison-blocks.py")
controls = module("controls", "run-v08-cpu-controls.py")


class ComparisonTests(unittest.TestCase):
    def test_paired_and_three_client_controls_balance_every_order_position(self):
        for names in (("baseline", "candidate"), ("baseline", "channel", "candidate")):
            for case_index in range(8):
                orders = [controls.client_order(names, case_index, repeat)
                          for repeat in range(1, 2 * len(names) + 1)]
                for order in orders:
                    self.assertCountEqual(order, names)
                for name in names:
                    for position in range(len(names)):
                        self.assertEqual(sum(order[position] == name for order in orders), 2)

    def test_blocks_never_classify_protocol_or_observer_errors_as_retryable(self):
        clean = dict(returncode=0, process_group_empty_after_run=True,
                     remaining_engine_processes=[], surviving_process_group=False,
                     ambient_cpu=dict(observer_errors=[], compiler_load_detected=[]))
        contaminated = copy.deepcopy(clean)
        contaminated['ambient_cpu']['compiler_load_detected'] = [{'name': 'rustc'}]
        self.assertEqual(blocks.quality([clean]), 'clean')
        self.assertEqual(blocks.quality([clean, contaminated]), 'contaminated')
        for field, value in [('returncode', 1), ('process_group_empty_after_run', False),
                             ('remaining_engine_processes', ['leftover']), ('surviving_process_group', True)]:
            failed = copy.deepcopy(contaminated)
            failed[field] = value
            self.assertEqual(blocks.quality([failed]), 'error')
        contaminated['ambient_cpu']['observer_errors'] = ['ps failed']
        self.assertEqual(blocks.quality([contaminated]), 'error')

    def test_case_filter_preserves_full_campaign_rotation_and_rejects_typos(self):
        cases = collector.cases(collector.PROFILES)
        selected = collector.select_cases(cases, [cases[17]["id"], cases[3]["id"]])
        self.assertEqual(selected, [(3, cases[3]), (17, cases[17])])
        self.assertEqual(collector.select_cases(cases, None), list(enumerate(cases)))
        for invalid in [["missing-case"], [cases[3]["id"], cases[3]["id"]]]:
            with self.assertRaises(ValueError):
                collector.select_cases(cases, invalid)

    def test_environment_guard_covers_builds_and_active_neural_compilers(self):
        processes = "1 0.0 /bin/rustc\n2 0.0 /bin/ANECompilerService\n3 5.0 /bin/ANECompilerService\n4 20.0 /bin/ordinary-app\n"
        with patch.object(collector.bench, "command", return_value=processes):
            self.assertEqual([p["pid"] for p in collector.ambient()["compiler_load_detected"]], [1, 3])

    def test_failed_environment_observation_cannot_be_a_successful_trial(self):
        with patch.object(collector, "ambient", side_effect=OSError("ps failed")), \
                patch.object(collector.bench, "execute", return_value={"returncode": 0}):
            result = collector.measured_execute([], Path("unused"))
        self.assertEqual(result["returncode"], 126)
        self.assertEqual(result["ambient_cpu"]["observer_errors"], ["ps failed"])

    def profile(self, name, directory):
        client, server = collector.configs(name, directory, 12345)
        client["inbounds"] = [{"protocol": "socks", "listen": "127.0.0.1", "port": 23456}]
        return client, server

    def test_all_seven_profiles_have_identical_axes_and_payloads(self):
        cases = collector.cases(collector.PROFILES)
        self.assertEqual(len(cases), 70)
        self.assertEqual(len({c["id"] for c in cases}), 70)
        axes = lambda profile: {(c["traffic"], c["connections"], c["iterations"], c["payload_size"])
                                for c in cases if c["profile"] == profile}
        for profile in collector.PROFILES:
            self.assertEqual(axes(profile), axes("trojan-tls"))
        self.assertEqual({c["path"] for c in cases}, {"socks"})

    def test_ss2022_key_length_cipher_and_server_match(self):
        with tempfile.TemporaryDirectory() as temp:
            for profile in ("ss2022-aes128", "ss2022-aes256", "ss2022-chacha20"):
                client, server = self.profile(profile, Path(temp))
                converted, _, kind = launcher.translate(client, "singbox", "")
                settings = server["inbounds"][0]["settings"]
                out = converted["outbounds"][0]
                self.assertEqual(kind, "singbox")
                self.assertEqual(out["method"], settings["method"])
                self.assertEqual(out["password"], settings["password"])
                self.assertEqual(len(base64.b64decode(out["password"])), 16 if profile.endswith("aes128") else 32)

    def test_vmess_padding_xudp_and_cipher_match_pinned_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            for profile in ("vmess-aes128", "vmess-chacha20", "vmess-auto"):
                client, server = self.profile(profile, Path(temp))
                translated, _, _ = launcher.translate(client, "singbox", "")
                out = translated["outbounds"][0]
                self.assertEqual(out["uuid"], server["inbounds"][0]["settings"]["clients"][0]["id"])
                self.assertEqual(out["security"], client["outbounds"][0]["settings"]["security"])
                self.assertTrue(out["global_padding"])
                self.assertFalse(out["authenticated_length"])
                self.assertEqual(out["packet_encoding"], "xudp")
                self.assertNotIn("tls", out)

    def test_trojan_uses_verified_same_key_and_chrome_fingerprint(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            client, _ = self.profile("trojan-tls", directory)
            converted, args, kind = launcher.translate(client, "singbox", directory / "tls.crt")
            self.assertEqual((args, kind), (["run", "-c"], "singbox"))
            tls = converted["outbounds"][0]["tls"]
            self.assertNotIn("insecure", tls)
            self.assertEqual(tls["utls"], {"enabled": True, "fingerprint": "chrome"})
            self.assertEqual(len(base64.b64decode(tls["certificate_public_key_sha256"][0])), 32)
            client["outbounds"][0]["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"] = "00" * 32
            for mode in ("singbox", "xray"):
                with self.assertRaisesRegex(ValueError, "does not match"):
                    launcher.translate(client, mode, directory / "tls.crt")

    def test_legacy_or_weaker_profiles_are_rejected_for_both_references(self):
        with tempfile.TemporaryDirectory() as temp:
            for mode in ("singbox", "xray"):
                for field, value in (("security", "none"), ("alterId", 1), ("experiments", "AuthenticatedLength")):
                    client, _ = self.profile("vmess-aes128", Path(temp))
                    client["outbounds"][0]["settings"][field] = value
                    with self.assertRaises(ValueError):
                        launcher.translate(client, mode, "")
                client, _ = self.profile("ss2022-aes128", Path(temp))
                client["outbounds"][0]["settings"]["method"] = "aes-128-gcm"
                with self.assertRaises(ValueError):
                    launcher.translate(client, mode, "")

    def test_nonlocal_carrier_tun_and_unsupported_transport_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            for change in ("carrier", "ingress", "transport", "mux"):
                client, _ = self.profile("vmess-aes128", Path(temp))
                if change == "carrier":
                    client["outbounds"][0]["settings"]["address"] = "192.0.2.1"
                elif change == "ingress":
                    client["inbounds"][0]["protocol"] = "tun"
                elif change == "transport":
                    client["outbounds"][0]["streamSettings"]["network"] = "ws"
                else:
                    client["outbounds"][0]["mux"] = {"enabled": True}
                with self.assertRaises(ValueError):
                    launcher.translate(client, "singbox", "")


if __name__ == "__main__":
    unittest.main()

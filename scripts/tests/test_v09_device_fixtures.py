"""v0.9 device fixtures, comparison profiles and their guards."""
import argparse
import asyncio
import base64
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import unquote, urlsplit

SCRIPTS = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


device = module("v09_device", "run-v07-apple-protocol-fixture.py")
android = module("v09_android", "run-v08-android-protocol-fixture.py")
acceptance = module("v09_acceptance", "run-v08-apple-acceptance-fixture.py")
comparison = module("v09_comparison", "run-v08-protocol-comparison.py")
launcher = module("v09_launcher", "v08-reference-client.py")
performance = module("v09_performance", "run-v07-performance.py")
prepare = module("v09_prepare", "prepare-v08-protocol-comparison.py")
campaign = module("v09_campaign", "run-apple-device-campaign.py")
driver = module("v09_driver", "run-v09-android-device-matrix.py")

# The legacy-regression transitions of the v0.9 evidence profile.
LEGACY_V09 = {"vless-reality", "xhttp-h1", "xhttp-h2", "xhttp-h3", "hysteria2", "wireguard",
              "trojan", "shadowsocks2022", "vmess"}
KW = {"mode": "smoke", "probe_host": "v07-probe-abc.test"}
OPENSSL = shutil.which("openssl")


def fake_openssl(*args):
    return b"k" * 32


def read(root):
    return (json.loads((root / "server.json").read_text()),
            json.loads((root / "v07-probe.json").read_text()))


def outbound(case):
    return json.loads(case["configJSON"])["outbounds"][0]


class AppleV09FixtureTests(unittest.TestCase):
    def generate(self, protocol="v09", port=None):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        with patch.object(device, "openssl", side_effect=fake_openssl):
            device.write_fixtures(root, "127.0.0.1", 41001, 41002, 41003, protocol=protocol, port=port, **KW)
        return read(root)

    def test_v09_cases_are_labelled_by_scenario_with_udp_expectations(self):
        server, envelope = self.generate()
        self.assertEqual([(c["format"], c["label"], c["udp"]) for c in envelope["cases"]], [
            ("socks", "socks:password", True), ("http", "http:plain", False),
            ("http", "http:tls", False), ("shadowsocks2022", "shadowsocks-aead:aes-256-gcm", True)])
        self.assertEqual([i["protocol"] for i in server["inbounds"]], ["socks", "http", "http", "shadowsocks"])
        self.assertEqual(len({i["port"] for i in server["inbounds"]}), 4)
        for case, inbound in zip(envelope["cases"], server["inbounds"]):
            settings = outbound(case)["settings"]
            self.assertEqual((settings["address"], settings["port"]), ("127.0.0.1", inbound["port"]))
            self.assertEqual(case["serverAddress"], "127.0.0.1")

    def test_http_resolves_over_tcp_and_udp_protocols_keep_udp_dns(self):
        _, envelope = self.generate()
        for case in envelope["cases"]:
            servers = json.loads(case["configJSON"])["dns"]["servers"]
            expected = "tcp://198.51.100.53:41003" if case["format"] == "http" else "198.51.100.53:41003"
            self.assertEqual(servers, [expected])

    def test_proxy_credentials_match_the_server_and_link(self):
        server, envelope = self.generate()
        for case, inbound in zip(envelope["cases"][:3], server["inbounds"][:3]):
            settings = outbound(case)["settings"]
            self.assertEqual(inbound["settings"]["accounts"], [{"user": settings["user"], "pass": settings["pass"]}])
            link = urlsplit(case["text"])
            self.assertEqual((unquote(link.username), unquote(link.password)), (settings["user"], settings["pass"]))
            self.assertEqual((link.hostname, link.port, link.query), ("127.0.0.1", inbound["port"], ""))
        socks = server["inbounds"][0]["settings"]
        self.assertEqual((socks["auth"], socks["udp"], socks["ip"]), ("password", True, "127.0.0.1"))
        self.assertTrue(envelope["cases"][0]["text"].startswith("socks5://"))
        self.assertTrue(envelope["cases"][1]["text"].startswith("http://"))
        self.assertTrue(envelope["cases"][2]["text"].startswith("https://"))

    def test_https_pins_the_fixture_certificate_and_offers_only_http11(self):
        server, envelope = self.generate()
        stream = outbound(envelope["cases"][2])["streamSettings"]
        self.assertEqual(stream["security"], "tls")
        self.assertEqual(stream["tlsSettings"]["alpn"], ["http/1.1"])
        self.assertRegex(stream["tlsSettings"]["pinnedPeerCertSha256"], "^[0-9a-f]{64}$")
        self.assertNotIn("allowInsecure", stream["tlsSettings"])
        self.assertEqual(server["inbounds"][2]["streamSettings"]["tlsSettings"]["alpn"], ["http/1.1"])
        self.assertNotIn("security", outbound(envelope["cases"][1])["streamSettings"])

    def test_shadowsocks_aead_link_is_sip002_base64url(self):
        server, envelope = self.generate()
        case, inbound = envelope["cases"][3], server["inbounds"][3]
        settings = outbound(case)["settings"]
        self.assertEqual(inbound["settings"], {"method": "aes-256-gcm", "password": settings["password"],
                                               "network": "tcp,udp"})
        userinfo = urlsplit(case["text"]).username
        self.assertNotIn("=", userinfo)
        decoded = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
        self.assertEqual(decoded, f"aes-256-gcm:{settings['password']}")

    def test_invalid_imports_carry_the_marker_for_each_selected_scenario(self):
        _, envelope = self.generate()
        marker = envelope["redactionMarker"]
        self.assertEqual([(i["scenario"], i["format"]) for i in envelope["invalidImports"]],
                         [("socks", "socks"), ("http", "http"), ("shadowsocks-aead", "shadowsocks2022")])
        for item in envelope["invalidImports"]:
            self.assertIn(marker, item["text"])
        _, single = self.generate("https", port=41010)
        self.assertEqual([i["scenario"] for i in single["invalidImports"]], ["http"])

    def test_single_protocol_honours_an_explicit_wan_port(self):
        server, envelope = self.generate("shadowsocks-aead", port=41010)
        self.assertEqual([i["port"] for i in server["inbounds"]], [41010])
        self.assertEqual(outbound(envelope["cases"][0])["settings"]["port"], 41010)

    def test_v08_envelope_is_unchanged(self):
        _, envelope = self.generate("v08")
        self.assertEqual([c["format"] for c in envelope["cases"]], ["trojan", "shadowsocks2022", "vmess"])
        for case in envelope["cases"]:
            self.assertFalse({"label", "udp"} & set(case))
        self.assertFalse({"invalidImports", "redactionMarker"} & set(envelope))

    def test_unknown_client_protocol_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(device, "openssl", side_effect=fake_openssl), \
                self.assertRaises(ValueError):
            device.write_client_fixtures(Path(directory), "127.0.0.1", 1, 2, 3, "socks4", None, "smoke", "x.test")


class DnsTests(unittest.IsolatedAsyncioTestCase):
    def query(self, name, kind=1, ident=0x1234):
        question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
        return struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question + struct.pack("!HH", kind, 1)

    async def test_tcp_dns_answers_framed_queries_on_one_connection(self):
        loop = asyncio.get_running_loop()
        transport, server = await device.dns_listeners(loop, "127.0.0.1", "probe.test")
        try:
            udp_port = transport.get_extra_info("sockname")[1]
            self.assertEqual(server.sockets[0].getsockname()[1], udp_port)
            reader, writer = await asyncio.open_connection("127.0.0.1", udp_port)
            answers = []
            for name, kind in [("probe.test", 1), ("probe.test", 28), ("other.test", 1)]:
                query = self.query(name, kind)
                writer.write(struct.pack("!H", len(query)) + query)
                length = struct.unpack("!H", await reader.readexactly(2))[0]
                answers.append(await reader.readexactly(length))
            self.assertEqual(answers[0][-4:], bytes([198, 51, 100, 7]))
            self.assertEqual(answers[1][-16:], bytes.fromhex("20010db8000000000000000000000007"))
            self.assertEqual(answers[2][3] & 15, 3)  # NXDOMAIN
            writer.write(b"\x00\x03abc")  # malformed: the listener closes
            self.assertEqual(await asyncio.wait_for(reader.read(), 2), b"")
            writer.close()
        finally:
            server.close()
            await server.wait_closed()
            transport.close()

    def test_udp_and_tcp_answers_are_identical(self):
        query = self.query("probe.test")
        self.assertEqual(device.dns_answer(query, "probe.test")[-4:], bytes([198, 51, 100, 7]))
        self.assertIsNone(device.dns_answer(query[:-1], "probe.test"))


class AndroidV09FixtureTests(unittest.TestCase):
    def test_v09_case_ids_cover_every_classic_aead_method(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(android.fixture, "openssl", side_effect=fake_openssl):
            root = Path(directory)
            android.write_fixtures(root, "127.0.0.1", 1, 2, 3, protocol="v09", port=None, **KW)
            server, envelope = read(root)
        self.assertEqual([c["caseId"] for c in envelope["cases"]], [
            "socks-password", "http-plain", "http-tls", "shadowsocks-aead-aes-256-gcm",
            "shadowsocks-aead-aes-128-gcm", "shadowsocks-aead-chacha20-poly1305",
            "shadowsocks-aead-xchacha20-poly1305"])
        self.assertEqual(len({i["port"] for i in server["inbounds"]}), len(server["inbounds"]))
        for case, inbound in zip(envelope["cases"], server["inbounds"]):
            settings = outbound(case)["settings"]
            self.assertEqual(settings["port"], inbound["port"])
            self.assertEqual(case["udp"], case["format"] != "http")
            if inbound["protocol"] == "shadowsocks":
                self.assertEqual((inbound["settings"]["method"], inbound["settings"]["password"]),
                                 (settings["method"], settings["password"]))
                self.assertTrue(case["text"].endswith(f"@127.0.0.1:{inbound['port']}"))

    def test_v08_case_ids_are_unchanged_and_ports_are_still_rejected(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(android.fixture, "openssl", side_effect=fake_openssl):
            root = Path(directory)
            android.write_fixtures(root, "127.0.0.1", 1, 2, 3, protocol="v08", port=None, **KW)
            _, envelope = read(root)
            with self.assertRaises(ValueError):
                android.write_fixtures(root, "127.0.0.1", 1, 2, 3, protocol="v09", port=4000, **KW)
        self.assertEqual([c["caseId"] for c in envelope["cases"]], [
            "trojan-tls", "shadowsocks2022-2022-blake3-chacha20-poly1305", "vmess-auto",
            "shadowsocks2022-2022-blake3-aes-128-gcm", "shadowsocks2022-2022-blake3-aes-256-gcm",
            "vmess-aes-128-gcm", "vmess-chacha20-poly1305"])


@unittest.skipUnless(OPENSSL, "openssl is required for the legacy key generators")
class AppleAcceptanceV09Tests(unittest.TestCase):
    def test_ciphers_v09_cover_four_methods_and_an_alias_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            acceptance.write_ciphers_v09(root, "127.0.0.1", 1, 2, 3, protocol="both", port=None, **KW)
            server, envelope = read(root)
        methods = [outbound(c)["settings"]["method"] for c in envelope["cases"]]
        self.assertEqual(methods, ["aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "xchacha20-poly1305"])
        self.assertEqual([i["settings"]["method"] for i in server["inbounds"]], methods)
        userinfo = urlsplit(envelope["cases"][2]["text"]).username
        decoded = base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode()
        self.assertTrue(decoded.startswith("chacha20-ietf-poly1305:"))

    def test_legacy_v09_holds_the_nine_regression_protocols_and_is_cleaned_up(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture"
            output.mkdir()
            stub = Path(directory) / "xray"
            stub.write_text("#!/bin/sh\nexec sleep 30\n")
            stub.chmod(0o700)
            written = {}

            def write(*args, **kwargs):
                acceptance.write_legacy_v09(*args, **kwargs)
                written.update(zip(("server", "envelope"), read(output)))
                written["parts"] = sorted(p.name for p in (output / "parts").iterdir())

            args = argparse.Namespace(output=output, bind="127.0.0.1", protocol="both", port=None,
                                      mode="smoke", seconds=1, reference_binary=stub)
            with patch.object(acceptance.fixture, "write_fixtures", side_effect=write), \
                    patch("builtins.print"):
                asyncio.run(acceptance.fixture.serve(args))
            remaining = sorted(p.name for p in output.iterdir())
        self.assertEqual({c["label"] for c in written["envelope"]["cases"]}, LEGACY_V09)
        self.assertEqual(len(written["envelope"]["cases"]), 9)
        ports = [i["port"] for i in written["server"]["inbounds"]]
        self.assertEqual(len(ports), len(set(ports)))
        self.assertEqual(written["parts"], ["legacy", "v07", "v08"])
        self.assertEqual(remaining, ["server.log"])  # keys, configs and parts removed

    def test_android_legacy_v09_case_ids_are_the_transition_names(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            android.write_regression(root, "127.0.0.1", 1, 2, 3, suite="legacy-v09",
                                     protocol="both", port=None, **KW)
            _, envelope = read(root)
        self.assertEqual({c["caseId"] for c in envelope["cases"]}, LEGACY_V09)


class ComparisonV09Tests(unittest.TestCase):
    def profile(self, name, directory):
        client, server = comparison.configs(name, directory, 12345)
        client["inbounds"] = [{"protocol": "socks", "listen": "127.0.0.1", "port": 23456}]
        return client, server

    def test_v09_cases_match_v08_axes_without_http_udp(self):
        cases = comparison.cases(comparison.V09_PROFILES)
        self.assertEqual(len(cases), 66)
        self.assertEqual(len(comparison.cases(comparison.PROFILES)), 70)
        self.assertFalse([c for c in cases if c["traffic"] == "udp" and c["profile"].startswith("http")])
        groups = comparison.MEASUREMENT_GROUPS["v09"]
        self.assertEqual(set(groups), {"socks", "http", "shadowsocks-aead"})
        self.assertEqual(sorted(p for v in groups.values() for p in v), sorted(comparison.V09_PROFILES))

    def test_proxy_profiles_authenticate_and_translate_for_both_references(self):
        with tempfile.TemporaryDirectory() as temp:
            for name, kind in [("socks-auth", "socks"), ("http-basic", "http")]:
                client, server = self.profile(name, Path(temp))
                settings = client["outbounds"][0]["settings"]
                self.assertEqual(server["inbounds"][0]["settings"]["accounts"],
                                 [{"user": settings["user"], "pass": settings["pass"]}])
                converted, _, mode = launcher.translate(client, "singbox", "", "v09")
                out = converted["outbounds"][0]
                self.assertEqual((mode, out["type"], out["username"], out["password"]),
                                 ("singbox", kind, settings["user"], settings["pass"]))
                self.assertNotIn("tls", out)
                self.assertEqual(launcher.translate(client, "xray", "", "v09")[2], "xray")
                del client["outbounds"][0]["settings"]["pass"]
                with self.assertRaisesRegex(ValueError, "authenticated"):
                    launcher.translate(client, "xray", "", "v09")
            self.assertEqual(self.profile("socks-auth", Path(temp))[1]["inbounds"][0]["settings"]["udp"], True)

    @unittest.skipUnless(OPENSSL, "openssl is required for the TLS fixture")
    def test_https_profile_is_pinned_and_chrome_shaped(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            client, _ = self.profile("http-basic-tls", directory)
            converted, _, _ = launcher.translate(client, "singbox", directory / "tls.crt", "v09")
            tls = converted["outbounds"][0]["tls"]
            self.assertEqual(tls["utls"], {"enabled": True, "fingerprint": "chrome"})
            self.assertEqual(tls["alpn"], ["http/1.1"])
            client["outbounds"][0]["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"] = "00" * 32
            with self.assertRaisesRegex(ValueError, "does not match"):
                launcher.translate(client, "xray", directory / "tls.crt", "v09")

    def test_shadowsocks_families_stay_in_their_suites(self):
        with tempfile.TemporaryDirectory() as temp:
            for name, singbox in [("ss-aes128gcm", "aes-128-gcm"), ("ss-chacha20", "chacha20-ietf-poly1305"),
                                  ("ss-xchacha20", "xchacha20-ietf-poly1305")]:
                client, server = self.profile(name, Path(temp))
                converted, _, _ = launcher.translate(client, "singbox", "", "v09")
                self.assertEqual(converted["outbounds"][0]["method"], singbox)
                self.assertEqual(server["inbounds"][0]["settings"]["password"],
                                 client["outbounds"][0]["settings"]["password"])
                with self.assertRaises(ValueError):
                    launcher.translate(client, "xray", "", "v08")
            client, _ = self.profile("ss2022-aes128", Path(temp))
            with self.assertRaisesRegex(ValueError, "AEAD-2017"):
                launcher.translate(client, "xray", "", "v09")
            client, _ = self.profile("vmess-auto", Path(temp))
            with self.assertRaises(ValueError):
                launcher.translate(client, "xray", "", "v09")


class PinsAndPerformanceTests(unittest.TestCase):
    def test_collectors_record_and_require_the_device_fixture_reference(self):
        self.assertEqual(performance.REFERENCE, device.REFERENCE)
        self.assertEqual(prepare.XRAY, device.REFERENCE)

    def test_performance_v09_suite_has_no_http_udp(self):
        cases = performance.protocol_cases("v09", smoke=True)
        protocols = {c["protocol"] for c in cases}
        self.assertEqual(protocols, {"socks", "http", "https", "shadowsocks-aead"})
        self.assertEqual({c["path"] for c in cases}, {"socks", "tun"})
        self.assertFalse([c for c in cases if c["traffic"] == "udp" and c["protocol"].startswith("http")])
        self.assertEqual(set(performance.V09_CASES), {"socks:password", "http:plain", "http:tls",
                                                      "shadowsocks-aead:" + device.SHADOWSOCKS_AEAD_METHOD})


class AndroidDriverTests(unittest.TestCase):
    def drive(self, cases, leak=False):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        with patch.object(android.fixture, "openssl", side_effect=fake_openssl):
            android.write_fixtures(root, "127.0.0.1", 1, 2, 3, protocol="v09", port=None, **KW)
        environment = {"ANDROID_SERIAL": "emulator-0", "ADB": str(SCRIPTS / "tests/fixtures/fake-adb.py"),
                       "FAKE_ADB_STATE": str(root / "adb.json")}
        if leak:
            environment["FAKE_ADB_HTTP_UDP"] = "leak"
        argv = ["driver", "--fixture", str(root / "v07-probe.json"), "--work-dir", str(root / "run")]
        for case in cases:
            argv += ["--case", case]
        with patch.dict("os.environ", environment), patch("sys.argv", argv), \
                patch.object(driver.time, "sleep"), patch("builtins.print"):
            try:
                driver.main()
            finally:
                log, adb = root / "run/events.jsonl", root / "adb.json"
                events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                state = json.loads(adb.read_text()) if adb.exists() else {"argv": []}
                envelope = json.loads((root / "v07-probe.json").read_text())
                self.result = events, state, envelope
        return self.result

    def test_http_cases_require_refused_udp_on_both_backends(self):
        events, state, envelope = self.drive(["socks-password", "http-plain"])
        passed = [(e["case"], e["backend"], e["udp"]) for e in events if e["kind"] == "case-pass"]
        self.assertEqual(passed, [("socks-password", "file-descriptor", "echo"),
                                  ("socks-password", "packet-pump", "echo"),
                                  ("http-plain", "file-descriptor", "refused"),
                                  ("http-plain", "packet-pump", "refused")])
        self.assertEqual(events[-1]["kind"], "controls-complete")
        controls = [(e["scenario"], e["passed"]) for e in events if e["kind"] == "invalid-import-control"]
        self.assertEqual(controls, [("socks", True), ("http", True), ("shadowsocks-aead", True)])
        http = [e for e in events if e["kind"] == "traffic" and e["case"] == "http-plain"]
        self.assertTrue(http and all(int(e["status"]["udp-failed"]) >= 3 for e in http))
        # Links, configs and credentials only travel through stdin.
        arguments = json.dumps(state["argv"])
        for case in envelope["cases"]:
            self.assertNotIn(case["text"], arguments)
            settings = json.loads(case["configJSON"])["outbounds"][0]["settings"]
            self.assertNotIn(settings.get("pass", settings.get("password")), arguments)

    def test_an_answered_http_udp_probe_fails_the_case(self):
        with self.assertRaisesRegex(RuntimeError, "without UDP"):
            self.drive(["http-tls"], leak=True)
        events = self.result[0]
        self.assertEqual([e["kind"] for e in events if e["kind"] in ("case-fail", "matrix-pass")], ["case-fail"])

    def test_unknown_case_is_rejected(self):
        with self.assertRaises(SystemExit):
            self.drive(["http-plaintext"])


class CampaignRedactionTests(unittest.TestCase):
    def test_every_share_link_and_credentialed_url_is_redacted(self):
        line = ("a vless://u@h:1 b vmess://e30= c trojan://p@h:1 d ss://YQ@h:1 e socks5://u:p@h:1 "
                "f SOCKS://u:p@h:1 g hy2://a@h:1 h https://u:p@h:1 i http://u:p@h:1")
        redacted = campaign.redact(line, [])
        self.assertNotIn("://", redacted)
        self.assertIn("<redacted-vless-url>", redacted)
        kept = "probe https://example.test/generate_204 class=boss://x"
        self.assertEqual(campaign.redact(kept, []), kept)


if __name__ == "__main__":
    unittest.main()

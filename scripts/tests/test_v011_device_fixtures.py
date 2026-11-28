"""v0.11 device fixtures: TUN sniffing, import, WireGuard's idle case, their relay and checks."""
import asyncio
import base64
import importlib.util
import ipaddress
import json
from pathlib import Path
import socket
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


device = module("v011_device", "run-v07-apple-protocol-fixture.py")
android = module("v011_android", "run-v08-android-protocol-fixture.py")
acceptance = module("v011_acceptance", "run-v08-apple-acceptance-fixture.py")
loopback = module("v011_loopback", "check-v011-fixture-loopback.py")
restart = module("v011_restart", "check-v011-wireguard-restart.py")
policy = module("v011_policy", "check-v011-release-evidence.py")

PROBE = "v07-probe-abc.test"
KW = {"mode": "smoke", "probe_host": PROBE}
# What every SDK importer release from 0.7.0 to 0.10.1 wrote, on both platforms.
IMPORTED = {"tag": "tun-in", "protocol": "tun", "listen": "127.0.0.1", "port": 0, "settings": {},
            "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"], "metadataOnly": False}}


def fake_openssl(*args):
    return b"k" * 32


def generate(test, protocol, port=None, writer=None, **extra):
    directory = tempfile.TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    root = Path(directory.name)
    writer = writer or device.write_fixtures
    with patch.object(device, "openssl", side_effect=fake_openssl), \
            patch.object(android.fixture, "openssl", side_effect=fake_openssl):
        writer(root, "127.0.0.1", 41001, 41002, 41003, protocol=protocol, port=port, **KW, **extra)
    server = json.loads((root / "server.json").read_text())
    envelope = json.loads((root / "v07-probe.json").read_text())
    return server, envelope, root


def config(case):
    return json.loads(case["configJSON"])


def sniffed_name(payload):
    """What the core's sniffer reads: HTTP Host, or the ClientHello's SNI."""
    if payload.startswith(b"GET "):
        return next(line.split(b": ", 1)[1].decode() for line in payload.split(b"\r\n") if line.startswith(b"Host: "))
    # TLS record, handshake header, version, random, session id, ciphers, compression, extensions.
    offset = 5 + 4 + 2 + 32
    offset += 1 + payload[offset]
    offset += 2 + int.from_bytes(payload[offset:offset + 2], "big")
    offset += 1 + payload[offset]
    end = offset + 2 + int.from_bytes(payload[offset:offset + 2], "big")
    offset += 2
    while offset < end:
        kind, length = int.from_bytes(payload[offset:offset + 2], "big"), int.from_bytes(payload[offset + 2:offset + 4], "big")
        if kind == 0:
            size = int.from_bytes(payload[offset + 7:offset + 9], "big")
            return payload[offset + 9:offset + 9 + size].decode()
        offset += 4 + length
    raise AssertionError("no server name")


def matches(rule, domain, address):
    if "domain" in rule:
        return domain is not None and f"full:{domain}" in rule["domain"]
    if "ip" in rule:
        return any(ipaddress.ip_address(address) in ipaddress.ip_network(net) for net in rule["ip"])
    return rule.get("network") == "tcp,udp"


def route(rules, domain, address, default):
    return next((rule["outboundTag"] for rule in rules if matches(rule, domain, address)), default)


def outcome(case_config, server, probe, route_only):
    """Xray-core's decision for one probe: the sniffed name routes the flow;
    with routeOnly the original address is dialed, without it the name."""
    domain = sniffed_name(base64.b64decode(probe["payload"]))
    rules = case_config["routing"]["rules"]
    if route(rules, domain, probe["host"], case_config["outbounds"][0]["tag"]) != "proxy":
        return "refused"
    target_domain, target_address = (None, probe["host"]) if route_only else (domain, "0.0.0.0")
    tag = route(server["routing"]["rules"], target_domain, target_address, server["outbounds"][0]["tag"])
    return "echo" if tag == "echo" else "refused"


class SniffFixtureTests(unittest.TestCase):
    def setUp(self):
        self.server, self.envelope, _ = generate(self, "sniff-v011")
        self.cases = {case["label"]: case for case in self.envelope["cases"]}

    def test_three_cases_carry_the_importers_inbound_with_their_own_sniffing(self):
        self.assertEqual(list(self.cases), ["sniff:route-only", "sniff:imported", "sniff:name-dial"])
        self.assertEqual(device.IMPORTED_TUN_INBOUND, IMPORTED)
        extras = {"sniff:route-only": {"routeOnly": True}, "sniff:imported": {}, "sniff:name-dial": {"routeOnly": False}}
        for label, case in self.cases.items():
            inbound = config(case)["inbounds"][0]
            self.assertEqual(inbound, {**IMPORTED, "sniffing": {**IMPORTED["sniffing"], **extras[label]}}, label)
            self.assertEqual(case["format"], "config")
            self.assertNotIn("text", case)
        # The migration matches exactly this: three keys, nothing else.
        self.assertEqual(config(self.cases["sniff:imported"])["inbounds"][0]["sniffing"], IMPORTED["sniffing"])

    def test_probes_are_the_scenarios_transitions(self):
        seen = [probe["transition"] for case in self.cases.values() for probe in case["sniffProbes"]]
        self.assertEqual(len(seen), len(set(seen)))
        self.assertEqual(set(seen), policy.SNIFFING_TRANSITIONS)
        for case in self.cases.values():
            for probe in case["sniffProbes"]:
                self.assertIn(probe["expect"], ("echo", "refused"))
                ipaddress.ip_address(probe["host"])

    def test_payloads_name_their_labels_under_the_probe_host(self):
        names = {"http-host-route": "routed", "tls-sni-route": "routed", "domain-rule-refusal": "refused",
                 "decoy-sni-address": "decoy", "saved-profile-migration": "decoy", "sniffed-name-dial": "byname"}
        for case in self.cases.values():
            for probe in case["sniffProbes"]:
                payload = base64.b64decode(probe["payload"])
                self.assertEqual(sniffed_name(payload), f"{names[probe['transition']]}.{PROBE}")
                if "tls" in probe["transition"] or "decoy" in probe["transition"] or "migration" in probe["transition"]:
                    self.assertEqual(payload[:2], b"\x16\x03")
                    # Within the core's 8 KiB sniff buffer.
                    self.assertLess(len(payload), 8 * 1024)
                else:
                    self.assertTrue(payload.startswith(b"GET / HTTP/1.1\r\n") and payload.endswith(b"\r\n\r\n"))

    def test_every_expectation_follows_from_xray_cores_routing(self):
        for label, case in self.cases.items():
            sniffing = config(case)["inbounds"][0]["sniffing"]
            # sniff:imported runs with the routeOnly its start path adds.
            route_only = sniffing.get("routeOnly", label == "sniff:imported")
            for probe in case["sniffProbes"]:
                with self.subTest(transition=probe["transition"]):
                    self.assertEqual(outcome(config(case), self.server, probe, route_only), probe["expect"])

    def test_each_echo_would_be_refused_if_what_it_checks_were_broken(self):
        for label, case in self.cases.items():
            for probe in case["sniffProbes"]:
                if probe["expect"] != "echo":
                    continue
                with self.subTest(transition=probe["transition"]):
                    flipped = config(case)
                    if label == "sniff:name-dial":
                        # Dialed by its address, as a migration that touched an explicit false would.
                        self.assertEqual(outcome(flipped, self.server, probe, True), "refused")
                    elif probe["transition"] in ("decoy-sni-address", "saved-profile-migration"):
                        # Dialed by the decoy name, as without routeOnly.
                        self.assertEqual(outcome(flipped, self.server, probe, False), "refused")
                    else:
                        # Routed by its address alone, as without sniffing.
                        self.assertEqual(route(flipped["routing"]["rules"], None, probe["host"], "proxy"), "block")
        # And the refusal: routed by its address alone, it would be echoed.
        probe = next(p for p in self.cases["sniff:route-only"]["sniffProbes"] if p["transition"] == "domain-rule-refusal")
        rules = config(self.cases["sniff:route-only"])["routing"]["rules"]
        self.assertEqual(route(rules, None, probe["host"], "proxy"), "proxy")

    def test_server_echoes_the_ranges_and_one_name_and_refuses_the_rest(self):
        self.assertEqual(self.server["outbounds"][0], {"tag": "blocked", "protocol": "blackhole"})
        self.assertEqual(self.server["routing"]["rules"], [
            {"type": "field", "domain": [f"full:byname.{PROBE}"], "outboundTag": "echo"},
            {"type": "field", "ip": ["198.51.100.0/24", "2001:db8::/32"], "outboundTag": "echo"}])
        self.assertEqual(len(self.server["inbounds"]), 1)
        for case in self.cases.values():
            outbound = config(case)["outbounds"][0]
            self.assertEqual(outbound["settings"]["port"], self.server["inbounds"][0]["port"])
            self.assertEqual(config(case)["outbounds"][1], {"tag": "block", "protocol": "blackhole"})
            self.assertEqual(config(case)["routing"]["rules"][-1],
                             {"type": "field", "network": "tcp,udp", "outboundTag": "block"})

    def test_no_case_resolves_a_name(self):
        for case in self.cases.values():
            self.assertNotIn("dns", config(case))

    def test_the_cli_refuses_the_imported_decoy_without_the_sdk_start_path(self):
        self.assertEqual(loopback.CLI_EXPECTATIONS, {"saved-profile-migration": "refused"})
        case = self.cases["sniff:imported"]
        probe = case["sniffProbes"][0]
        self.assertEqual(outcome(config(case), self.server, probe, False), "refused")
        socks = loopback.sniff_config(case, 41999)
        self.assertEqual(socks["inbounds"][0]["sniffing"], IMPORTED["sniffing"])
        self.assertEqual(socks["inbounds"][0]["protocol"], "socks")


class ImportFixtureTests(unittest.TestCase):
    def setUp(self):
        self.server, self.envelope, _ = generate(self, "import-v011")

    def test_the_traffic_case_is_a_full_subscription(self):
        [case] = self.envelope["cases"]
        self.assertEqual(case["label"], "xray-json-subscription")
        value = config(case)
        self.assertEqual(value["stats"], {})
        self.assertEqual(value["api"]["tag"], "api")
        self.assertEqual(value["metrics"]["tag"], "metrics")
        self.assertEqual(value["routing"]["domainMatcher"], "hybrid")
        self.assertEqual(value["outbounds"][0]["streamSettings"]["tlsSettings"]["minVersion"], "1.2")
        self.assertEqual(value["outbounds"][0]["protocol"], "trojan")

    def test_the_plain_vmess_link_is_v2boards_websocket_link_with_fp(self):
        [item] = self.envelope["imports"]
        self.assertEqual((item["transition"], item["format"], item["serverAddress"]),
                         ("vmess-link-plain", "vmess", "127.0.0.1"))
        link = json.loads(base64.b64decode(item["text"].removeprefix("vmess://")))
        self.assertEqual((link["net"], link["tls"], link["fp"]), ("ws", "", "chrome"))

    def test_malformed_links_carry_the_marker_and_the_transitions_are_produced(self):
        marker = self.envelope["redactionMarker"]
        self.assertTrue(all(marker in item["text"] for item in self.envelope["invalidImports"]))
        self.assertLessEqual(len(self.envelope["invalidImports"]), 8)
        produced = {self.envelope["cases"][0]["label"], *(i["transition"] for i in self.envelope["imports"]),
                    "invalid-input-redaction"}
        self.assertEqual(produced, policy.IMPORT_TRANSITIONS)


class WireguardIdleTests(unittest.TestCase):
    def test_the_case_has_no_keepalive_and_nothing_else_reaches_the_device(self):
        server, envelope, root = generate(self, "wireguard-idle")
        [case] = envelope["cases"]
        self.assertEqual(case["label"], "wireguard:idle")
        self.assertNotIn("keepAlive", case["configJSON"])
        self.assertNotIn("PersistentKeepalive", case["text"])
        value = config(case)
        self.assertEqual([o["tag"] for o in value["outbounds"]], ["proxy", "block"])
        self.assertEqual(value["routing"]["rules"][-1], {"type": "field", "network": "tcp,udp", "outboundTag": "block"})
        self.assertEqual(value["dns"]["servers"], [{"address": "198.51.100.53", "port": 41003,
                                                    "domains": [f"full:{PROBE}"], "skipFallback": True}])
        # Five minutes of IDLE_CLOSE after a UDP flow's minute, with margin.
        self.assertGreaterEqual(case["idleRestartSeconds"], 360)

    def test_the_device_dials_the_relay_and_the_server_listens_behind_it(self):
        for port in (None, 53053):
            with self.subTest(port=port):
                server, envelope, root = generate(self, "wireguard-idle", port=port)
                relay = json.loads((root / device.WIREGUARD_WATCH).read_text())
                endpoint = config(envelope["cases"][0])["outbounds"][0]["settings"]["peers"][0]["endpoint"]
                self.assertEqual(endpoint, f"127.0.0.1:{relay['port']}")
                self.assertEqual((server["inbounds"][0]["listen"], server["inbounds"][0]["port"]),
                                 ("127.0.0.1", relay["upstream"]))
                self.assertNotEqual(relay["port"], relay["upstream"])
                if port:
                    self.assertEqual(relay["port"], port)

    def test_the_keepalive_case_is_unchanged(self):
        _, envelope, root = generate(self, "wireguard")
        self.assertIn('"keepAlive": 1', envelope["cases"][0]["configJSON"])
        self.assertFalse((root / device.WIREGUARD_WATCH).exists())
        self.assertNotIn("idleRestartSeconds", envelope["cases"][0])


class RelayTests(unittest.IsolatedAsyncioTestCase):
    async def test_relay_carries_both_ways_and_logs_sources_and_handshakes_only(self):
        loop = asyncio.get_running_loop()
        upstream, _ = await loop.create_datagram_endpoint(device.Echo, local_addr=("127.0.0.1", 0))
        with tempfile.TemporaryDirectory() as directory:
            log_path = Path(directory) / device.WIREGUARD_SOURCES
            with log_path.open("a") as log:
                relay, watch = await loop.create_datagram_endpoint(
                    lambda: device.WireguardWatch(("127.0.0.1", upstream.get_extra_info("sockname")[1]), log),
                    local_addr=("127.0.0.1", 0))
                address = relay.get_extra_info("sockname")
                try:
                    for message in (b"\x01" + b"h" * 147, b"\x04" + b"d" * 63):
                        for _ in range(2):
                            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                            client.setblocking(False)
                            with client:
                                client.sendto(message, address)
                                reply = await asyncio.wait_for(loop.sock_recv(client, 2048), 2)
                                self.assertEqual(reply, message)
                finally:
                    watch.close()
                    relay.close()
                    upstream.close()
            rows = restart.read(log_path)
        self.assertEqual([row["event"] for row in rows].count("new-source"), 4)
        self.assertEqual([row["event"] for row in rows].count("handshake-initiation"), 2)
        self.assertNotIn("hhhh", log_path.name + json.dumps(rows))


class RestartCheckTests(unittest.TestCase):
    rows = [{"time": 10.0, "event": "new-source", "source": "192.0.2.5:50000"},
            {"time": 10.1, "event": "handshake-initiation", "source": "192.0.2.5:50000"}]

    def test_a_handshake_from_a_new_source_after_the_idle_start_is_a_fresh_device(self):
        rows = self.rows + [{"time": 500.0, "event": "new-source", "source": "192.0.2.5:50001"},
                            {"time": 500.1, "event": "handshake-initiation", "source": "192.0.2.5:50001"}]
        self.assertTrue(restart.fresh_handshake(rows, 100.0)["fresh"])

    def test_the_same_source_or_a_new_one_before_the_idle_start_is_not(self):
        same = self.rows + [{"time": 500.1, "event": "handshake-initiation", "source": "192.0.2.5:50000"}]
        self.assertFalse(restart.fresh_handshake(same, 100.0)["fresh"])
        early = self.rows + [{"time": 50.0, "event": "handshake-initiation", "source": "192.0.2.5:50002"}]
        self.assertFalse(restart.fresh_handshake(early, 100.0)["fresh"])
        self.assertFalse(restart.fresh_handshake([], 100.0)["fresh"])

    def test_since_takes_the_probes_iso_time_and_malformed_rows_are_refused(self):
        self.assertEqual(restart.since_seconds("1970-01-01T00:01:40Z"), 100.0)
        self.assertEqual(restart.since_seconds("100"), 100.0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log.jsonl"
            path.write_text(json.dumps({"time": "x", "event": "new-source", "source": "a"}) + "\n")
            with self.assertRaises(ValueError):
                restart.read(path)


class HarnessWiringTests(unittest.TestCase):
    def test_android_case_ids_are_the_labels_and_only_the_idle_case_takes_a_port(self):
        for protocol, ids in [("sniff-v011", ["sniff-route-only", "sniff-imported", "sniff-name-dial"]),
                              ("import-v011", ["xray-json-subscription"]), ("wireguard-idle", ["wireguard-idle"])]:
            _, envelope, _ = generate(self, protocol, writer=android.write_fixtures)
            self.assertEqual([case["caseId"] for case in envelope["cases"]], ids)
        _, envelope, _ = generate(self, "wireguard-idle", port=53053, writer=android.write_fixtures)
        with self.assertRaisesRegex(ValueError, "WireGuard idle"):
            generate(self, "sniff-v011", port=53053, writer=android.write_fixtures)

    def test_reality_v011_is_vless_over_reality_alone(self):
        self.assertIn("reality-v011", acceptance.SINGLE_CASE_SUITES)
        self.assertIn("reality-v011", android.SINGLE_CASE_SUITES)
        with patch.object(acceptance, "original", side_effect=lambda root, *a, **kw: device.write_fixtures(
                root, *a, **{**kw, "protocol": "trojan"})), \
                patch.object(device, "openssl", side_effect=fake_openssl), \
                patch.object(acceptance.subprocess, "check_output", side_effect=lambda *a, **kw: b"k" * 48):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                acceptance.write_reality(root, "127.0.0.1", 41001, 41002, 41003, port=None, **KW)
                envelope = json.loads((root / "v07-probe.json").read_text())
        self.assertEqual([case["label"] for case in envelope["cases"]], ["vless-reality"])

    def test_the_loopback_check_has_a_suite_for_every_new_fixture(self):
        self.assertEqual(set(loopback.loopback.SUITES), {"sniff-v011", "import-v011", "wireguard-idle", "reality-v011"})
        self.assertIn("wireguard-sources.jsonl", loopback.loopback.KEPT)
        self.assertIs(loopback.loopback.check_case, loopback.check_case)

    def test_new_protocols_are_fixture_choices(self):
        self.assertEqual(device.V011_PROTOCOLS, ("sniff-v011", "import-v011", "wireguard-idle"))


if __name__ == "__main__":
    unittest.main()

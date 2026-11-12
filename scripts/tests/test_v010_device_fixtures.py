"""v0.10 device fixtures, their host services, the Android driver and the profile they serve."""
import argparse
import asyncio
import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import socket
import struct
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

SCRIPTS = Path(__file__).resolve().parents[1]


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


device = module("v010_device", "run-v07-apple-protocol-fixture.py")
android = module("v010_android", "run-v08-android-protocol-fixture.py")
acceptance = module("v010_acceptance", "run-v08-apple-acceptance-fixture.py")
driver = module("v010_driver", "run-v09-android-device-matrix.py")
loopback = module("v010_loopback", "check-v010-fixture-loopback.py")
policy = module("v010_policy", "check-v010-release-evidence.py")

KW = {"mode": "smoke", "probe_host": "v07-probe-abc.test"}
OPENSSL = shutil.which("openssl")
# What serve() hands the generator once its host services run.
SERVICES = {
    "realm": {"url": "realm+http://token@127.0.0.1:41010/v010-realm", "stun": "127.0.0.1:41011"},
    "xdrive": {"endpoint": "http://127.0.0.1:41012", "access": "V010ACCESS", "secret": "fixture-secret",
               "region": "eu-test-1", "bucket": "xdrive-fixture", "decryption": "dec", "encryption": "enc"},
}


def fake_openssl(*args):
    return b"k" * 32


def read(root):
    return (json.loads((root / "server.json").read_text()),
            json.loads((root / "v07-probe.json").read_text()))


def config(case):
    return json.loads(case["configJSON"])


def generate(test, protocol, port=None, writer=None, **extra):
    directory = tempfile.TemporaryDirectory()
    test.addCleanup(directory.cleanup)
    root = Path(directory.name)
    writer = writer or device.write_fixtures
    with patch.object(device, "openssl", side_effect=fake_openssl), \
            patch.object(android.fixture, "openssl", side_effect=fake_openssl):
        writer(root, "127.0.0.1", 41001, 41002, 41003, protocol=protocol, port=port, **KW, **extra)
    return read(root)


class CarrierPortTests(unittest.TestCase):
    def test_a_port_taken_for_udp_is_passed_over(self):
        """A carrier needs its port for TCP and UDP. The kernel may offer one
        that another process holds for UDP; the reservation takes the next."""
        while True:
            with socket.socket() as tcp:
                tcp.bind(("127.0.0.1", 0))
                taken = tcp.getsockname()[1]
            holder = socket.socket(type=socket.SOCK_DGRAM)
            try:
                holder.bind(("127.0.0.1", taken))
                break
            except OSError:
                holder.close()
        self.addCleanup(holder.close)
        offers = iter([taken])

        class Offering(socket.socket):
            def bind(self, address):
                if self.type == socket.SOCK_STREAM and address[1] == 0:
                    address = (address[0], next(offers, 0))
                super().bind(address)

        with patch.object(device.socket, "socket", Offering):
            port = device.reserve_carrier("127.0.0.1", set())
        self.assertNotEqual(port, taken)
        self.assertEqual(list(offers), [])  # the taken port was offered first


class FullSetFixtureTests(unittest.TestCase):
    def test_mkcp_and_masque_are_config_only_cases_on_their_own_ports(self):
        server, envelope = generate(self, "v010")
        self.assertEqual([c["label"] for c in envelope["cases"]], ["mkcp:vless", "masque:h3"])
        self.assertEqual([i["protocol"] for i in server["inbounds"]], ["vless", "masque"])
        self.assertEqual(len({i["port"] for i in server["inbounds"]}), 2)
        for case, inbound in zip(envelope["cases"], server["inbounds"]):
            self.assertEqual((case["format"], case["udp"], case["serverAddress"]), ("config", True, "127.0.0.1"))
            self.assertNotIn("text", case)  # no share link exists for either
            settings = config(case)["outbounds"][0]["settings"]
            self.assertEqual((settings["address"], settings["port"]), ("127.0.0.1", inbound["port"]))
            self.assertEqual(config(case)["dns"]["servers"], ["198.51.100.53:41003"])
        self.assertFalse({"invalidImports", "imports"} & set(envelope))

    def test_mkcp_is_plain_vless_in_the_flat_form(self):
        server, envelope = generate(self, "mkcp", port=41020)
        outbound, inbound = config(envelope["cases"][0])["outbounds"][0], server["inbounds"][0]
        self.assertEqual((inbound["port"], inbound["streamSettings"]), (41020, {"network": "kcp"}))
        self.assertEqual(outbound["streamSettings"], {"network": "kcp"})
        self.assertEqual(outbound["settings"], {"address": "127.0.0.1", "port": 41020,
                                                "id": inbound["settings"]["clients"][0]["id"], "encryption": "none"})

    def test_masque_is_pinned_http3_with_datagrams_its_tunnel_carries(self):
        server, envelope = generate(self, "masque")
        case, inbound = envelope["cases"][0], server["inbounds"][0]
        stream, user = config(case)["outbounds"][0]["streamSettings"], inbound["settings"]["users"][0]
        self.assertEqual((stream["network"], stream["security"]), ("masque", "tls"))
        self.assertEqual(stream["tlsSettings"]["alpn"], ["h3"])
        self.assertRegex(stream["tlsSettings"]["pinnedPeerCertSha256"], "^[0-9a-f]{64}$")
        self.assertNotIn("allowInsecure", stream["tlsSettings"])
        self.assertEqual((stream["masqueSettings"]["user"], stream["masqueSettings"]["pass"]),
                         (user["email"], user["pass"]))
        self.assertEqual(stream["masqueSettings"]["path"], inbound["streamSettings"]["masqueSettings"]["path"])
        # A 1280-byte packet less the IP and UDP headers of each family.
        self.assertEqual(case["udpPayloadBytes"], [1280 - 20 - 8, 1280 - 40 - 8])
        self.assertNotIn("udpPayloadBytes", generate(self, "mkcp")[1]["cases"][0])


class SmokeFixtureTests(unittest.TestCase):
    def setUp(self):
        self.server, self.envelope = generate(self, "smoke-v010", services=SERVICES)
        self.cases = {case["label"]: case for case in self.envelope["cases"]}

    def outbound(self, label):
        return config(self.cases[label])["outbounds"][0]

    def inbound(self, label):
        port = self.outbound(label)["settings"]["port"]
        return next(i for i in self.server["inbounds"] if i["port"] == port)

    def test_every_smoke_scenario_but_xicmp_has_one_case(self):
        self.assertEqual(list(self.cases), ["xdns:mkcp", "realm:mkcp", "sudoku:tcp", "xmc:tcp",
                                            "header-custom:tcp", "xdrive:s3", "vless-reverse:bridge"])
        ports = [i["port"] for i in self.server["inbounds"]]
        self.assertEqual(len(ports), len(set(ports)))
        for case in self.cases.values():
            self.assertNotIn("text", case)
            self.assertTrue(case["udp"])

    def test_tcp_masks_are_the_same_on_both_sides_of_raw_vless(self):
        for label in ["sudoku:tcp", "xmc:tcp"]:
            client, server = self.outbound(label)["streamSettings"], self.inbound(label)["streamSettings"]
            self.assertEqual(client, server, label)
            self.assertEqual(client["network"], "raw")
            self.assertEqual([m["type"] for m in client["finalmask"]["tcp"]], [label.split(":")[0]])
        passwords = {self.outbound(label)["streamSettings"]["finalmask"]["tcp"][0]["settings"]["password"]
                     for label in ["sudoku:tcp", "xmc:tcp"]}
        self.assertEqual(len(passwords), 2)

    def test_header_custom_reads_the_carrier_port_from_each_side(self):
        metadata = lambda stream: stream["finalmask"]["tcp"][0]["settings"]["clients"][0][2]["transform"]["args"]
        self.assertEqual(metadata(self.outbound("header-custom:tcp")["streamSettings"]), [{"metadata": "remote_port"}])
        self.assertEqual(metadata(self.inbound("header-custom:tcp")["streamSettings"]), [{"metadata": "local_port"}])

    def test_xdns_asks_the_inbound_itself_and_the_server_names_no_resolver(self):
        client = self.outbound("xdns:mkcp")
        mask = client["streamSettings"]["finalmask"]["udp"][0]["settings"]
        self.assertEqual(client["streamSettings"]["network"], "kcp")
        self.assertEqual(mask["resolvers"], [{"addrs": [f"127.0.0.1:{client['settings']['port']}"]}])
        server = self.inbound("xdns:mkcp")["streamSettings"]["finalmask"]["udp"][0]["settings"]
        self.assertEqual(server["domains"][0]["names"], mask["domains"][0]["names"])
        self.assertNotIn("resolvers", server)

    def test_realm_reaches_the_server_only_through_the_introduction(self):
        client = self.outbound("realm:mkcp")
        mask = client["streamSettings"]["finalmask"]["udp"][0]
        self.assertEqual(mask["settings"]["url"], SERVICES["realm"]["url"])
        self.assertEqual(mask["settings"]["stunServers"], [SERVICES["realm"]["stun"]])
        registered = [i for i in self.server["inbounds"]
                      if i["streamSettings"].get("finalmask", {}).get("udp", [{}])[0].get("type") == "realm"]
        self.assertEqual(len(registered), 1)
        self.assertEqual(registered[0]["streamSettings"]["finalmask"]["udp"][0], mask)
        # The outbound names a port nothing listens on.
        self.assertNotIn(client["settings"]["port"], [i["port"] for i in self.server["inbounds"]])
        self.assertEqual(client["settings"]["id"], registered[0]["settings"]["clients"][0]["id"])

    def test_xdrive_meets_its_server_in_the_stand_ins_bucket(self):
        client, server = self.outbound("xdrive:s3"), self.inbound("xdrive:s3")
        self.assertEqual(client["streamSettings"], server["streamSettings"])
        xdrive = client["streamSettings"]["xdriveSettings"]
        self.assertEqual((xdrive["service"], xdrive["s3"]["endpoint"], xdrive["s3"]["bucket"]),
                         ("s3", SERVICES["xdrive"]["endpoint"], "xdrive-fixture"))
        self.assertEqual(xdrive["secrets"], ["V010ACCESS", "fixture-secret"])
        self.assertTrue(xdrive["s3"]["endpoint"].startswith("http://127.0.0.1:"))  # the fixture host, no cloud
        self.assertEqual((server["settings"]["decryption"], client["settings"]["encryption"]), ("dec", "enc"))
        self.assertTrue(client["mux"]["enabled"])
        self.assertNotIn("flow", client["settings"])

    def test_the_bridge_serves_its_own_probe_traffic_through_the_portal(self):
        case = self.cases["vless-reverse:bridge"]
        proxy, portal, home = config(case)["outbounds"]
        inbounds = {i.get("tag"): i for i in self.server["inbounds"]}
        entry, tunnel = inbounds["reverse-entry"], inbounds["reverse-portal"]
        # The device's traffic enters as an ordinary client of the portal...
        self.assertEqual((proxy["tag"], proxy["settings"]["port"], proxy["settings"]["id"]),
                         ("proxy", entry["port"], entry["settings"]["clients"][0]["id"]))
        self.assertNotIn("reverse", proxy["settings"])
        # ...which sends all of it into the tunnel the bridge keeps open...
        self.assertEqual(self.server["routing"]["rules"][0],
                         {"type": "field", "inboundTag": ["reverse-entry"], "outboundTag": "r-out"})
        self.assertEqual(tunnel["settings"]["clients"][0], {"id": portal["settings"]["id"], "reverse": {"tag": "r-out"}})
        self.assertEqual((portal["settings"]["port"], portal["settings"]["reverse"]),
                         (tunnel["port"], {"tag": "from-portal"}))
        self.assertNotEqual(proxy["settings"]["id"], portal["settings"]["id"])
        # ...and the bridge's sessions leave through a freedom that reaches only the fixture.
        self.assertEqual(config(case)["routing"]["rules"][0],
                         {"type": "field", "inboundTag": ["from-portal"], "outboundTag": "home"})
        self.assertEqual(home, {"tag": "home", "protocol": "freedom", "settings": {
            "redirect": "127.0.0.1:0", "finalRules": [{"action": "allow", "ip": ["127.0.0.1"]}]}})
        self.assertEqual(case["settleSeconds"], 5)
        self.assertFalse([c for label, c in self.cases.items() if label != "vless-reverse:bridge"
                          and "settleSeconds" in c])

    def test_xicmp_runs_alone_with_datagram_sockets_on_the_client(self):
        server, envelope = generate(self, "xicmp")
        self.assertEqual([c["label"] for c in envelope["cases"]], ["xicmp:mkcp"])
        client = config(envelope["cases"][0])["outbounds"][0]["streamSettings"]["finalmask"]["udp"][0]["settings"]
        self.assertEqual(client, {"dgram": True, "ips": ["127.0.0.1"]})
        self.assertEqual(server["inbounds"][0]["streamSettings"]["finalmask"]["udp"][0]["settings"], {"dgram": False})
        self.assertNotIn("xicmp", device.V010_SMOKE)

    def test_unknown_v010_protocol_and_missing_services_fail(self):
        with self.assertRaises(ValueError):
            device.v010_case("xtls", "127.0.0.1", 1, lambda: 2, "00" * 32, [], {})
        with self.assertRaises(KeyError):
            generate(self, "realm")


class ImportFixtureTests(unittest.TestCase):
    def setUp(self):
        self.server, self.envelope = generate(self, "import-v010")

    def test_one_link_of_each_new_kind_names_the_fixture_address(self):
        rows = self.envelope["imports"]
        self.assertEqual([(r["transition"], r["format"]) for r in rows], [
            ("vless-link", "vless"), ("trojan-link", "trojan"), ("vmess-link", "vmess"),
            ("hysteria2-link", "hysteria2")])
        for row in rows:
            link = urlsplit(row["text"])
            self.assertEqual((link.hostname, row["serverAddress"]), ("127.0.0.1", "127.0.0.1"))
            self.assertNotIn(self.envelope["redactionMarker"], row["text"])
        query = lambda index: parse_qs(urlsplit(rows[index]["text"]).query)
        self.assertEqual((query(0)["type"], query(0)["security"]), (["ws"], ["tls"]))
        self.assertEqual((query(1)["type"], query(1)["mode"]), (["grpc"], ["gun"]))
        self.assertRegex(query(1)["pcs"][0], "^[0-9a-f]{64}$")
        self.assertTrue(rows[2]["text"].startswith("vmess://") and "@" in rows[2]["text"])  # the URI form
        self.assertEqual(query(3)["pinSHA256"], query(1)["pcs"])

    def test_the_traffic_case_is_a_remnawave_profile(self):
        self.assertEqual([c["label"] for c in self.envelope["cases"]], ["remnawave-json"])
        case = self.envelope["cases"][0]
        profile = config(case)
        self.assertEqual(list(profile)[:2], ["remarks", "meta"])
        self.assertIsInstance(profile["meta"], dict)
        tls = profile["outbounds"][0]["streamSettings"]["tlsSettings"]
        self.assertIs(tls["enableSessionResumption"], False)
        self.assertRegex(tls["pinnedPeerCertSha256"], "^[0-9a-f]{64}$")
        self.assertEqual((case["format"], profile["outbounds"][0]["protocol"]), ("config", "trojan"))
        self.assertNotIn("text", case)
        self.assertEqual([i["protocol"] for i in self.server["inbounds"]], ["trojan"])

    def test_a_malformed_link_of_each_kind_carries_the_marker(self):
        marker = self.envelope["redactionMarker"]
        rows = self.envelope["invalidImports"]
        self.assertEqual([(r["scenario"], r["format"]) for r in rows], [
            ("vless-link", "vless"), ("trojan-link", "trojan"), ("vmess-link", "vmess"),
            ("hysteria2-link", "hysteria2")])
        for row in rows:
            self.assertIn(marker, row["text"])

    def test_profile_import_transitions_are_all_produced(self):
        produced = {r["transition"] for r in self.envelope["imports"]} | {self.envelope["cases"][0]["label"]}
        self.assertEqual(produced | {"invalid-input-redaction"}, policy.IMPORT_TRANSITIONS)


class HostServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_stun_reports_the_senders_address(self):
        loop = asyncio.get_running_loop()
        server, _ = await loop.create_datagram_endpoint(device.Stun, local_addr=("127.0.0.1", 0))
        replies = asyncio.Queue()

        class Client(asyncio.DatagramProtocol):
            def datagram_received(self, data, address):
                replies.put_nowait(data)

        client, _ = await loop.create_datagram_endpoint(Client, remote_addr=server.get_extra_info("sockname"))
        try:
            transaction = bytes(range(12))
            client.sendto(b"\x00\x01\x00\x00" + device.STUN_MAGIC + transaction)
            client.sendto(b"\x00\x01\x00\x00" + b"\x00" * 16)  # no magic cookie: ignored
            reply = await asyncio.wait_for(replies.get(), 2)
            self.assertEqual(reply[:2], b"\x01\x01")
            self.assertEqual(struct.unpack("!H", reply[2:4])[0], len(reply) - 20)
            self.assertEqual(reply[4:20], device.STUN_MAGIC + transaction)
            kind, length, _, family, port = struct.unpack("!HHBBH", reply[20:28])
            self.assertEqual((kind, length, family), (0x0020, 8, 1))
            self.assertEqual(port ^ 0x2112, client.get_extra_info("sockname")[1])
            address = bytes(a ^ b for a, b in zip(reply[28:32], device.STUN_MAGIC))
            self.assertEqual(address, bytes([127, 0, 0, 1]))
            self.assertTrue(replies.empty())
        finally:
            client.close()
            server.close()

    async def call(self, port, method, path, bearer, body=None):
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        payload = json.dumps(body).encode() if body is not None else b""
        writer.write(f"{method} {path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer {bearer}\r\n"
                     f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload)
        status = (await reader.readline()).decode().split(" ", 1)[1].strip()
        length = 0
        while (line := (await reader.readline()).decode().strip()):
            if line.lower().startswith("content-length:"):
                length = int(line.split(":")[1])
        answer = json.loads(await reader.readexactly(length)) if length else None
        return status, answer, reader, writer

    async def test_rendezvous_introduces_a_client_to_the_registered_server(self):
        rendezvous = device.Rendezvous("token")
        server = await asyncio.start_server(rendezvous.handle, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        writers = []
        try:
            status, _, _, writer = await self.call(port, "POST", "/v1/home", "wrong", {"addresses": ["192.0.2.1:1"]})
            writers.append(writer)
            self.assertEqual(status, "401 Unauthorized")
            self.assertNotIn("home", rendezvous.realms)
            status, answer, _, writer = await self.call(port, "POST", "/v1/home", "token", {"addresses": ["192.0.2.1:1"]})
            writers.append(writer)
            session = answer["session_id"]
            self.assertEqual((status, answer["ttl"]), ("200 OK", 60))
            self.assertIn("home", rendezvous.realms)
            # The server's event stream, opened with its session.
            status, _, events, writer = await self.call(port, "GET", "/v1/home/events", session)
            writers.append(writer)
            self.assertEqual(status, "200 OK")
            offer = {"addresses": ["198.51.100.9:9"], "nonce": "n1", "obfs": "key"}
            connect = asyncio.create_task(self.call(port, "POST", "/v1/home/connect", "token", offer))
            self.assertEqual(await asyncio.wait_for(events.readline(), 2), b"event: punch\n")
            pushed = json.loads((await events.readline()).decode().removeprefix("data: "))
            self.assertEqual(pushed, offer)
            # The server answers the attempt with the addresses it has now.
            status, _, _, writer = await self.call(port, "POST", "/v1/home/connects/n1", session,
                                                    {"addresses": ["192.0.2.1:2"]})
            writers.append(writer)
            self.assertEqual(status, "204 No Content")
            status, answer, _, writer = await asyncio.wait_for(connect, 2)
            writers.append(writer)
            self.assertEqual((status, answer), ("200 OK", {"addresses": ["192.0.2.1:2"], "nonce": "n1", "obfs": "key"}))
            # No such realm, and an attempt nobody is waiting for.
            status, answer, _, writer = await self.call(port, "POST", "/v1/away/connect", "token", offer)
            writers.append(writer)
            self.assertEqual((status, answer["error"]), ("404 Not Found", "realm_not_found"))
            status, _, _, writer = await self.call(port, "POST", "/v1/home/connects/n1", session, {})
            writers.append(writer)
            self.assertEqual(status, "404 Not Found")
            status, _, _, writer = await self.call(port, "POST", "/v1/home/heartbeat", session,
                                                    {"addresses": ["192.0.2.1:3"]})
            writers.append(writer)
            self.assertEqual(rendezvous.sessions[session]["addresses"], ["192.0.2.1:3"])
        finally:
            for writer in writers:
                writer.close()
            server.close()

    def stub(self, directory, name, script):
        path = Path(directory) / name
        path.write_text("#!/bin/sh\n" + script)
        path.chmod(0o700)
        return path

    async def test_xdrive_fixture_starts_the_stand_in_and_leaves_no_secret_behind(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture"
            output.mkdir()
            xray = self.stub(directory, "xray", 'if [ "$1" = vlessenc ]; then\n'
                             'printf \'Authentication: X25519, not Post-Quantum\\n"decryption": "dec-x"\\n'
                             '"encryption": "enc-x"\\n\\nAuthentication: ML-KEM-768, Post-Quantum\\n'
                             '"decryption": "dec-m"\\n"encryption": "enc-m"\\n\'\nexit 0\nfi\nexec sleep 30\n')
            # Like the stand-in: its address on stdout, a line per request on stderr.
            standin = self.stub(directory, "standin", 'echo "$@" > "$0.args"\n'
                                'echo \'{"http":"127.0.0.1:41012"}\'\n'
                                'echo "served HTTP/1.1 PUT x /k 200" >&2\necho "refused PUT /k : bad signature" >&2\n'
                                'exec sleep 30\n')
            written, generator = {}, device.write_fixtures

            def write(*args, **kwargs):
                with patch.object(device, "openssl", side_effect=fake_openssl):
                    generator(*args, **kwargs)
                written.update(zip(("server", "envelope"), read(output)))

            args = argparse.Namespace(output=output, bind="127.0.0.1", protocol="xdrive", port=None, mode="smoke",
                                      seconds=1, reference_binary=xray, xdrive_standin=standin)
            with patch.object(device, "write_fixtures", side_effect=write), patch("builtins.print"):
                await device.serve(args)
            launched = Path(str(standin) + ".args").read_text().split()
            log = (output / "xdrive-standin.log").read_text()
            remaining = sorted(p.name for p in output.iterdir())
        xdrive = written["server"]["inbounds"][0]["streamSettings"]["xdriveSettings"]
        self.assertEqual((xdrive["s3"]["endpoint"], written["server"]["inbounds"][0]["settings"]["decryption"]),
                         ("http://127.0.0.1:41012", "dec-x"))
        self.assertEqual(config(written["envelope"]["cases"][0])["outbounds"][0]["settings"]["encryption"], "enc-x")
        # The stand-in checks the keys the configs carry, on the bind address.
        self.assertEqual(launched[launched.index("-listen") + 1], "127.0.0.1:0")
        self.assertEqual([launched[launched.index("-access") + 1], launched[launched.index("-secret") + 1]],
                         xdrive["secrets"])
        self.assertEqual(log, "refused PUT /k : bad signature\n")  # refusals kept, the request log dropped
        self.assertEqual(remaining, ["server.log", "xdrive-standin.log"])

    def test_xicmp_fixture_refuses_to_start_without_raw_icmp_sockets(self):
        with patch.object(device.socket, "socket", side_effect=PermissionError):
            with self.assertRaisesRegex(SystemExit, "raw ICMP"):
                device.require_raw_icmp()


@unittest.skipUnless(OPENSSL, "openssl is required for the legacy key generators")
class LegacyV010Tests(unittest.TestCase):
    def legacy(self, writer=acceptance.write_legacy_v010, **extra):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        writer(root, "127.0.0.1", 1, 2, 3, **{"protocol": "both", "port": None, **KW, **extra})
        return read(root)

    def test_legacy_v010_is_every_protocol_v090_shipped(self):
        server, envelope = self.legacy()
        labels = [c["label"] for c in envelope["cases"]]
        self.assertEqual(set(labels), policy.LEGACY_PROTOCOLS)
        self.assertEqual(len(labels), 12)
        ports = [i["port"] for i in server["inbounds"]]
        self.assertEqual((len(ports), len(set(ports))), (12, 12))  # the HTTPS inbound is dropped with its case
        cases = {c["label"]: c for c in envelope["cases"]}
        self.assertIs(cases["http"]["udp"], False)
        self.assertEqual(config(cases["http"])["outbounds"][0]["streamSettings"], {"network": "raw"})
        self.assertTrue(all(c.get("udp", True) for label, c in cases.items() if label != "http"))
        self.assertTrue(cases["socks"]["text"].startswith("socks5://"))

    def test_hysteria2_and_xhttp_h3_keep_chrome_parrot(self):
        _, envelope = self.legacy()
        cases = {c["label"]: c for c in envelope["cases"]}
        for label in ["hysteria2", "xhttp-h3"]:
            self.assertNotIn("disableChromeParrot", cases[label]["configJSON"], label)
        self.assertNotIn("disableChromeParrot", json.dumps(envelope))

    def test_xhttp_h3_alone_takes_a_wan_port(self):
        server, envelope = self.legacy(acceptance.write_xhttp_h3, port=41443)
        self.assertEqual([c["label"] for c in envelope["cases"]], ["xhttp-h3"])
        self.assertEqual([i["port"] for i in server["inbounds"]], [41443])
        outbound = config(envelope["cases"][0])["outbounds"][0]
        self.assertEqual(outbound["settings"]["vnext"][0]["port"], 41443)
        self.assertEqual(outbound["streamSettings"]["tlsSettings"]["alpn"], ["h3"])

    def test_android_legacy_case_ids_are_the_transition_names(self):
        for suite, expected, extra in [("legacy-v010", policy.LEGACY_PROTOCOLS, {}),
                                       ("xhttp-h3-v010", {"xhttp-h3"}, {"port": 41443})]:
            writer = lambda *a, suite=suite, **kw: android.write_regression(*a, suite=suite, **kw)
            _, envelope = self.legacy(writer, **extra)
            self.assertEqual({c["caseId"] for c in envelope["cases"]}, expected)
        with self.assertRaisesRegex(ValueError, "dynamically allocated"):
            self.legacy(lambda *a, **kw: android.write_regression(*a, suite="legacy-v010", **kw), port=41443)


class AndroidV010FixtureTests(unittest.TestCase):
    def test_case_ids_are_the_labels_and_only_one_carrier_takes_a_port(self):
        _, envelope = generate(self, "v010", writer=android.write_fixtures)
        self.assertEqual([c["caseId"] for c in envelope["cases"]], ["mkcp-vless", "masque-h3"])
        _, envelope = generate(self, "smoke-v010", writer=android.write_fixtures, services=SERVICES)
        self.assertEqual([c["caseId"] for c in envelope["cases"]], [
            "xdns-mkcp", "realm-mkcp", "sudoku-tcp", "xmc-tcp", "header-custom-tcp", "xdrive-s3",
            "vless-reverse-bridge"])
        _, envelope = generate(self, "import-v010", writer=android.write_fixtures)
        self.assertEqual([c["caseId"] for c in envelope["cases"]], ["remnawave-json"])
        self.assertEqual(len(envelope["imports"]), 4)
        server, _ = generate(self, "masque", port=41443, writer=android.write_fixtures)
        self.assertEqual([i["port"] for i in server["inbounds"]], [41443])
        with self.assertRaisesRegex(ValueError, "one v0.10 carrier"):
            generate(self, "v010", port=41443, writer=android.write_fixtures)
        with self.assertRaises(ValueError):
            generate(self, "v08", port=41443, writer=android.write_fixtures)


class ProfileCoverageTests(unittest.TestCase):
    """Every scenario of the v0.10 profile has a fixture case, and no more."""

    def test_fixture_labels_are_the_profiles_protocol_scenarios(self):
        scenarios = {label.split(":")[0] for label in device.V010_LABELS.values()}
        self.assertEqual(scenarios, policy.FULL_PROTOCOLS | policy.SMOKE_PROTOCOLS)
        self.assertEqual(set(device.V010_FULL), policy.FULL_PROTOCOLS)
        self.assertEqual(set(device.V010_SMOKE) | set(device.V010_PRIVILEGED), policy.SMOKE_PROTOCOLS)
        self.assertEqual(set(device.V010_LABELS), set(device.V010_PROTOCOLS))

    def test_android_backends_are_the_profiles_and_network_change_names_its_ids(self):
        self.assertEqual({f"{protocol}-{backend}" for protocol in device.V010_FULL for backend in driver.BACKENDS},
                         set(policy.ANDROID_PROTOCOL_SCENARIOS))
        self.assertEqual(driver.network_transitions("mkcp-vless"), ["wifi-cellular-wifi"])
        self.assertEqual(driver.network_transitions("xhttp-h3"), ["wifi-cellular-wifi", "xhttp-h3-network-change"])
        self.assertIn("xhttp-h3-network-change", policy.LEGACY_TRANSITIONS)
        self.assertIn("wifi-cellular-wifi", policy.POLICY.transitions("masque-packet-pump"))

    def test_the_loopback_check_has_a_suite_for_every_new_case(self):
        fixtures = {"run-v07-apple-protocol-fixture.py": device.GROUPS, "run-v08-apple-acceptance-fixture.py": {}}
        covered = set()
        for suite, (script, arguments) in loopback.loopback.SUITES.items():
            self.assertIn(script, fixtures, suite)
            covered |= set(device.GROUPS.get(arguments[1], (arguments[1],)))
        self.assertLessEqual(set(device.V010_PROTOCOLS), covered)
        self.assertLessEqual({"import-v010", "legacy-v010", "xhttp-h3-v010"}, covered)
        # The Apple probe's datagram sizes, and the reverse bridge's wait.
        self.assertEqual(loopback.loopback.UDP_PAYLOADS, (1392, 1372))
        self.assertIn("xdrive-standin.log", loopback.loopback.KEPT)


class FakeClock:
    """The driver's clock: sleeping advances it, so deadlines pass at once."""

    def __init__(self):
        self.now, self.slept = 0.0, []

    def monotonic(self):
        self.now += 0.01
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds

    @staticmethod
    def time():
        return driver_time.time()


import time as driver_time  # noqa: E402  (the real clock behind FakeClock.time)


class AndroidDriverV010Tests(unittest.TestCase):
    def drive(self, envelope, *arguments, serial="R58XXXXXXXX", **fake):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        (root / "v07-probe.json").write_text(json.dumps(envelope))
        environment = {"ANDROID_SERIAL": serial, "ADB": str(SCRIPTS / "tests/fixtures/fake-adb.py"),
                       "FAKE_ADB_STATE": str(root / "adb.json"), **fake}
        argv = ["driver", "--fixture", str(root / "v07-probe.json"), "--work-dir", str(root / "run"),
                "--package-suffix", ".v010", "--warmup-seconds", "0", *arguments]
        self.clock = FakeClock()
        with patch.dict("os.environ", environment), patch("sys.argv", argv), \
                patch.object(driver, "time", self.clock), patch("builtins.print"):
            try:
                driver.main()
            finally:
                log, adb = root / "run/events.jsonl", root / "adb.json"
                self.events = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
                self.state = json.loads(adb.read_text()) if adb.exists() else {"argv": []}
        return self.events

    def commands(self):
        return [shlex.split(argv[1]) for argv in self.state["argv"] if argv[0] == "shell"]

    def envelope(self, protocol, **extra):
        return generate(self, protocol, writer=android.write_fixtures, **extra)[1]

    def test_config_only_cases_skip_the_link_and_the_bridge_settles(self):
        envelope = self.envelope("smoke-v010", services=SERVICES)
        events = self.drive(envelope, "--case", "sudoku-tcp", "--case", "vless-reverse-bridge")
        self.assertEqual([(e["case"], e["backend"]) for e in events if e["kind"] == "case-pass"], [
            ("sudoku-tcp", "file-descriptor"), ("sudoku-tcp", "packet-pump"),
            ("vless-reverse-bridge", "file-descriptor"), ("vless-reverse-bridge", "packet-pump")])
        self.assertFalse([e for e in events if e["kind"] == "share-link-import"])
        skipped = [e for e in events if e["kind"] == "share-link-import-not-supported"]
        self.assertEqual(len(skipped), 4)
        self.assertTrue(all("no share link" in e["scope"] for e in skipped))
        pending = [c[-1] for c in self.commands() if c[:1] == ["run-as"] and c[2:4] == ["sh", "-c"]]
        self.assertEqual(set(pending), {"cat > no_backup/profile-config-import.pending"})
        # Two connects a backend for the bridge, five seconds after each; none for sudoku.
        self.assertEqual(self.clock.slept.count(5), 4)
        ids = {t for e in events if e["kind"] == "traffic" for t in e["transitions"]}
        self.assertEqual(ids, {"ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination", "routed-dns"})
        self.assertEqual(events[-1]["kind"], "matrix-pass")

    def test_links_import_on_their_own_and_malformed_ones_are_refused(self):
        envelope = self.envelope("import-v010")
        events = self.drive(envelope, "--backend", "file-descriptor")
        self.assertEqual([e["backend"] for e in events if e["kind"] == "case-pass"], ["file-descriptor"])
        self.assertEqual([(e["transition"], e["passed"]) for e in events if e["kind"] == "link-import"], [
            ("vless-link", True), ("trojan-link", True), ("vmess-link", True), ("hysteria2-link", True)])
        controls = [(e["scenario"], e["passed"]) for e in events if e["kind"] == "invalid-import-control"]
        self.assertEqual(controls, [("vless-link", True), ("trojan-link", True), ("vmess-link", True),
                                    ("hysteria2-link", True)])
        kinds = [e["kind"] for e in events]
        self.assertLess(kinds.index("matrix-pass"), kinds.index("link-import"))
        self.assertLess(kinds.index("link-imports-complete"), kinds.index("invalid-import-control"))
        self.assertEqual(kinds[-1], "controls-complete")
        # Links only travel through stdin.
        arguments = json.dumps(self.state["argv"])
        for row in envelope["imports"] + envelope["invalidImports"]:
            self.assertNotIn(row["text"], arguments)

    def test_network_change_needs_recovery_on_both_networks_and_a_rebind_request(self):
        events = self.drive(self.envelope("mkcp", port=41443), "--network-change")
        recovered = [(e["backend"], e["stage"], e["transitions"]) for e in events if e["kind"] == "transition-recovered"]
        self.assertEqual(recovered, [(backend, stage, ["wifi-cellular-wifi"])
                                     for backend in driver.BACKENDS for stage in ("cellular", "wifi")])
        changes = [e for e in events if e["kind"] == "network-change"]
        self.assertEqual([(e["rebindRequests"], e["changeErrors"]) for e in changes], [(2, 0), (2, 0)])
        self.assertTrue(events[0]["networkChange"])
        wifi = [c[2] for c in self.commands() if c[:2] == ["svc", "wifi"]]
        self.assertEqual(wifi, ["disable", "enable", "enable"] * 2)  # always left on
        # Traffic was probed while Wi-Fi was off, between the two switches.
        commands = self.commands()
        off, on = commands.index(["svc", "wifi", "disable"]), commands.index(["svc", "wifi", "enable"])
        self.assertTrue([c for c in commands[off:on] if c[:2] == ["am", "start"] and "start" in c])
        self.assertEqual(events[-1]["kind"], "matrix-pass")

    def test_xhttp_h3_network_change_names_the_legacy_transition(self):
        envelope = {"tcpPort": 1, "udpPort": 2, "probeHost": "p.test", "cases": [{
            "format": "vless", "caseId": "xhttp-h3", "text": "vless://u@127.0.0.1:1",
            "configJSON": json.dumps({"inbounds": [{}], "outbounds": [{"protocol": "vless"}]})}]}
        events = self.drive(envelope, "--network-change", "--backend", "packet-pump")
        ids = [e["transitions"] for e in events if e["kind"] in ("transition-recovered", "network-change")]
        self.assertEqual(ids, [["wifi-cellular-wifi", "xhttp-h3-network-change"]] * 3)
        self.assertTrue([e for e in events if e["kind"] == "share-link-import"])

    def test_no_rebind_a_restart_or_a_dead_network_fails_the_case(self):
        envelope = self.envelope("mkcp", port=41443)
        for fake, message in [({"FAKE_ADB_REBIND": "none"}, "0 rebind requests"),
                              ({"FAKE_ADB_REBIND": "restart"}, "restarted during the network change"),
                              ({"FAKE_ADB_CELLULAR": "dead"}, "HTTP failure")]:
            with self.subTest(**fake):
                with self.assertRaisesRegex(RuntimeError, message):
                    self.drive(envelope, "--network-change", **fake)
                self.assertEqual([e["kind"] for e in self.events if e["kind"] in ("case-fail", "matrix-pass")],
                                 ["case-fail"])
                # Whatever failed, Wi-Fi is switched back on.
                self.assertEqual([c[2] for c in self.commands() if c[:2] == ["svc", "wifi"]][-1], "enable")
        retried = [e for e in self.events if e["kind"] == "recovery-retry"]
        self.assertTrue(retried and all(e["stage"] == "cellular" for e in retried))

    def test_network_change_refuses_adb_over_the_network(self):
        envelope = self.envelope("mkcp", port=41443)
        for serial in ["192.168.1.20:5555", "adb-R58XXXXXXXX-abcdef._adb-tls-connect._tcp"]:
            with self.assertRaises(SystemExit):
                self.drive(envelope, "--network-change", serial=serial)
            self.assertEqual(self.state["argv"], [])
        # Without the step the same serial runs the matrix.
        self.drive(envelope, "--backend", "file-descriptor", serial="192.168.1.20:5555")
        self.assertEqual(self.events[-1]["kind"], "matrix-pass")
        self.assertFalse([c for c in self.commands() if c[:2] == ["svc", "wifi"]])


if __name__ == "__main__":
    unittest.main()

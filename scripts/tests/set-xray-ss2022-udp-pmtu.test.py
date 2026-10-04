#!/usr/bin/env python3
"""Selection guards for the privileged, startup-only SS2022 socket helper."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("pmtu", ROOT / "scripts/set-xray-ss2022-udp-pmtu.py")
pmtu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pmtu)


class Guards(unittest.TestCase):
    def config(self, method="2022-blake3-chacha20-poly1305", network="tcp,udp"):
        return {"inbounds": [{"protocol": "shadowsocks", "port": 53053,
                              "settings": {"method": method, "network": network}}]}

    def test_three_native_methods(self):
        for method in ("2022-blake3-chacha20-poly1305", "2022-blake3-aes-128-gcm",
                       "2022-blake3-aes-256-gcm"):
            pmtu.validate_config(self.config(method), 53053)

    def test_refuses_unrelated_protocol_and_legacy(self):
        for protocol, method in (("trojan", "2022-blake3-aes-128-gcm"),
                                 ("shadowsocks", "aes-128-gcm")):
            config = self.config(method)
            config["inbounds"][0]["protocol"] = protocol
            with self.assertRaises(ValueError):
                pmtu.validate_config(config, 53053)

    def test_udp_must_be_explicit(self):
        for network in ("tcp", "not-udp", ""):
            with self.assertRaises(ValueError):
                pmtu.validate_config(self.config(network=network), 53053)

    def test_wrong_port_and_duplicate_listener_refused(self):
        with self.assertRaises(ValueError):
            pmtu.validate_config(self.config(), 53054)
        config = self.config()
        config["inbounds"] *= 2
        with self.assertRaises(ValueError):
            pmtu.validate_config(config, 53053)

    def test_process_requires_exact_single_config_path(self):
        config = Path("/tmp/owned/server.json")
        valid = [b"/usr/local/bin/xray", b"run", b"-config", bytes(config)]
        self.assertTrue(pmtu.command_matches(valid, config))
        for other in (valid[:-1] + [b"/etc/production.json"], valid + [b"-config", b"other"],
                      [valid[0], b"version"], valid[:-2] + [b"-confdir", b"/tmp/owned"]):
            self.assertFalse(pmtu.command_matches(other, config))

    def test_no_root_or_unbounded_cgroup(self):
        for group in ("", "/", "relative/path", "/system.slice/../other"):
            with patch.object(pmtu.subprocess, "check_output", return_value=group):
                with self.assertRaises(ValueError):
                    pmtu.service_pids("owned.service")

    def test_only_named_service_members(self):
        with patch.object(pmtu.subprocess, "check_output", return_value="/system.slice/owned.service\n") as show:
            with patch.object(Path, "read_text", return_value="101\n102\n") as read:
                self.assertEqual(pmtu.service_pids("owned.service"), [101, 102])
        show.assert_called_once_with(
            ["systemctl", "show", "owned.service", "--property=ControlGroup", "--value"], text=True
        )
        read.assert_called_once()


if __name__ == "__main__":
    unittest.main()

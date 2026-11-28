import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.tests import test_v06_release_evidence as legacy

SPEC = importlib.util.spec_from_file_location("v011_evidence", legacy.ROOT / "scripts/check-v011-release-evidence.py")
assert SPEC and SPEC.loader
V011 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V011)
V010_SPEC = importlib.util.spec_from_file_location("v010_evidence", legacy.ROOT / "scripts/check-v010-release-evidence.py")
assert V010_SPEC and V010_SPEC.loader
V010 = importlib.util.module_from_spec(V010_SPEC)
V010_SPEC.loader.exec_module(V010)

PROFILE = legacy.ROOT / "scripts/release-evidence-profile.sh"
COMPARISON = "performance/release-comparison.json"
LIMITATIONS = "performance/known-limitations.txt"
FULL_ANDROID = set(V011.ANDROID_PROTOCOL_SCENARIOS)
TWELVE = {
    "ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination", "routed-dns",
    "start-stop", "cancel-active-flow", "reconnect", "wifi-cellular-wifi", "lock-wake",
    "resource-recovery",
}


def put(manifest, blobs, path, data):
    """Replace an artifact and its digest, as a collector that wrote it would."""
    blobs[path] = data
    next(a for a in manifest["performance"]["artifacts"] if a["path"] == path)["sha256"] = \
        hashlib.sha256(data).hexdigest()


def comparison():
    return {
        "schemaVersion": 1,
        "baseline": dict(V011.BASELINE),
        "candidate": {"revision": legacy.REVISION, "tree": legacy.TREE},
        "measurements": [
            {"id": name, "unit": "test-units", "baseline": [100] * 5, "candidate": [100] * 5,
             "verdict": "within-budget"}
            for name in sorted(V011.COMPARISON_MEASUREMENTS)
        ],
    }


def scenarios_of(policy, platform, template):
    return [
        dict(copy.deepcopy(template), id=scenario,
             transitions=sorted(policy.device_transitions(platform, scenario)) or ["start-stop"])
        for scenario in sorted(policy.scenarios(platform))
    ]


class V011ReleaseEvidenceTests(unittest.TestCase):
    write_zip = legacy.V06ReleaseEvidenceTests.write_zip

    def evidence(self):
        manifest, blobs = legacy.V06ReleaseEvidenceTests.evidence(self)
        manifest["schemaVersion"] = 5
        for device in manifest["devices"]:
            device["scenarios"] = scenarios_of(V011.POLICY, device["platform"], device["scenarios"][0])
        manifest["performance"]["measurements"] = [
            {"id": name, "unit": "test-units", "samples": [2] * 5,
             "comparison": comparison, "threshold": 1 if comparison == "at-least" else 3}
            for name, comparison in sorted(V011.POLICY.measurement_comparisons.items())
        ]
        for path, data in [("performance/protocol-comparisons.txt", b"test-only protocol-comparisons"),
                           (LIMITATIONS, b"test-only known-limitations"),
                           (COMPARISON, json.dumps(comparison()).encode())]:
            blobs[path] = data
            manifest["performance"]["artifacts"].append(
                {"kind": Path(path).stem, "path": path, "sha256": hashlib.sha256(data).hexdigest()})
        return manifest, blobs

    def reject(self, mutation, message):
        with self.assertRaisesRegex(V011.COMMON.ValidationError, message):
            V011.validate_archive(self.write_zip(mutation), legacy.REVISION, legacy.TREE)

    def reject_comparison(self, change, message, limitations=None):
        def mutate(manifest, blobs):
            document = comparison()
            data = change(document)
            put(manifest, blobs, COMPARISON, data if isinstance(data, bytes) else json.dumps(document).encode())
            if limitations is not None:
                put(manifest, blobs, LIMITATIONS, limitations)
        self.reject(mutate, message)

    def omit_transition(self, platform, scenario, transition):
        def omit(m, _):
            device = next(d for d in m["devices"] if d["platform"] == platform)
            next(s for s in device["scenarios"] if s["id"] == scenario)["transitions"].remove(transition)
        return omit

    def profile(self, version):
        result = subprocess.run(["bash", str(PROFILE), version], capture_output=True, text=True)
        return result.returncode, result.stdout.strip()

    def test_valid_exact_candidate(self):
        V011.validate_archive(self.write_zip(), legacy.REVISION, legacy.TREE)

    def test_minor_11_selects_v011_and_nothing_near_it_does(self):
        for version in ["0.11.0", "v0.11.0", "v0.11.0-rc.1", "0.11.12"]:
            self.assertEqual(self.profile(version), (0, "v011"), version)
        # The older profiles keep their versions.
        self.assertEqual(self.profile("0.10.1"), (0, "v010"))
        self.assertEqual(self.profile("0.9.1"), (0, "v09"))
        # "0.1" is a prefix of "0.11": neither it nor a longer minor may match.
        for version in ["0.1.1", "v0.1.11", "0.110.0", "0.111.0", "0.11", "0.11.", "0.11.01",
                        "v0.11.0-rc.0", "0.12.0", "v1.0.0", "1.11.0", "00.11.0", "0.11.0 ", "0.11.0/../x"]:
            self.assertNotEqual(self.profile(version)[0], 0, version)

    def test_release_boundary_dispatches_0_11_to_this_policy(self):
        # check-release-evidence.sh reads the workspace version; give it one.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            for name in ["check-release-evidence.sh", "release-evidence-profile.sh",
                         "check-v06-release-evidence.py", "check-v010-release-evidence.py",
                         "check-v011-release-evidence.py"]:
                shutil.copy(legacy.ROOT / "scripts" / name, root / "scripts" / name)
            # The script runs "python3"; make that this interpreter (tomllib needs 3.11).
            (root / "bin").mkdir()
            (root / "bin/python3").symlink_to(sys.executable)
            environment = dict(os.environ, PATH=f"{root / 'bin'}{os.pathsep}{os.environ['PATH']}")
            for version, passes in [("0.11.0", True), ("0.11.2", True), ("0.10.1", False), ("0.12.0", False)]:
                (root / "Cargo.toml").write_text(f'[workspace.package]\nversion = "{version}"\n')
                result = subprocess.run(
                    ["bash", str(root / "scripts/check-release-evidence.sh"), str(self.write_zip()),
                     legacy.REVISION, legacy.TREE], capture_output=True, text=True, env=environment)
                self.assertEqual(result.returncode == 0, passes, (version, result.stderr))
                if passes:
                    self.assertIn("v0.11 evidence validated", result.stdout)

    def test_previous_acceptance_and_v010_archives_are_rejected(self):
        for schema in [1, 2, 3, 4, 6, True]:
            with self.subTest(schema=schema):
                self.reject(lambda m, _: m.update(schemaVersion=schema), "schemaVersion must be 5")
        self.reject(lambda m, _: m.update(acceptance={"release": "0.10.1"}), "fields differ")
        self.reject(lambda m, _: m.update(result="accepted-with-exceptions"), "must be 'pass'")
        self.reject(lambda m, _: m["candidate"].update(revision="3" * 40), "candidate revision")

        def v010_scenarios(m, _):
            for device in m["devices"]:
                device["scenarios"] = scenarios_of(V010.POLICY, device["platform"], device["scenarios"][0])
        self.reject(v010_scenarios, "scenarios must be exactly|transitions must include")
        # A v0.11 archive does not satisfy the v0.10 gate either, though both are schema 5.
        with self.assertRaisesRegex(V010.COMMON.ValidationError, "scenarios must be exactly|transitions must include"):
            V010.validate_archive(self.write_zip(), legacy.REVISION, legacy.TREE)

    def test_scenario_sets_are_the_accepted_contract(self):
        shared = V011.SHARED_SCENARIOS
        self.assertEqual(shared - V010.SHARED_SCENARIOS, {"tun-sniffing"})
        self.assertEqual(V011.POLICY.scenarios("apple") - shared, {"vless-reality", "hysteria2", "wireguard"})
        self.assertEqual(V011.POLICY.scenarios("android") - shared, {
            "vless-reality-file-descriptor", "vless-reality-packet-pump",
            "hysteria2-file-descriptor", "hysteria2-packet-pump",
            "wireguard-file-descriptor", "wireguard-packet-pump"})
        # The 0.10 smoke scenarios moved into legacy-regression.
        self.assertFalse(V011.POLICY.scenarios("apple") & (V010.SMOKE_PROTOCOLS | V010.FULL_PROTOCOLS))
        self.assertTrue(all(len(name) <= 64 for name in V011.POLICY.scenarios("android")))

    def test_every_scenario_and_transition_is_required(self):
        for platform in ["apple", "android"]:
            for name in V011.POLICY.scenarios(platform):
                for transition in V011.POLICY.device_transitions(platform, name):
                    with self.subTest(platform=platform, scenario=name, transition=transition):
                        self.reject(self.omit_transition(platform, name, transition), "transitions must include")
                with self.subTest(platform=platform, scenario=name):
                    def drop(m, _, name=name, platform=platform):
                        device = next(d for d in m["devices"] if d["platform"] == platform)
                        device["scenarios"] = [s for s in device["scenarios"] if s["id"] != name]
                    self.reject(drop, "scenarios must be exactly")

    def test_full_set_is_twelve_and_wireguard_adds_the_idle_restart(self):
        self.assertEqual(V011.PROTOCOL_TRANSITIONS, TWELVE)
        self.assertEqual(V011.PROTOCOL_TRANSITIONS, V010.PROTOCOL_TRANSITIONS)
        for protocol in ["vless-reality", "hysteria2"]:
            self.assertEqual(V011.POLICY.device_transitions("apple", protocol), TWELVE)
        self.assertEqual(V011.POLICY.device_transitions("apple", "wireguard"), TWELVE | {"idle-device-restart"})
        for path in ["file-descriptor", "packet-pump"]:
            self.assertIn("idle-device-restart", V011.POLICY.device_transitions("android", f"wireguard-{path}"))
            for protocol in ["vless-reality", "hysteria2"]:
                self.assertNotIn("idle-device-restart",
                                 V011.POLICY.device_transitions("android", f"{protocol}-{path}"))
        # No refusal ids: every full-set scenario carries real UDP of both families.
        for platform in ["apple", "android"]:
            for name in V011.POLICY.scenarios(platform) - V011.SHARED_SCENARIOS:
                self.assertFalse([t for t in V011.POLICY.transitions(name) if t.endswith("-refused")], name)

    def test_android_tests_lock_wake_and_skips_only_the_network_change(self):
        # The owner's decisions: 2026-11-15 for the network change, 2026-11-28 for lock-wake.
        self.assertEqual(V011.ANDROID_OWNER_SKIPPED_TRANSITIONS, {"wifi-cellular-wifi"})
        self.assertEqual(V011.ANDROID_OWNER_SKIPPED_LEGACY_TRANSITIONS, {"xhttp-h3-network-change"})
        self.assertIn("lock-wake", V010.ANDROID_OWNER_SKIPPED_TRANSITIONS)
        for name in FULL_ANDROID:
            required = V011.POLICY.device_transitions("android", name)
            self.assertIn("lock-wake", required, name)
            self.assertNotIn("wifi-cellular-wifi", required, name)
            with self.subTest(scenario=name):
                self.reject(self.omit_transition("android", name, "lock-wake"), "transitions must include")
        self.assertEqual(V011.POLICY.device_transitions("android", "legacy-regression"), V011.LEGACY_PROTOCOLS)
        # Not tested is not passed: a valid archive claims neither on Android.
        manifest, _ = self.evidence()
        android = next(d for d in manifest["devices"] if d["platform"] == "android")
        for scenario in android["scenarios"]:
            self.assertFalse(set(scenario["transitions"]) & {"wifi-cellular-wifi", "xhttp-h3-network-change"},
                             scenario["id"])
        # Apple keeps both.
        for name, transition in [("vless-reality", "wifi-cellular-wifi"), ("wireguard", "wifi-cellular-wifi"),
                                 ("hysteria2", "lock-wake"),
                                 ("legacy-regression", "xhttp-h3-network-change")]:
            with self.subTest(scenario=name, transition=transition):
                self.reject(self.omit_transition("apple", name, transition), "transitions must include")

    def test_sniffing_runs_six_transitions_on_both_platforms(self):
        expected = {"http-host-route", "tls-sni-route", "domain-rule-refusal", "decoy-sni-address",
                    "saved-profile-migration", "sniffed-name-dial"}
        for platform in ["apple", "android"]:
            self.assertIn("tun-sniffing", V011.POLICY.scenarios(platform))
            self.assertEqual(V011.POLICY.device_transitions(platform, "tun-sniffing"), expected)

    def test_import_and_legacy_regression_cover_what_changed_since_v010(self):
        self.assertEqual(V011.POLICY.transitions("profile-import"),
                         {"vmess-link-plain", "xray-json-subscription", "invalid-input-redaction"})
        shipped = V010.LEGACY_PROTOCOLS | V010.FULL_PROTOCOLS | V010.SMOKE_PROTOCOLS
        self.assertEqual(len(shipped), 22)
        self.assertEqual(V011.LEGACY_PROTOCOLS, shipped)
        self.assertEqual(V011.POLICY.transitions("legacy-regression"), shipped | {"xhttp-h3-network-change"})

    def test_each_gate_budget_is_enforced(self):
        self.assertEqual(set(V011.POLICY.measurement_comparisons) - set(V011.COMMON.MEASUREMENT_COMPARISONS), {
            f"{protocol}-{metric}" for protocol in ["vless-reality", "hysteria2", "wireguard"]
            for metric in ["throughput", "latency", "memory"]})
        for name in V011.POLICY.measurement_comparisons:
            with self.subTest(measurement=name):
                def regress(m, _, name=name):
                    measurement = next(v for v in m["performance"]["measurements"] if v["id"] == name)
                    measurement["samples"] = [0.5 if measurement["comparison"] == "at-least" else 4] * 5
                self.reject(regress, "median exceeds|below its explicit minimum")

    def test_release_comparison_is_bound_to_v0101_and_the_candidate(self):
        self.assertEqual(len(V011.COMPARISON_MEASUREMENTS), 42)
        self.assertEqual(V011.BASELINE, {"version": "0.10.1",
                                         "revision": "3cef7c42c2fd296afd27ab0b6435c632842e1a26",
                                         "tree": "d430ce5f1c106b48ba9ecc55a25455f0a201c50f"})

        def drop_artifact(m, b):
            m["performance"]["artifacts"] = [a for a in m["performance"]["artifacts"] if a["path"] != COMPARISON]
            del b[COMPARISON]
        self.reject(drop_artifact, "kinds must be exactly")
        self.reject_comparison(lambda d: d.update(baseline=dict(V010.BASELINE)), "published v0.10.1")
        self.reject_comparison(lambda d: d["baseline"].update(revision="4" * 40), "published v0.10.1")
        self.reject_comparison(lambda d: d["baseline"].update(version="0.10.0"), "published v0.10.1")
        self.reject_comparison(lambda d: d["candidate"].update(revision="4" * 40), "does not match the release")
        self.reject_comparison(lambda d: d["candidate"].update(tree="4" * 40), "does not match the release")
        self.reject_comparison(lambda d: d.update(schemaVersion=2), "schemaVersion must be 1")
        self.reject_comparison(lambda d: d.update(note="extra"), "fields differ")
        self.reject_comparison(lambda d: b"{not json", "invalid release-comparison")
        self.reject_comparison(lambda d: b'{"schemaVersion": 1, "schemaVersion": 1}', "duplicate JSON field")
        self.reject_comparison(lambda d: b" " * (V011.MAX_COMPARISON_BYTES + 1), "exceeds 1 MiB")

    def test_release_comparison_covers_mkcp_and_masque_with_five_runs(self):
        for carrier in ["mkcp", "masque"]:
            for metric in ["throughput", "latency", "memory"]:
                self.assertIn(f"{carrier}-{metric}", V011.COMPARISON_MEASUREMENTS)
        self.reject_comparison(lambda d: d["measurements"].pop(), "measurements must be exactly")
        self.reject_comparison(lambda d: d["measurements"].append(dict(d["measurements"][0])),
                               "measurements must be exactly")
        self.reject_comparison(lambda d: d["measurements"][0].update(id="xdns-throughput"),
                               "not a v0.10.1 carrier measurement")
        for side in ["baseline", "candidate"]:
            self.reject_comparison(lambda d, side=side: d["measurements"][0].update({side: [100] * 4}),
                                   "at least five")
            self.reject_comparison(lambda d, side=side: d["measurements"][0].update({side: [100, 100, 100, 100, 0]}),
                                   "allowed numeric range")

    def test_a_regression_must_be_labelled_and_disclosed(self):
        cases = {"masque-throughput": [89] * 5, "mkcp-latency": [111] * 5, "vless-reality-memory": [111] * 5}
        for name, samples in cases.items():
            def regress(document, verdict, name=name, samples=samples):
                row = next(r for r in document["measurements"] if r["id"] == name)
                row.update(candidate=samples, verdict=verdict)
            with self.subTest(measurement=name):
                self.reject_comparison(lambda d: regress(d, "within-budget"), "verdict must be 'regression'")
                self.reject_comparison(lambda d: regress(d, "regression"), "does not name the regression")

                def disclosed(m, b, regress=regress, name=name):
                    document = comparison()
                    regress(document, "regression")
                    put(m, b, COMPARISON, json.dumps(document).encode())
                    put(m, b, LIMITATIONS, f"Known limitation: {name} regressed against 0.10.1.".encode())
                V011.validate_archive(self.write_zip(disclosed), legacy.REVISION, legacy.TREE)
        self.reject_comparison(lambda d: d["measurements"][0].update(verdict="regression"),
                               "verdict must be 'within-budget'")
        self.reject_comparison(lambda d: None, "must be UTF-8", limitations=b"\xff\xfe")

    def test_verdicts_use_medians_and_budget_edges_are_inside(self):
        self.assertEqual(V011.COMPARISON_BUDGETS, V010.COMPARISON_BUDGETS)
        self.assertEqual(V011.comparison_verdict("throughput", [100] * 5, [90] * 5), "within-budget")
        self.assertEqual(V011.comparison_verdict("latency", [100] * 5, [110] * 5), "within-budget")
        self.assertEqual(V011.comparison_verdict("throughput", [100] * 5, [10, 10, 10, 95, 95]), "regression")

    def test_incomplete_or_modified_evidence_is_rejected(self):
        self.reject(lambda m, _: m["devices"][0]["scenarios"].pop(), "scenarios must be exactly")
        self.reject(lambda m, _: m["performance"]["measurements"].pop(), "measurements must be exactly")
        self.reject(lambda _, b: b.update({LIMITATIONS: b"changed"}), "checksum differs")


if __name__ == "__main__":
    unittest.main()

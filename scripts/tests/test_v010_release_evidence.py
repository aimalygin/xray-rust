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

SPEC = importlib.util.spec_from_file_location("v010_evidence", legacy.ROOT / "scripts/check-v010-release-evidence.py")
assert SPEC and SPEC.loader
V010 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V010)
V09_SPEC = importlib.util.spec_from_file_location("v09_evidence", legacy.ROOT / "scripts/check-v09-release-evidence.py")
assert V09_SPEC and V09_SPEC.loader
V09 = importlib.util.module_from_spec(V09_SPEC)
V09_SPEC.loader.exec_module(V09)

PROFILE = legacy.ROOT / "scripts/release-evidence-profile.sh"
COMPARISON = "performance/release-comparison.json"
LIMITATIONS = "performance/known-limitations.txt"
FULL_ANDROID = set(V010.ANDROID_PROTOCOL_SCENARIOS)


def put(manifest, blobs, path, data):
    """Replace an artifact and its digest, as a collector that wrote it would."""
    blobs[path] = data
    next(a for a in manifest["performance"]["artifacts"] if a["path"] == path)["sha256"] = \
        hashlib.sha256(data).hexdigest()


def comparison():
    return {
        "schemaVersion": 1,
        "baseline": dict(V010.BASELINE),
        "candidate": {"revision": legacy.REVISION, "tree": legacy.TREE},
        "measurements": [
            {"id": name, "unit": "test-units", "baseline": [100] * 5, "candidate": [100] * 5,
             "verdict": "within-budget"}
            for name in sorted(V010.COMPARISON_MEASUREMENTS)
        ],
    }


class V010ReleaseEvidenceTests(unittest.TestCase):
    write_zip = legacy.V06ReleaseEvidenceTests.write_zip

    def evidence(self):
        manifest, blobs = legacy.V06ReleaseEvidenceTests.evidence(self)
        manifest["schemaVersion"] = 5
        for device in manifest["devices"]:
            template = device["scenarios"][0]
            device["scenarios"] = [
                dict(copy.deepcopy(template), id=scenario,
                     transitions=sorted(V010.POLICY.transitions(scenario)) or ["start-stop"])
                for scenario in sorted(V010.POLICY.scenarios(device["platform"]))
            ]
        manifest["performance"]["measurements"] = [
            {"id": name, "unit": "test-units", "samples": [2] * 5,
             "comparison": comparison, "threshold": 1 if comparison == "at-least" else 3}
            for name, comparison in sorted(V010.POLICY.measurement_comparisons.items())
        ]
        for path, data in [("performance/protocol-comparisons.txt", b"test-only protocol-comparisons"),
                           (LIMITATIONS, b"test-only known-limitations"),
                           (COMPARISON, json.dumps(comparison()).encode())]:
            blobs[path] = data
            manifest["performance"]["artifacts"].append(
                {"kind": Path(path).stem, "path": path, "sha256": hashlib.sha256(data).hexdigest()})
        return manifest, blobs

    def reject(self, mutation, message):
        with self.assertRaisesRegex(V010.COMMON.ValidationError, message):
            V010.validate_archive(self.write_zip(mutation), legacy.REVISION, legacy.TREE)

    def reject_comparison(self, change, message, limitations=None):
        def mutate(manifest, blobs):
            document = comparison()
            data = change(document)
            put(manifest, blobs, COMPARISON, data if isinstance(data, bytes) else json.dumps(document).encode())
            if limitations is not None:
                put(manifest, blobs, LIMITATIONS, limitations)
        self.reject(mutate, message)

    def profile(self, version):
        result = subprocess.run(["bash", str(PROFILE), version], capture_output=True, text=True)
        return result.returncode, result.stdout.strip()

    def test_valid_exact_candidate(self):
        V010.validate_archive(self.write_zip(), legacy.REVISION, legacy.TREE)

    def test_two_digit_minor_selects_v010_and_nothing_near_it_does(self):
        for version in ["0.10.0", "v0.10.0", "v0.10.0-rc.1", "0.10.12"]:
            self.assertEqual(self.profile(version), (0, "v010"), version)
        # The older profiles keep their versions.
        self.assertEqual(self.profile("0.9.1"), (0, "v09"))
        self.assertEqual(self.profile("v0.6.1"), (0, "v06"))
        # "0.1" is a prefix of "0.10": neither it nor a longer minor may match.
        for version in ["0.1.0", "v0.1.10", "0.100.0", "0.101.0", "0.10", "0.1", "0.10.", "0.10.01",
                        "v0.10.0-rc.0", "0.11.0", "v1.0.0", "1.10.0", "00.10.0", "0.10.0 ", "0.10.0/../x"]:
            self.assertNotEqual(self.profile(version)[0], 0, version)

    def test_release_boundary_dispatches_0_10_to_this_policy(self):
        # check-release-evidence.sh reads the workspace version; give it one.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            for name in ["check-release-evidence.sh", "release-evidence-profile.sh",
                         "check-v06-release-evidence.py", "check-v010-release-evidence.py"]:
                shutil.copy(legacy.ROOT / "scripts" / name, root / "scripts" / name)
            # The script runs "python3"; make that this interpreter (tomllib needs 3.11).
            (root / "bin").mkdir()
            (root / "bin/python3").symlink_to(sys.executable)
            environment = dict(os.environ, PATH=f"{root / 'bin'}{os.pathsep}{os.environ['PATH']}")
            for version, passes in [("0.10.0", True), ("0.10.3", True), ("0.9.0", False), ("0.11.0", False)]:
                (root / "Cargo.toml").write_text(f'[workspace.package]\nversion = "{version}"\n')
                result = subprocess.run(
                    ["bash", str(root / "scripts/check-release-evidence.sh"), str(self.write_zip()),
                     legacy.REVISION, legacy.TREE], capture_output=True, text=True, env=environment)
                self.assertEqual(result.returncode == 0, passes, (version, result.stderr))
                if passes:
                    self.assertIn("v0.10 evidence validated", result.stdout)

    def test_previous_schemas_acceptance_and_v09_archives_are_rejected(self):
        for schema in [1, 2, 3, 4, True]:
            with self.subTest(schema=schema):
                self.reject(lambda m, _: m.update(schemaVersion=schema), "schemaVersion must be 5")
        self.reject(lambda m, _: m.update(acceptance={"release": "0.9.0"}), "fields differ")
        self.reject(lambda m, _: m.update(result="accepted-with-exceptions"), "must be 'pass'")
        self.reject(lambda m, _: m["candidate"].update(revision="3" * 40), "candidate revision")

        def v09_scenarios(m, _):
            for device in m["devices"]:
                template = device["scenarios"][0]
                device["scenarios"] = [
                    dict(copy.deepcopy(template), id=scenario,
                         transitions=sorted(V09.POLICY.transitions(scenario)) or ["start-stop"])
                    for scenario in sorted(V09.POLICY.scenarios(device["platform"]))
                ]
        self.reject(v09_scenarios, "scenarios must be exactly|transitions must include")
        # A v0.10 archive does not satisfy the v0.9 gate either.
        with self.assertRaisesRegex(V09.COMMON.ValidationError, "schemaVersion must be 4"):
            V09.validate_archive(self.write_zip(), legacy.REVISION, legacy.TREE)

    def test_scenario_sets_are_the_accepted_contract(self):
        shared = V010.SHARED_SCENARIOS
        smoke = {"xdns", "xicmp", "realm", "sudoku", "xmc", "header-custom", "xdrive", "vless-reverse"}
        self.assertEqual(V010.POLICY.scenarios("apple") - shared, {"mkcp", "masque"} | smoke)
        self.assertEqual(V010.POLICY.scenarios("android") - shared, smoke | {
            "mkcp-file-descriptor", "mkcp-packet-pump", "masque-file-descriptor", "masque-packet-pump"})
        self.assertEqual(shared, V09.SHARED_SCENARIOS)
        self.assertTrue(all(len(name) <= 64 for name in V010.POLICY.scenarios("android")))

    def test_every_protocol_path_and_transition_is_required(self):
        for platform in ["apple", "android"]:
            for name in V010.POLICY.scenarios(platform) - V010.SHARED_SCENARIOS:
                for transition in V010.POLICY.transitions(name):
                    with self.subTest(platform=platform, scenario=name, transition=transition):
                        def omit(m, _):
                            device = next(d for d in m["devices"] if d["platform"] == platform)
                            next(s for s in device["scenarios"] if s["id"] == name)["transitions"].remove(transition)
                        self.reject(omit, "transitions must include")
            for name in V010.POLICY.scenarios(platform):
                with self.subTest(platform=platform, scenario=name):
                    def drop(m, _):
                        device = next(d for d in m["devices"] if d["platform"] == platform)
                        device["scenarios"] = [s for s in device["scenarios"] if s["id"] != name]
                    self.reject(drop, "scenarios must be exactly")

    def test_full_set_takes_twelve_transitions_and_smoke_takes_seven(self):
        full = V09.PROTOCOL_TRANSITIONS
        self.assertEqual(len(full), 12)
        smoke = {"ipv4-tcp", "ipv6-tcp", "ipv4-udp", "ipv6-udp", "domain-destination", "routed-dns", "start-stop"}
        for protocol in ["mkcp", "masque"]:
            self.assertEqual(V010.POLICY.transitions(protocol), full)
        for protocol in V010.SMOKE_PROTOCOLS:
            self.assertEqual(V010.POLICY.transitions(protocol), smoke, protocol)
        # No refusal ids: every v0.10 scenario carries real UDP of both families.
        for platform in ["apple", "android"]:
            for name in V010.POLICY.scenarios(platform) - V010.SHARED_SCENARIOS:
                self.assertFalse([t for t in V010.POLICY.transitions(name) if t.endswith("-refused")], name)

    def test_android_tests_network_change_and_skips_only_lock_wake(self):
        full = V010.PROTOCOL_TRANSITIONS
        self.assertEqual(V010.ANDROID_OWNER_SKIPPED_TRANSITIONS, {"lock-wake"})
        for name in FULL_ANDROID:
            self.assertEqual(V010.POLICY.transitions(name), full - {"lock-wake"})
            self.assertIn("wifi-cellular-wifi", V010.POLICY.transitions(name))

            def untested(m, _, name=name):
                android = next(d for d in m["devices"] if d["platform"] == "android")
                next(s for s in android["scenarios"] if s["id"] == name)["transitions"].remove("wifi-cellular-wifi")
            self.reject(untested, "transitions must include")
        # v0.9 skipped both; that decision is not inherited.
        self.assertEqual(V09.ANDROID_OWNER_SKIPPED_TRANSITIONS, {"wifi-cellular-wifi", "lock-wake"})
        manifest, _ = self.evidence()
        android = next(d for d in manifest["devices"] if d["platform"] == "android")
        for scenario in android["scenarios"]:
            self.assertNotIn("lock-wake", scenario["transitions"])

    def test_import_and_legacy_regression_cover_what_changed_since_v09(self):
        self.assertEqual(V010.POLICY.transitions("profile-import"), {
            "vless-link", "trojan-link", "vmess-link", "hysteria2-link", "remnawave-json",
            "invalid-input-redaction"})
        legacy_v09 = V09.POLICY.transitions("legacy-regression") | V09.PROTOCOLS
        self.assertEqual(V010.LEGACY_PROTOCOLS, legacy_v09)
        self.assertEqual(V010.POLICY.transitions("legacy-regression"), legacy_v09 | {"xhttp-h3-network-change"})
        for platform in ["apple", "android"]:
            for scenario in ["profile-import", "legacy-regression"]:
                for transition in V010.POLICY.transitions(scenario):
                    with self.subTest(platform=platform, scenario=scenario, transition=transition):
                        def omit(m, _):
                            device = next(d for d in m["devices"] if d["platform"] == platform)
                            next(s for s in device["scenarios"] if s["id"] == scenario)["transitions"].remove(transition)
                        self.reject(omit, "transitions must include")

    def test_each_gate_budget_is_enforced(self):
        self.assertEqual(set(V010.POLICY.measurement_comparisons) - set(V010.COMMON.MEASUREMENT_COMPARISONS), {
            f"{protocol}-{metric}" for protocol in ["mkcp", "masque"]
            for metric in ["throughput", "latency", "memory"]})
        for name in V010.POLICY.measurement_comparisons:
            with self.subTest(measurement=name):
                def regress(m, _):
                    measurement = next(v for v in m["performance"]["measurements"] if v["id"] == name)
                    measurement["samples"] = [0.5 if measurement["comparison"] == "at-least" else 4] * 5
                self.reject(regress, "median exceeds|below its explicit minimum")

    def test_release_comparison_is_bound_to_v090_and_the_candidate(self):
        self.assertEqual(len(V010.COMPARISON_MEASUREMENTS), 36)

        def drop_artifact(m, b):
            m["performance"]["artifacts"] = [a for a in m["performance"]["artifacts"] if a["path"] != COMPARISON]
            del b[COMPARISON]
        self.reject(drop_artifact, "kinds must be exactly")
        self.reject_comparison(lambda d: d["baseline"].update(revision="4" * 40), "published v0.9.0")
        self.reject_comparison(lambda d: d["baseline"].update(version="0.8.1"), "published v0.9.0")
        self.reject_comparison(lambda d: d["candidate"].update(revision="4" * 40), "does not match the release")
        self.reject_comparison(lambda d: d["candidate"].update(tree="4" * 40), "does not match the release")
        self.reject_comparison(lambda d: d.update(schemaVersion=2), "schemaVersion must be 1")
        self.reject_comparison(lambda d: d.update(schemaVersion=True), "schemaVersion must be 1")
        self.reject_comparison(lambda d: d.update(note="extra"), "fields differ")
        self.reject_comparison(lambda d: b"{not json", "invalid release-comparison")
        self.reject_comparison(lambda d: b'{"schemaVersion": 1, "schemaVersion": 1}', "duplicate JSON field")
        self.reject_comparison(lambda d: b" " * (V010.MAX_COMPARISON_BYTES + 1), "exceeds 1 MiB")

    def test_release_comparison_covers_every_v09_protocol_with_five_runs(self):
        self.reject_comparison(lambda d: d["measurements"].pop(), "measurements must be exactly")
        self.reject_comparison(lambda d: d["measurements"].append(dict(d["measurements"][0])),
                               "measurements must be exactly")
        self.reject_comparison(lambda d: d["measurements"][0].update(id="mkcp-throughput"),
                               "not a v0.9 protocol measurement")
        for side in ["baseline", "candidate"]:
            self.reject_comparison(lambda d: d["measurements"][0].update({side: [100] * 4}), "at least five")
            self.reject_comparison(lambda d: d["measurements"][0].update({side: [100, 100, 100, 100, 0]}),
                                   "allowed numeric range")
            self.reject_comparison(lambda d: d["measurements"][0].update({side: "100"}), "at least five")
        self.reject_comparison(lambda d: d["measurements"][0].pop("unit"), "fields differ")

    def test_a_regression_must_be_labelled_and_disclosed(self):
        cases = {"trojan-throughput": [89] * 5, "xhttp-h3-latency": [111] * 5, "shadowsocks-aead-memory": [111] * 5}
        for name, samples in cases.items():
            def regress(document, verdict, name=name, samples=samples):
                row = next(r for r in document["measurements"] if r["id"] == name)
                row.update(candidate=samples, verdict=verdict)
            with self.subTest(measurement=name):
                # Called within budget when the medians say otherwise.
                self.reject_comparison(lambda d: regress(d, "within-budget"), "verdict must be 'regression'")
                # Labelled, but the release's known limitations are silent.
                self.reject_comparison(lambda d: regress(d, "regression"), "does not name the regression")
                # Labelled and disclosed: recorded, not a gate failure.
                def disclosed(m, b):
                    document = comparison()
                    regress(document, "regression")
                    put(m, b, COMPARISON, json.dumps(document).encode())
                    put(m, b, LIMITATIONS, f"Known limitation: {name} regressed against 0.9.0.".encode())
                V010.validate_archive(self.write_zip(disclosed), legacy.REVISION, legacy.TREE)
        # The budgets' edges are inside them, and nothing may be called a regression that is not.
        for name, samples in {"trojan-throughput": [90] * 5, "xhttp-h3-latency": [110] * 5}.items():
            def edge(m, b, name=name, samples=samples):
                document = comparison()
                next(r for r in document["measurements"] if r["id"] == name)["candidate"] = samples
                put(m, b, COMPARISON, json.dumps(document).encode())
            V010.validate_archive(self.write_zip(edge), legacy.REVISION, legacy.TREE)
        self.reject_comparison(lambda d: d["measurements"][0].update(verdict="regression"),
                               "verdict must be 'within-budget'")
        self.reject_comparison(lambda d: None, "must be UTF-8", limitations=b"\xff\xfe")

    def test_verdicts_use_medians(self):
        self.assertEqual(V010.comparison_verdict("throughput", [100] * 5, [10, 10, 95, 95, 95]), "within-budget")
        self.assertEqual(V010.comparison_verdict("throughput", [100] * 5, [10, 10, 10, 95, 95]), "regression")
        self.assertEqual(V010.comparison_verdict("memory", [100] * 5, [500, 500, 105, 105, 105]), "within-budget")
        self.assertEqual(V010.comparison_verdict("latency", [100] * 5, [105, 105, 500, 500, 500]), "regression")

    def test_incomplete_or_modified_evidence_is_rejected(self):
        self.reject(lambda m, _: m["devices"][0]["scenarios"].pop(), "scenarios must be exactly")
        self.reject(lambda m, _: m["performance"]["measurements"].pop(), "measurements must be exactly")
        self.reject(lambda _, b: b.update({LIMITATIONS: b"changed"}), "checksum differs")
        self.reject(lambda _, b: b.update({COMPARISON: json.dumps(comparison()).encode() + b" "}), "checksum differs")


if __name__ == "__main__":
    unittest.main()

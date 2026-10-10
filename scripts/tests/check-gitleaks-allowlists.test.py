#!/usr/bin/env python3
"""Exercise evidence exceptions with Gitleaks, including positive leak controls."""

import json
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tarfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[2]
INDEX = "docs/benchmarks/results/2026-09-20-v07-parity/evidence-index.json"
FIXTURE = "scripts/run-v07-performance.py"
BUILD = "docs/benchmarks/results/2026-09-20-v07-parity/data/reference-native-hysteria-build.txt"
DIGEST = "abcdef0123456789" * 4
PUBLIC_FIXTURE = "aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks"
ARCHIVE_INDEX = "automated-validation.json"
ARCHIVE_ALLOWLIST = "Nine verified file digests in the v0.7 automated evidence index"


class EvidenceAllowlists(unittest.TestCase):
    def test_pr42_issue_binary_digests_are_narrow(self):
        base = "docs/benchmarks/results/2026-10-10-pr42-issues/"
        archive_path = base + "measurements.tar.gz"
        index = json.loads((ROOT / base / "evidence-index.json").read_text())
        self.assertEqual(hashlib.sha256((ROOT / archive_path).read_bytes()).hexdigest(),
                         index["archive_sha256"])
        reviewed = {}
        with tarfile.open(ROOT / archive_path) as archive:
            for member in archive.getmembers():
                if not member.isfile():
                    continue
                data = archive.extractfile(member).read()
                self.assertEqual(hashlib.sha256(data).hexdigest(),
                                 index["members"][member.name]["sha256"])
                if member.name.endswith("/manifest.json"):
                    manifest = json.loads(data)
                    binaries = {name: digest for name, digest in manifest.get("file_hashes", {}).items()
                                if Path(name).name in ("xray-rust", "xray-bench", "xray-core")}
                    if binaries:
                        reviewed[archive_path + "!" + member.name] = json.dumps(binaries)
        self.assertGreaterEqual(len(reviewed), 15)
        self.assertEqual(self.scan(reviewed), set())
        path = next(iter(reviewed))
        digest = next(iter(json.loads(reviewed[path]).values()))
        unrelated = archive_path + "!unreviewed/manifest.json"
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        self.assertEqual(self.scan({path: json.dumps({"xray": other}),
                                   unrelated: json.dumps({"xray": digest})}),
                         {(name, "jfrog-identity-token") for name in (path, unrelated)})
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({path: json.dumps({"api_key": synthetic})}),
                         {(path, "generic-api-key")})

    def test_iphone_v08_executable_digest_exceptions_are_narrow(self):
        path = "docs/device-results/2026-10-03-iphone17-v08/manifest.json"
        manifest = json.loads((ROOT / path).read_text())
        digests = (
            "90b0c79c7487f49ba9cf8faf20bed3603b3450e090602e199d12f319ae22f49b",
            "06f46e890bf381e1b684ca9de3bc61e54fe8b73995492ca5b37a11947d76b029",
        )
        reviewed = dict(zip(("XrayClient", "XrayClient.debug.dylib"), digests))
        for name, digest in reviewed.items():
            self.assertEqual(manifest["app_files_sha256"][name], digest)
        self.assertEqual(self.scan({path: json.dumps(reviewed)}), set())
        unrelated = "docs/device-results/unreviewed/manifest.json"
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        self.assertEqual(self.scan({path: json.dumps({"xray": other}), unrelated: json.dumps(reviewed)}),
                         {(name, "jfrog-identity-token") for name in (path, unrelated)})
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({path: json.dumps({"api_key": synthetic})}),
                         {(path, "generic-api-key")})

    def test_iphone_lifecycle_digest_exceptions_are_narrow(self):
        path = "docs/device-results/2026-10-04-iphone17-lifecycle-resources/manifest.json"
        manifest = json.loads((ROOT / path).read_text())
        names = ("XrayClient", "XrayClient.debug.dylib")
        digests = (
            "f6c7c7bc1d3098812f1a1b7daad838640fe421769792ca448b86aa2b574bd3db",
            "9db02665e7e335231b38eab280ed29ef3b9310a98726c1dacb0f4db2a5d3a4fe",
        )
        reviewed = dict(zip(names, digests))
        for name, digest in reviewed.items():
            self.assertEqual(manifest["build"]["binaries"][name], digest)
        self.assertEqual(self.scan({path: json.dumps(reviewed)}), set())
        unrelated = "docs/device-results/unreviewed/manifest.json"
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        self.assertEqual(self.scan({path: json.dumps({"xray": other}), unrelated: json.dumps(reviewed)}),
                         {(name, "jfrog-identity-token") for name in (path, unrelated)})
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({path: json.dumps({"api_key": synthetic})}),
                         {(path, "generic-api-key")})

    def test_adaptive_relay_exceptions_are_derived_and_narrow(self):
        base = "docs/benchmarks/results/2026-10-02-v08-adaptive-relay/"
        inputs = json.loads((ROOT / base / "data/inputs.json").read_text())
        digest = inputs["xray"]["sha256"]
        paths = [base + "measurements.tar.gz!" + name + "/manifest.json"
                 for name in inputs["campaigns"]]
        self.assertEqual(self.scan({p: json.dumps({"xray": digest}) for p in paths}), set())
        index_paths = [base + name for name in ("evidence-index.json", "data/reviewed-public-hashes.json")]
        reviewed = json.loads((ROOT / index_paths[1]).read_text())
        index = json.loads((ROOT / index_paths[0]).read_text())
        self.assertEqual(len(reviewed), 30)
        with tarfile.open(ROOT / base / "measurements.tar.gz") as archive:
            for name, expected in reviewed.items():
                self.assertTrue(name.endswith('.log'))
                self.assertEqual(hashlib.sha256(archive.extractfile(name).read()).hexdigest(), expected)
                self.assertEqual(index["file_sha256"][name], expected)
        self.assertEqual(self.scan({p: json.dumps({"xray": list(reviewed.values())}) for p in index_paths}), set())
        fixture = base + "measurements.tar.gz!investigation/scripts/run-v07-performance.py"
        self.assertEqual(self.scan({fixture: json.dumps({"privateKey": PUBLIC_FIXTURE})}), set())
        unrelated = base + "measurements.tar.gz!unreviewed/manifest.json"
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        self.assertEqual(self.scan({
            paths[0]: json.dumps({"xray": other}),
            index_paths[0]: json.dumps({"xray": other}),
            index_paths[1]: json.dumps({"xray": other}),
            unrelated: json.dumps({"xray": digest}),
        }), {(p, "jfrog-identity-token") for p in [paths[0], *index_paths, unrelated]})
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({p: json.dumps({"api_key": synthetic}) for p in [*paths, *index_paths, fixture]}),
                         {(p, "generic-api-key") for p in [*paths, *index_paths, fixture]})

    def test_split_codec_exceptions_are_derived_and_narrow(self):
        base = "docs/benchmarks/results/2026-10-02-v08-split/"
        inputs = json.loads((ROOT / base / "data/inputs.json").read_text())
        digest = inputs["xray"]["sha256"]
        campaigns = list(inputs["campaign_variants"]) + ["duplex-pilot-rejected-permission"]
        paths = [base + "measurements.tar.gz!" + name + "/manifest.json" for name in campaigns]
        self.assertEqual(self.scan({p: json.dumps({"xray": digest}) for p in paths}), set())
        index_path = base + "evidence-index.json"
        index = json.loads((ROOT / index_path).read_text())
        with tarfile.open(ROOT / base / "measurements.tar.gz") as archive:
            for name in ("investigation/interop-xray.log", "investigation/restored-trojan-xray.log"):
                log_hash = hashlib.sha256(archive.extractfile(name).read()).hexdigest()
                self.assertEqual(log_hash, index["file_sha256"][name])
                self.assertEqual(self.scan({index_path: json.dumps({"xray": log_hash})}), set())
        fixture_path = base + "measurements.tar.gz!investigation/scripts/run-v07-performance.py"
        self.assertEqual(self.scan({fixture_path: json.dumps({"privateKey": PUBLIC_FIXTURE})}), set())
        unrelated = base + "measurements.tar.gz!unreviewed/manifest.json"
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        self.assertEqual(self.scan({
            paths[0]: json.dumps({"xray": other}),
            index_path: json.dumps({"xray": other}),
            unrelated: json.dumps({"xray": digest}),
        }), {(p, "jfrog-identity-token") for p in (paths[0], index_path, unrelated)})
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({p: json.dumps({"api_key": synthetic}) for p in paths + [index_path, fixture_path]}),
                         {(p, "generic-api-key") for p in paths + [index_path, fixture_path]})

    def test_duplex_profile_reference_digest_exception_is_narrow(self):
        base = "docs/benchmarks/results/2026-10-02-v08-duplex-profile/"
        digest = "fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99"
        inputs = json.loads((ROOT / base / "data/inputs.json").read_text())
        self.assertEqual(inputs["xray"]["sha256"], digest)
        paths = [base + "measurements.tar.gz!" + campaign + "/manifest.json"
                 for campaign in ("normal-controls", "normal-confirmation", "kernel", "libc")]
        paths += [base + f"measurements.tar.gz!{engine}-duplex-{i}/capture.json"
                  for engine in ("rust", "xray") for i in range(1, 5)]
        self.assertEqual(self.scan({p: json.dumps({"xray": digest}) for p in paths}), set())
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        unrelated = base + "measurements.tar.gz!rust-duplex-5/capture.json"
        self.assertEqual(self.scan({
            paths[0]: json.dumps({"xray": other}),
            unrelated: json.dumps({"xray": digest}),
        }), {(p, "jfrog-identity-token") for p in (paths[0], unrelated)})
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({p: json.dumps({"api_key": synthetic}) for p in paths}),
                         {(p, "generic-api-key") for p in paths})

    def test_idle_buffer_reference_digest_exception_is_narrow(self):
        base = "docs/benchmarks/results/2026-10-02-v08-idle-buffers/"
        digest = "fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99"
        inputs = json.loads((ROOT / base / "data/inputs.json").read_text())
        self.assertEqual(inputs["frozen_files"]["target/v08-io-final/bin/xray"], digest)
        paths = [base + "data/inputs.json"] + [
            base + "measurements.tar.gz!" + campaign + "/manifest.json"
            for campaign in ("held", "footprint", "untouched-controls")
        ]
        self.assertEqual(self.scan({p: json.dumps({"xray": digest}) for p in paths}), set())
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        unrelated = base + "data/unreviewed.json"
        self.assertEqual(self.scan({
            paths[0]: json.dumps({"xray": other}),
            unrelated: json.dumps({"xray": digest}),
        }), {(p, "jfrog-identity-token") for p in (paths[0], unrelated)})
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({p: json.dumps({"api_key": synthetic}) for p in paths}),
                         {(p, "generic-api-key") for p in paths})

    def test_vivat_build_hash_exceptions_keep_exact_path_value_and_rule(self):
        archive_path = "docs/benchmarks/results/2026-10-09-vivat-pr-integration/measurements.tar.gz"
        other = "e79a0029cc782ff8166c708f8c911ef3" + "9de33563b71a30df2cd2ff1d63d799ab"
        with tarfile.open(ROOT / archive_path) as archive:
            for variant in ("baseline", "pr48", "candidate"):
                member = f"validation/{variant}-build.json"
                manifest = json.load(archive.extractfile(member))
                digests = list(manifest["binaries"].values())
                if variant == "candidate":
                    digests.append(manifest["xray_core_sha256"])
                path = archive_path + "!" + member
                for digest in digests:
                    with self.subTest(variant=variant, digest=digest):
                        reviewed = json.dumps({"xray": digest})
                        self.assertEqual(self.scan({path: reviewed}), set())
                        self.assertEqual(self.scan({
                            path: json.dumps({"xray": other}),
                            "unreviewed.json": reviewed,
                        }), {(p, "jfrog-identity-token") for p in (path, "unreviewed.json")})
                synthetic = "ABcdeF01234" + "GHijk56789lMno"
                self.assertEqual(self.scan({path: json.dumps({"api_key": synthetic})}),
                                 {(path, "generic-api-key")})

    def test_v08_digest_exceptions_keep_path_value_and_rule_scope(self):
        # Public executable/log digests already reviewed on the v0.8 branch.
        # Keep controls independent of the configured regexes: broadening an
        # exception to a whole file, value or rule must fail this test.
        reviewed = {
            "docs/device-results/2026-10-03-iphone17-v08/manifest.json":
                "90b0c79c7487f49ba9cf8faf20bed3603" + "b3450e090602e199d12f319ae22f49b",
            "docs/benchmarks/results/2026-09-30-v08-cpu/data/verification.json":
                "fcbfcfe586d891ecf556570acd32ce516" + "0e803498e30fe072d151d0056d23b99",
            "docs/benchmarks/results/2026-10-02-v08-adaptive-relay/evidence-index.json":
                "1b7584d75dd361110e1fddb81f9242f58" + "2b02ac681e46b98bcf5ffc65210178b",
        }
        other_digest = "e79a0029cc782ff8166c708f8c911ef3" + "9de33563b71a30df2cd2ff1d63d799ab"
        for path, digest in reviewed.items():
            with self.subTest(path=path):
                self.assertEqual(self.scan({path: json.dumps({"xray": digest})}), set())
                self.assertEqual(self.scan({
                    path: json.dumps({"xray": other_digest}),
                    "unreviewed.json": json.dumps({"xray": digest}),
                }), {(name, "jfrog-identity-token") for name in (path, "unreviewed.json")})
                synthetic = "ABcdeF01234" + "GHijk56789lMno"
                self.assertEqual(self.scan({path: json.dumps({"api_key": synthetic})}),
                                 {(path, "generic-api-key")})

    def test_v08_oracle_key_exception_only_allows_the_reviewed_field(self):
        path = "tests/fixtures/v08/protocol-primitives.json"
        command_key = "d34482dca079f1e8" + "ad37ff8d08a382cf"
        oracle_line = '  "commandKey": "' + command_key + '",\n'
        self.assertEqual(self.scan({path: oracle_line}), set())
        self.assertEqual(self.scan({
            path: json.dumps({"api_key": command_key}),
            "unreviewed.json": oracle_line,
        }), {(name, "generic-api-key") for name in (path, "unreviewed.json")})
        test_path = "scripts/tests/check-gitleaks-allowlists.test.py"
        assignment = '        command_key = "' + command_key[:16] + '" + "' + command_key[16:] + '"\n'
        self.assertEqual(self.scan({test_path: assignment}), set())
        self.assertEqual(self.scan({
            "unreviewed.py": assignment,
            test_path: assignment.replace("command_key", "api_key"),
        }), {(name, "generic-api-key") for name in (test_path, "unreviewed.py")})

    def scan(self, files):
        binary = os.environ["GITLEAKS_BINARY"]
        with tempfile.TemporaryDirectory(prefix="xray-gitleaks-guards-") as name:
            root = Path(name)
            source = root / "source"
            source.mkdir()
            for relative, content in files.items():
                target = source / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content)
            report = root / "report.json"
            result = subprocess.run(
                [binary, "dir", ".", "--config", str(ROOT / ".gitleaks.toml"),
                 "--redact=100", "--no-banner", "--report-format", "json",
                 "--report-path", str(report)],
                cwd=source, capture_output=True, text=True, timeout=60,
            )
            self.assertIn(result.returncode, (0, 1), result.stderr)
            findings = json.loads(report.read_text())
            self.assertEqual(result.returncode, int(bool(findings)))
            return {(item["File"], item["RuleID"]) for item in findings}

    def test_reviewed_evidence_is_allowed(self):
        self.assertEqual(self.scan({
            INDEX: json.dumps({"fixture/tls.key": DIGEST}),
            FIXTURE: json.dumps({"privateKey": PUBLIC_FIXTURE}),
            BUILD: "\tdep\tgolang.org/x/oauth2\tv0.30.0\th1:"
                   "dnDm7JmhM45NNpd8FDDeLhK6FwqbOf4MLCM9zb1BOHI=\n",
        }), set())

    def test_vmess_oracle_exception_is_derived_and_narrow(self):
        path = "tests/fixtures/v08/protocol-primitives.json"
        fixture = json.loads((ROOT / path).read_text())["vmess"]
        command_key = hashlib.md5(bytes.fromhex("00112233445566778899aabbccddeeff") +
                                 b"c48619fe-8f02-49e0-b9e9-edf763e17e21").hexdigest()
        self.assertEqual(fixture["commandKey"], command_key)
        self.assertEqual(self.scan({path: json.dumps({"commandKey": command_key}, indent=2)}), set())
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({
            path: json.dumps({"commandKey": synthetic}, indent=2),
            "unreviewed.json": json.dumps({"commandKey": command_key}, indent=2),
        }), {(name, "generic-api-key") for name in (path, "unreviewed.json")})

    def test_other_credentials_in_reviewed_files_are_detected(self):
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({
            INDEX: json.dumps({"api_key": synthetic}),
            FIXTURE: json.dumps({"privateKey": synthetic}),
            BUILD: json.dumps({"api_key": synthetic}),
        }), {(name, "generic-api-key") for name in (INDEX, FIXTURE, BUILD)})

    def test_relay_manifest_digest_exception_is_narrow(self):
        base = "docs/benchmarks/results/2026-10-01-v08-relay/measurements.tar.gz!"
        path = base + "full/attempts/vmess-aes128-socks-upload-1-1/manifest.json"
        digest = "fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99"
        self.assertEqual(self.scan({path: json.dumps({"xray": digest})}), set())
        other_digest = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        self.assertEqual(self.scan({
            path: json.dumps({"xray": other_digest}),
            "unreviewed.json": json.dumps({"xray": digest}),
            base + "full/unreviewed.json": json.dumps({"xray": digest}),
        }), {(name, "jfrog-identity-token") for name in (
            path, "unreviewed.json", base + "full/unreviewed.json")})
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertIn((path, "generic-api-key"), self.scan({
            path: json.dumps({"api_key": synthetic}),
        }))

    def test_census_reference_digest_exceptions_are_narrow(self):
        base = "docs/benchmarks/results/2026-10-01-v08-census/"
        manifest = base + "measurements.tar.gz!kernel/manifest.json"
        inspection = base + "data/reference-inspection.json"
        executable = "fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99"
        source = "5450877ed206eb66a3dbeaec1f032c015e6e2dc458971293bcd2e9a01551f043"
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        data = json.loads((ROOT / inspection).read_text())
        self.assertEqual(data["files"]["common/crypto/auth.go"], source)
        self.assertEqual(self.scan({
            manifest: json.dumps({"xray": executable}),
            inspection: json.dumps({"common/crypto/auth.go": source}),
        }), set())
        self.assertIn((manifest, "jfrog-identity-token"), self.scan({
            manifest: json.dumps({"xray": other}),
        }))
        self.assertIn((inspection, "generic-api-key"), self.scan({
            inspection: json.dumps({"common/crypto/auth.go": other}),
        }))
        for filename, content, rule in [
            ("unreviewed.json", {"xray": executable}, "jfrog-identity-token"),
            ("unreviewed.json", {"common/crypto/auth.go": source}, "generic-api-key"),
            (base + "measurements.tar.gz!unreviewed/manifest.json", {"xray": executable}, "jfrog-identity-token"),
        ]:
            self.assertIn((filename, rule), self.scan({filename: json.dumps(content)}))
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({
            name: json.dumps({"api_key": synthetic}) for name in [manifest, inspection]
        }), {(name, "generic-api-key") for name in (manifest, inspection)})

    def test_download_manifest_and_log_digests_are_derived_and_narrow(self):
        base = "docs/benchmarks/results/2026-10-02-v08-download/"
        manifest = base + "measurements.tar.gz!comparison/attempts/vmess-aes128-socks-upload-1-1/manifest.json"
        digest = "fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99"
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        self.assertEqual(self.scan({manifest: json.dumps({"xray": digest})}), set())
        outside = base + "measurements.tar.gz!unreviewed/manifest.json"
        self.assertEqual(self.scan({
            manifest: json.dumps({"xray": other}),
            outside: json.dumps({"xray": digest}),
        }), {(name, "jfrog-identity-token") for name in (manifest, outside)})
        index_path = base + "evidence-index.json"
        index = json.loads((ROOT / index_path).read_text())
        with tarfile.open(ROOT / base / "measurements.tar.gz") as archive:
            for name in ["investigation/xray-interop.log", "investigation/xray-mux.log"]:
                value = hashlib.sha256(archive.extractfile(name).read()).hexdigest()
                self.assertEqual(value, index["file_sha256"][name])
                self.assertEqual(self.scan({index_path: json.dumps({name: value})}), set())
                self.assertIn(("unreviewed.json", "jfrog-identity-token"), self.scan({
                    "unreviewed.json": json.dumps({name: value}),
                }))
        self.assertIn((index_path, "jfrog-identity-token"), self.scan({
            index_path: json.dumps({"investigation/xray-interop.log": other}),
        }))
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({
            name: json.dumps({"api_key": synthetic}) for name in [manifest, index_path]
        }), {(name, "generic-api-key") for name in (manifest, index_path)})

    def test_send_manifest_and_log_digests_are_derived_and_narrow(self):
        base = "docs/benchmarks/results/2026-10-01-v08-send/"
        manifest = base + "measurements.tar.gz!comparison/attempts/vmess-aes128-socks-upload-1-1/manifest.json"
        digest = "fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99"
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        self.assertEqual(self.scan({manifest: json.dumps({"xray": digest})}), set())
        outside = base + "measurements.tar.gz!unreviewed/manifest.json"
        self.assertEqual(self.scan({
            manifest: json.dumps({"xray": other}),
            outside: json.dumps({"xray": digest}),
        }), {(name, "jfrog-identity-token") for name in (manifest, outside)})
        index_path = base + "evidence-index.json"
        index = json.loads((ROOT / index_path).read_text())
        with tarfile.open(ROOT / base / "measurements.tar.gz") as archive:
            for name in ["investigation/xray-interop.log", "investigation/xray-mux.log"]:
                value = hashlib.sha256(archive.extractfile(name).read()).hexdigest()
                self.assertEqual(value, index["file_sha256"][name])
                self.assertEqual(self.scan({index_path: json.dumps({name: value})}), set())
                self.assertIn(("unreviewed.json", "jfrog-identity-token"), self.scan({
                    "unreviewed.json": json.dumps({name: value}),
                }))
        self.assertIn((index_path, "jfrog-identity-token"), self.scan({
            index_path: json.dumps({"investigation/xray-interop.log": other}),
        }))
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({
            name: json.dumps({"api_key": synthetic}) for name in [manifest, index_path]
        }), {(name, "generic-api-key") for name in (manifest, index_path)})

    def test_batch_manifest_and_log_digests_are_derived_and_narrow(self):
        base = "docs/benchmarks/results/2026-10-01-v08-batch/"
        manifest = base + "measurements.tar.gz!comparison/attempts/vmess-aes128-socks-upload-1-1/manifest.json"
        digest = "fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99"
        other = "e79a0029cc782ff8166c708f8c911ef39de33563b71a30df2cd2ff1d63d799ab"
        self.assertEqual(self.scan({manifest: json.dumps({"xray": digest})}), set())
        outside = base + "measurements.tar.gz!comparison/unreviewed.json"
        self.assertEqual(self.scan({
            manifest: json.dumps({"xray": other}),
            outside: json.dumps({"xray": digest}),
        }), {(name, "jfrog-identity-token") for name in (manifest, outside)})
        index_path = base + "evidence-index.json"
        index = json.loads((ROOT / index_path).read_text())
        with tarfile.open(ROOT / base / "measurements.tar.gz") as archive:
            for name in ["investigation/xray-interop.log", "investigation/xray-mux.log"]:
                value = hashlib.sha256(archive.extractfile(name).read()).hexdigest()
                self.assertEqual(value, index["file_sha256"][name])
                self.assertEqual(self.scan({index_path: json.dumps({name: value})}), set())
                self.assertIn(("unreviewed.json", "jfrog-identity-token"), self.scan({
                    "unreviewed.json": json.dumps({name: value}),
                }))
        self.assertIn((index_path, "jfrog-identity-token"), self.scan({
            index_path: json.dumps({"investigation/xray-interop.log": other}, indent=2),
        }))
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        self.assertEqual(self.scan({
            name: json.dumps({"api_key": synthetic}) for name in [manifest, index_path]
        }), {(name, "generic-api-key") for name in (manifest, index_path)})

    def test_same_values_outside_reviewed_paths_are_detected(self):
        self.assertEqual(self.scan({
            "unreviewed.json": json.dumps({"api_key": DIGEST}),
            "unreviewed.py": json.dumps({"privateKey": PUBLIC_FIXTURE}),
        }), {("unreviewed.json", "generic-api-key"),
             ("unreviewed.py", "generic-api-key")})

    def test_other_rules_still_scan_reviewed_paths(self):
        # Synthetic scanner control, assembled to avoid embedding a token literal.
        token = "ghp_" + "aB7cD9eF2gH4iJ6kL8mN0oP1qR3sT5uV7wX9"
        self.assertIn((INDEX, "github-pat"), self.scan({INDEX: token}))

    def test_exact_archive_digests_are_allowed(self):
        config = tomllib.loads((ROOT / ".gitleaks.toml").read_text())
        reviewed = [item for item in config["allowlists"]
                    if item.get("description") == ARCHIVE_ALLOWLIST]
        self.assertEqual(len(reviewed), 1)
        expressions = reviewed[0]["regexes"]
        self.assertEqual(len(expressions), 9)
        for expression in expressions:
            self.assertRegex(expression, r"^\^[0-9a-f]{64}\$$")
            digest = expression[1:-1]
            with self.subTest(digest=digest):
                self.assertEqual(self.scan({
                    ARCHIVE_INDEX: json.dumps({"fixture/private-key.pem": digest}),
                    "unreviewed.json": json.dumps({"api_key": digest}),
                }), {("unreviewed.json", "generic-api-key")})

    def test_archive_index_still_detects_unreviewed_values_and_other_rules(self):
        synthetic = "ABcdeF01234" + "GHijk56789lMno"
        for value in (DIGEST, synthetic):
            with self.subTest(value=value):
                self.assertEqual(self.scan({
                    ARCHIVE_INDEX: json.dumps({"api_key": value}),
                }), {(ARCHIVE_INDEX, "generic-api-key")})
        token = "ghp_" + "aB7cD9eF2gH4iJ6kL8mN0oP1qR3sT5uV7wX9"
        self.assertIn((ARCHIVE_INDEX, "github-pat"), self.scan({ARCHIVE_INDEX: token}))


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Exercise evidence exceptions with Gitleaks, including positive leak controls."""

import json
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
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

#!/usr/bin/env python3
"""Reject network-capable or unreviewed credentials in committed JSON fixtures."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import subprocess
import unittest
import unittest.mock
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = REPOSITORY_ROOT / "tests" / "fixtures"
CONFIG_FIXTURE_ROOT = FIXTURE_ROOT / "configs"

IPV4_PATTERN = re.compile(
    r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])"
)
IPV6_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:])"
    r"(?:[0-9A-Fa-f]{0,4}:){2,7}"
    r"(?:[0-9A-Fa-f]{0,4}|(?:[0-9]{1,3}\.){3}[0-9]{1,3})"
    r"(?![0-9A-Fa-f:])"
)

SENSITIVE_CONFIG_FIELDS = frozenset(
    {
        "apikey",
        "id",
        "password",
        "privatekey",
        "publickey",
        "secret",
        "secretkey",
        "shortid",
        "shortids",
        "token",
        "uuid",
    }
)
NETWORK_CONFIG_FIELDS = frozenset(
    {
        "address",
        "dest",
        "server",
        "servername",
        "servernames",
    }
)
RESERVED_TEST_HOST_SUFFIXES = (
    "example",
    "example.com",
    "example.net",
    "example.org",
    "invalid",
    "localhost",
    "test",
)

# These SHA-256 digests represent reviewed deterministic UUID, short-ID, and
# X25519 test vectors. Keeping only digests here prevents the scanner from
# echoing credential-shaped fixture values in logs.
APPROVED_TEST_CREDENTIAL_DIGESTS = frozenset(
    {
        "0f007385b6f9d4b7eeb2748605afe1a984a0a3bfa3f014d09e2a784ce9e5cd1a",
        "11e594f481958c10e3015d0bf0447a22f068a8a647f475df15ce2c7ab4b8f3f1",
        "56d5fa7333f6d747db42c239407e5da4c32f4c79f35d092b134fd35a402d9c5c",
        "811de8804c16858aed0005d14b32269fecf6958183ed0d26b75944fc10d7f66c",
        "81626265a14b6f89251789d8e011e6fb0ca2dd94c8f8805ef6080fbd3c24f9d0",
        "9f9f5111f7b27a781f1f1ddde5ebc2dd2b796bfc7365c9c28b548e564176929f",
        "f920f1583dc9da3bc0569e6e1dc5f231b1292cbe378c62c0d88f599a7e68dab1",
    }
)

# SHA-256 digests of values retired from a previously committed live profile.
# The scanner compares candidate tokens by digest so neither CI output nor this
# source file republishes the credential-shaped values.
#
# Only high-entropy values belong here. An unsalted digest protects a value
# only as far as its keyspace: the retired profile's server address (2^32) and
# camouflage SNI (a dictionary word) would be recoverable from these digests
# alone, so listing them would publish what it claims to withhold. Those two
# are documented in SECURITY.md instead, which is honest about the fact that
# they are disclosed and cannot be rotated in place. The three below carry
# 122, 256 and 64 bits, so their digests disclose nothing.
FORBIDDEN_RETIRED_VALUE_DIGESTS = frozenset(
    {
        # VLESS user id
        "06327ebbc9e96a163b6257670e31f2c515b925971e64adf00ecff91994b1e6bb",
        # REALITY public key
        "8b4d2a0196fb8f3666ac618cf7e20cc9c058f54608259a07a1b4903acf2c869e",
        # REALITY short id
        "9b49e93352a26c7e2831a2b04061d59f30d54b2ebd11f2adb9a1b781d54c571d",
    }
)

# Commits that carried the retired values before they were scrubbed in
# 755a3a4 ("Prepare repository for open source release", 2026-07-27). The
# disclosure is recorded in SECURITY.md and the profile has been revoked
# server-side; rewriting these commits would invalidate every published
# commit SHA without withdrawing anything that is already public, so the
# history scan grandfathers them by identity rather than by date. Any other
# commit carrying a retired value — including a new one — still fails.
GRANDFATHERED_RETIRED_VALUE_COMMITS = frozenset(
    {
        "2d8d92e141acc4d65638df6cb41ff1ca0200b10c",
        "755a3a40e6f1abb58a768a80b5babea62d14f00f",
    }
)
RETIRED_VALUE_CANDIDATE_PATTERN = re.compile(
    r"(?<![A-Za-z0-9._:-])[A-Za-z0-9][A-Za-z0-9._:-]{5,127}"
)
# Marks the start of each commit in the history scan's log output. Every patch
# body line is prefixed by git with a space, `+`, `-`, `\` or `@`, so only a
# format header can begin a line with this marker.
COMMIT_HEADER_PREFIX = "__retired_value_scan_commit__ "


def normalized_field_name(field_name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", field_name.lower())


def tracked_unignored_paths(*pathspecs: str) -> list[Path]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            *pathspecs,
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
    )
    paths = result.stdout.decode("utf-8").split("\0")
    return sorted(REPOSITORY_ROOT / path for path in paths if path)


def tracked_json_fixtures() -> list[Path]:
    return [
        path
        for path in tracked_unignored_paths("tests/fixtures")
        if path.suffix.lower() == ".json"
    ]


def addresses_in(value: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for pattern in (IPV4_PATTERN, IPV6_PATTERN):
        for candidate in pattern.findall(value):
            try:
                addresses.add(ipaddress.ip_address(candidate))
            except ValueError:
                continue
    return addresses


def host_from_network_value(value: str) -> str | None:
    candidate = value.strip().lower()
    if not candidate:
        return None

    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1:
        host, port = candidate.rsplit(":", 1)
        if port.isdigit():
            candidate = host

    candidate = candidate.split("/", 1)[0].rstrip(".")
    try:
        ipaddress.ip_address(candidate)
        return None
    except ValueError:
        return candidate


def is_reserved_test_host(host: str) -> bool:
    return any(
        host == suffix or host.endswith(f".{suffix}")
        for suffix in RESERVED_TEST_HOST_SUFFIXES
    )


def json_path(parts: tuple[str, ...]) -> str:
    return ".".join(parts) if parts else "$"


def scan_scalar(
    *,
    file_path: Path,
    path: tuple[str, ...],
    owner_field: str,
    value: str,
    is_config_fixture: bool,
) -> list[str]:
    relative_path = file_path.relative_to(REPOSITORY_ROOT)
    location = f"{relative_path}:{json_path(path)}"
    violations = [
        f"{location}: globally routable IP literals are forbidden in fixtures"
        for address in addresses_in(value)
        if address.is_global
    ]

    if not is_config_fixture:
        return violations

    normalized_field = normalized_field_name(owner_field)
    if normalized_field in SENSITIVE_CONFIG_FIELDS:
        digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
        if digest not in APPROVED_TEST_CREDENTIAL_DIGESTS:
            violations.append(
                f"{location}: credential-shaped value is not an approved test vector"
            )

    if normalized_field in NETWORK_CONFIG_FIELDS:
        host = host_from_network_value(value)
        if host is not None and not is_reserved_test_host(host):
            violations.append(
                f"{location}: network endpoint must use a reserved test hostname"
            )

    return violations


def scan_document(file_path: Path, document: Any) -> list[str]:
    violations: list[str] = []
    is_config_fixture = file_path.is_relative_to(CONFIG_FIXTURE_ROOT)

    def visit(value: Any, path: tuple[str, ...], owner_field: str) -> None:
        if isinstance(value, dict):
            for field, child in value.items():
                violations.extend(
                    scan_scalar(
                        file_path=file_path,
                        path=(*path, "<object-key>"),
                        owner_field="",
                        value=field,
                        is_config_fixture=False,
                    )
                )
                visit(child, (*path, field), field)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, (*path, str(index)), owner_field)
        elif isinstance(value, str):
            violations.extend(
                scan_scalar(
                    file_path=file_path,
                    path=path,
                    owner_field=owner_field,
                    value=value,
                    is_config_fixture=is_config_fixture,
                )
            )

    visit(document, (), "")
    return violations


def scan_repository_fixtures() -> list[str]:
    violations: list[str] = []
    for file_path in tracked_json_fixtures():
        try:
            with file_path.open(encoding="utf-8") as fixture:
                document = json.load(fixture)
        except (OSError, UnicodeError, json.JSONDecodeError) as error:
            relative_path = file_path.relative_to(REPOSITORY_ROOT)
            violations.append(f"{relative_path}: invalid JSON fixture: {error}")
            continue
        violations.extend(scan_document(file_path, document))
    return violations


def retired_value_lines(
    text: str, forbidden_digests: frozenset[str] = FORBIDDEN_RETIRED_VALUE_DIGESTS
) -> set[int]:
    matching_lines: set[int] = set()
    for line_number, line in enumerate(text.splitlines(), start=1):
        for match in RETIRED_VALUE_CANDIDATE_PATTERN.finditer(line):
            token = match.group(0)
            candidates = {token, *token.split(":")}
            if any(
                hashlib.sha256(candidate.encode("utf-8")).hexdigest()
                in forbidden_digests
                for candidate in candidates
            ):
                matching_lines.add(line_number)
    return matching_lines


def scan_repository_for_retired_values() -> list[str]:
    violations: list[str] = []
    for file_path in tracked_unignored_paths():
        try:
            contents = file_path.read_bytes()
        except OSError as error:
            relative_path = file_path.relative_to(REPOSITORY_ROOT)
            violations.append(f"{relative_path}: could not scan tracked file: {error}")
            continue

        if b"\0" in contents:
            continue
        try:
            text = contents.decode("utf-8")
        except UnicodeDecodeError:
            continue

        relative_path = file_path.relative_to(REPOSITORY_ROOT)
        violations.extend(
            f"{relative_path}:{line_number}: retired live-profile value is forbidden"
            for line_number in sorted(retired_value_lines(text))
        )
    return violations


def commits_carrying_retired_values(
    forbidden_digests: frozenset[str] = FORBIDDEN_RETIRED_VALUE_DIGESTS,
) -> set[str]:
    """Return the commits whose patch text carries a retired value.

    The log is emitted with a `%H` header per commit so a hit can be attributed
    to the commit that carries it, rather than only reported for the history as
    a whole.
    """
    history = subprocess.run(
        [
            "git",
            "log",
            "--all",
            "--patch",
            "--no-ext-diff",
            "--no-textconv",
            f"--format={COMMIT_HEADER_PREFIX}%H",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8", errors="ignore")

    offenders: set[str] = set()
    current_commit: str | None = None
    pending: list[str] = []

    def flush() -> None:
        if current_commit is not None and retired_value_lines(
            "\n".join(pending), forbidden_digests
        ):
            offenders.add(current_commit)

    for line in history.splitlines():
        if line.startswith(COMMIT_HEADER_PREFIX):
            flush()
            current_commit = line[len(COMMIT_HEADER_PREFIX) :].strip()
            pending = []
            continue
        pending.append(line)
    flush()
    return offenders


def scan_git_history_for_retired_values() -> list[str]:
    offenders = commits_carrying_retired_values()
    unexpected = sorted(offenders - GRANDFATHERED_RETIRED_VALUE_COMMITS)
    missing = sorted(GRANDFATHERED_RETIRED_VALUE_COMMITS - offenders)

    violations = [
        f"git history: {commit} carries a retired live-profile value"
        for commit in unexpected
    ]
    # A grandfathered commit that no longer matches means history was rewritten
    # or the digest set changed; either way the allowlist has stopped
    # describing reality and must be re-derived rather than silently trusted.
    violations.extend(
        f"git history: grandfathered commit {commit} no longer carries a "
        "retired value; re-derive GRANDFATHERED_RETIRED_VALUE_COMMITS"
        for commit in missing
    )
    return violations


class JsonFixtureSafetyTests(unittest.TestCase):
    def test_committed_json_fixtures_are_offline_safe(self) -> None:
        violations = [
            *scan_repository_fixtures(),
            *scan_repository_for_retired_values(),
        ]
        if os.environ.get("XRAY_FIXTURE_SCAN_HISTORY") == "1":
            violations.extend(scan_git_history_for_retired_values())

        self.assertEqual([], violations, "\n" + "\n".join(violations))

    def test_global_ips_are_rejected_without_echoing_them(self) -> None:
        for value in ("8.8.8.8", "2606:4700:4700::1111"):
            with self.subTest(value=value):
                violations = scan_scalar(
                    file_path=CONFIG_FIXTURE_ROOT / "synthetic.json",
                    path=("address",),
                    owner_field="address",
                    value=value,
                    is_config_fixture=True,
                )
                self.assertEqual(
                    [
                        "tests/fixtures/configs/synthetic.json:address: "
                        "globally routable IP literals are forbidden in fixtures"
                    ],
                    violations,
                )

    def test_documentation_addresses_are_allowed(self) -> None:
        for value in ("192.0.2.10", "198.51.100.53", "203.0.113.53", "2001:db8::1"):
            with self.subTest(value=value):
                violations = scan_scalar(
                    file_path=CONFIG_FIXTURE_ROOT / "synthetic.json",
                    path=("address",),
                    owner_field="address",
                    value=value,
                    is_config_fixture=True,
                )
                self.assertEqual([], violations)

    def test_unreviewed_credential_is_rejected_without_echoing_it(self) -> None:
        violations = scan_scalar(
            file_path=CONFIG_FIXTURE_ROOT / "synthetic.json",
            path=("users", "0", "id"),
            owner_field="id",
            value="unreviewed-test-value",
            is_config_fixture=True,
        )

        self.assertEqual(
            [
                "tests/fixtures/configs/synthetic.json:users.0.id: "
                "credential-shaped value is not an approved test vector"
            ],
            violations,
        )

    def test_retired_value_detection_does_not_echo_the_value(self) -> None:
        retired_value = "synthetic-retired-value"
        retired_digest = hashlib.sha256(retired_value.encode("utf-8")).hexdigest()

        matching_lines = retired_value_lines(
            f"safe\n{retired_value}\nsafe\n", frozenset({retired_digest})
        )

        self.assertEqual({2}, matching_lines)

    def test_history_scan_grandfathers_only_the_listed_commits(self) -> None:
        newcomer = "0" * 40

        with unittest.mock.patch(
            f"{__name__}.commits_carrying_retired_values",
            return_value={*GRANDFATHERED_RETIRED_VALUE_COMMITS, newcomer},
        ):
            violations = scan_git_history_for_retired_values()

        self.assertEqual(
            [f"git history: {newcomer} carries a retired live-profile value"],
            violations,
        )

    def test_history_scan_reports_a_stale_allowlist(self) -> None:
        expected = sorted(GRANDFATHERED_RETIRED_VALUE_COMMITS)

        with unittest.mock.patch(
            f"{__name__}.commits_carrying_retired_values", return_value=set()
        ):
            violations = scan_git_history_for_retired_values()

        self.assertEqual(
            [
                f"git history: grandfathered commit {commit} no longer carries "
                "a retired value; re-derive GRANDFATHERED_RETIRED_VALUE_COMMITS"
                for commit in expected
            ],
            violations,
        )

    def test_history_scan_attributes_hits_to_their_commit(self) -> None:
        retired_value = "synthetic-retired-value"
        retired_digest = hashlib.sha256(retired_value.encode("utf-8")).hexdigest()
        clean_sha, dirty_sha = "a" * 40, "b" * 40
        log = (
            f"{COMMIT_HEADER_PREFIX}{clean_sha}\n"
            "+let untouched = 1;\n"
            f"{COMMIT_HEADER_PREFIX}{dirty_sha}\n"
            f"+let leaked = \"{retired_value}\";\n"
        )

        with unittest.mock.patch(f"{__name__}.subprocess.run") as run:
            run.return_value = subprocess.CompletedProcess(
                args=(), returncode=0, stdout=log.encode("utf-8")
            )
            offenders = commits_carrying_retired_values(frozenset({retired_digest}))

        self.assertEqual({dirty_sha}, offenders)


if __name__ == "__main__":
    unittest.main()

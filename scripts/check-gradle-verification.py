#!/usr/bin/env python3
"""Check Gradle SHA-256 locks against canonical Maven SHA-1 sidecars."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import pathlib
import re
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET


GOOGLE_PREFIXES = (
    "androidx.",
    "com.android",
    "com.google.android",
    "com.google.testing.platform",
)
GOOGLE_ROOT = "https://dl.google.com/dl/android/maven2"
CENTRAL_ROOT = "https://repo.maven.apache.org/maven2"
PLUGIN_ROOT = "https://plugins.gradle.org/m2"
VERIFIED_ORIGIN = "Canonical Maven repository (published sidecar verified)"
SHA1 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
MD5 = re.compile(r"^[0-9a-f]{32}$")


class VerificationError(Exception):
    pass


def repositories(group: str) -> tuple[str, ...]:
    if group.startswith(GOOGLE_PREFIXES):
        return GOOGLE_ROOT, CENTRAL_ROOT, PLUGIN_ROOT
    return CENTRAL_ROOT, GOOGLE_ROOT, PLUGIN_ROOT


def curl_arguments(url: str) -> list[str]:
    return [
        "curl",
        "--fail",
        "--location",
        "--silent",
        "--show-error",
        "--proto",
        "=https",
        "--tlsv1.2",
        "--retry",
        "3",
        "--connect-timeout",
        "10",
        "--max-time",
        "60",
        "--user-agent",
        "xray-rust-gradle-verifier/1.0",
        url,
    ]


def verify_remote(item: tuple[tuple[str, ...], str, str]) -> str:
    urls, expected_sha256, label = item
    failures = []
    for url in urls:
        try:
            verify_remote_url(url, expected_sha256, label)
            return label
        except VerificationError as error:
            failures.append(str(error))
    raise VerificationError(f"{label}: no canonical repository matched: {'; '.join(failures)}")


def verify_remote_url(url: str, expected_sha256: str, label: str) -> None:
    try:
        sidecar = ""
        sidecar_algorithm = ""
        # Some canonical Maven metadata artifacts publish only an MD5 sidecar.
        # The artifact itself is still fetched over HTTPS and must match the
        # independently recorded Gradle SHA-256; the sidecar binds it to the
        # canonical repository's published object.
        for algorithm, pattern in (("sha256", SHA256), ("sha1", SHA1), ("md5", MD5)):
            sidecar_result = subprocess.run(
                curl_arguments(f"{url}.{algorithm}"),
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if sidecar_result.returncode == 0:
                candidate = sidecar_result.stdout.decode("ascii", "strict").strip().split()[0].lower()
                if not pattern.fullmatch(candidate):
                    raise VerificationError(f"{label}: invalid canonical {algorithm} sidecar")
                sidecar = candidate
                sidecar_algorithm = algorithm
                break
        if not sidecar_algorithm:
            raise VerificationError(f"{label}: canonical repository has no checksum sidecar")
        published = hashlib.new(sidecar_algorithm, usedforsecurity=False)
        sha256 = hashlib.sha256()
        process = subprocess.Popen(
            curl_arguments(url), stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        assert process.stdout is not None
        while chunk := process.stdout.read(1024 * 1024):
            published.update(chunk)
            sha256.update(chunk)
        _, stderr = process.communicate()
        if process.returncode != 0:
            raise VerificationError(
                f"{label}: canonical download failed: {stderr.decode(errors='replace').strip()}"
            )
    except (OSError, UnicodeError, subprocess.CalledProcessError) as error:
        raise VerificationError(f"{label}: canonical download failed: {error}") from error
    if published.hexdigest() != sidecar:
        raise VerificationError(f"{label}: artifact differs from its canonical sidecar")
    if sha256.hexdigest() != expected_sha256:
        raise VerificationError(f"{label}: artifact differs from Gradle SHA-256 metadata")


def parse_metadata(path: pathlib.Path, allow_generated: bool):
    root = ET.parse(path).getroot()
    namespace = {"v": root.tag.partition("}")[0].removeprefix("{")}
    verify_metadata = root.find("v:configuration/v:verify-metadata", namespace)
    if verify_metadata is None or verify_metadata.text != "true":
        raise VerificationError("Gradle metadata verification is not enabled")
    forbidden = root.find("v:configuration/v:trusted-artifacts", namespace)
    if forbidden is not None and list(forbidden):
        raise VerificationError("broad trusted-artifacts bypasses are forbidden")

    items = []
    for component in root.findall("v:components/v:component", namespace):
        group = component.attrib["group"]
        name = component.attrib["name"]
        version = component.attrib["version"]
        roots = repositories(group)
        base = "/".join(
            urllib.parse.quote(part, safe="")
            for part in (*group.split("."), name, version)
        )
        for artifact in component.findall("v:artifact", namespace):
            artifact_name = artifact.attrib["name"]
            checksums = artifact.findall("v:sha256", namespace)
            if len(checksums) != 1:
                raise VerificationError(
                    f"{group}:{name}:{version}:{artifact_name}: exactly one SHA-256 is required"
                )
            checksum = checksums[0].attrib.get("value", "")
            origin = checksums[0].attrib.get("origin", "")
            if not SHA256.fullmatch(checksum):
                raise VerificationError(
                    f"{group}:{name}:{version}:{artifact_name}: invalid SHA-256"
                )
            if origin != VERIFIED_ORIGIN and not allow_generated:
                raise VerificationError(
                    f"{group}:{name}:{version}:{artifact_name}: unverified origin {origin!r}"
                )
            label = f"{group}:{name}:{version}:{artifact_name}"
            suffix = f"{base}/{urllib.parse.quote(artifact_name, safe='')}"
            urls = tuple(f"{root_url}/{suffix}" for root_url in roots)
            items.append((urls, checksum, label))
    if not items:
        raise VerificationError("Gradle verification metadata contains no artifacts")
    return items


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("metadata", type=pathlib.Path)
    parser.add_argument("--online", action="store_true")
    parser.add_argument("--allow-generated", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        items = parse_metadata(args.metadata, args.allow_generated)
        if args.online:
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                futures = [executor.submit(verify_remote, item) for item in items]
                for future in concurrent.futures.as_completed(futures):
                    future.result()
    except (ET.ParseError, OSError, VerificationError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    suffix = " and canonical repositories" if args.online else ""
    print(f"verified {len(items)} Gradle artifacts against checksum policy{suffix}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

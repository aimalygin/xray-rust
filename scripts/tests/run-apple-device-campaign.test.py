#!/usr/bin/env python3
"""Contract checks for rehearsal-only Apple campaign build reuse."""

from __future__ import annotations

import pathlib
import runpy
import subprocess
import sys
import tempfile


def run(arguments: list[str], root: pathlib.Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(root / "scripts/run-apple-device-campaign.py"), *arguments],
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    campaign_module = runpy.run_path(str(root / "scripts/run-apple-device-campaign.py"))
    failed_probe = campaign_module["FAILED_PROBE"]
    match = failed_probe.fullmatch(
        "XRAY_DEVICE_PROBE kind=udp result=failed error=udp-timeout"
    )
    if match is None or match.groups() != ("udp", "udp-timeout"):
        raise AssertionError("campaign runner does not recognize bounded failed probes")
    if failed_probe.fullmatch(
        "XRAY_DEVICE_PROBE kind=udp result=failed error=secret value"
    ) is not None:
        raise AssertionError("campaign runner accepts unsafe failed-probe text")
    help_result = run(["--help"], root)
    if help_result.returncode != 0 or "--skip-test-build" not in help_result.stdout:
        raise AssertionError("campaign help does not expose --skip-test-build")

    with tempfile.TemporaryDirectory(prefix="xray-apple-campaign-contract-") as raw:
        temporary = pathlib.Path(raw)
        common = [
            "--device-id",
            "contract-device",
            "--http-url",
            "https://127.0.0.1/probe",
            "--udp-host",
            "127.0.0.1",
            "--udp-port",
            "53053",
            "--derived-data",
            str(temporary / "derived"),
            "--skip-test-build",
        ]

        recursive_common = list(common)
        recursive_common[7] = "53"
        recursive_dns = run(
            [
                *recursive_common,
                "--campaign-id",
                "recursive-dns",
                "--campaign-dir",
                str(temporary / "recursive-dns"),
                "--duration-seconds",
                "30",
                "--rehearsal",
            ],
            root,
        )
        if recursive_dns.returncode == 0 or (
            "dedicated non-DNS probe endpoint" not in recursive_dns.stderr
        ):
            raise AssertionError(
                f"recursive DNS endpoint was not rejected: {recursive_dns.stderr}"
            )
        if (temporary / "recursive-dns").exists():
            raise AssertionError("recursive DNS rejection created a campaign directory")

        formal = run(
            [
                *common,
                "--campaign-id",
                "formal-skip",
                "--campaign-dir",
                str(temporary / "formal"),
            ],
            root,
        )
        if formal.returncode == 0 or (
            "formal campaigns cannot skip the Xcode test build" not in formal.stderr
        ):
            raise AssertionError(f"formal skip was not rejected: {formal.stderr}")
        if (temporary / "formal").exists():
            raise AssertionError("formal skip created a campaign directory")

        rehearsal = run(
            [
                *common,
                "--campaign-id",
                "rehearsal-skip",
                "--campaign-dir",
                str(temporary / "rehearsal"),
                "--duration-seconds",
                "30",
                "--rehearsal",
                "--skip-xcframework-build",
                "--skip-instruments",
            ],
            root,
        )
        expected = "expected one arm64 XrayClient xctestrun"
        if rehearsal.returncode == 0 or expected not in rehearsal.stderr:
            raise AssertionError(
                "rehearsal did not reuse/validate DerivedData: " + rehearsal.stderr
            )
        if "Xcode test build failed" in rehearsal.stderr:
            raise AssertionError("rehearsal unexpectedly attempted an Xcode test build")

    print("Apple device campaign build-reuse contract test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

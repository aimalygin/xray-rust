#!/usr/bin/env python3
"""Contract checks for rehearsal-only Apple campaign build reuse."""

from __future__ import annotations

import pathlib
import plistlib
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
    parse_memory_result = campaign_module["parse_memory_result"]
    prepare_xctestrun = campaign_module["prepare_xctestrun"]
    match = failed_probe.fullmatch(
        "XRAY_DEVICE_PROBE kind=udp result=failed error=udp-timeout"
    )
    if match is None or match.groups() != ("udp", "udp-timeout"):
        raise AssertionError("campaign runner does not recognize bounded failed probes")
    if failed_probe.fullmatch(
        "XRAY_DEVICE_PROBE kind=udp result=failed error=secret value"
    ) is not None:
        raise AssertionError("campaign runner accepts unsafe failed-probe text")
    memory_result = parse_memory_result(
        "XRAY_DEVICE_MEMORY_RESULT baselineRSS=18000000 peakRSS=90000000 "
        "recoveredRSS=80000000 baselinePhysicalFootprint=17000000 "
        "peakPhysicalFootprint=53000000 recoveredPhysicalFootprint=36000000 "
        "stressCycles=2 firstCyclePeakPhysicalFootprint=52000000 "
        "firstCycleRecoveredPhysicalFootprint=35000000 "
        "secondCyclePeakPhysicalFootprint=53000000 "
        "secondCycleRecoveredPhysicalFootprint=36000000 "
        "plateauAllowancePhysicalFootprint=8388608 "
        "safetyLimitPhysicalFootprint=60000000 "
        "safetyLimitReached=false stopStage=none highestTCPFlows=240 "
        "highestUDPFlows=480 closedConnections=1440"
    )
    if memory_result != {
        "baselineRSSBytes": 18_000_000,
        "peakRSSBytes": 90_000_000,
        "recoveredRSSBytes": 80_000_000,
        "baselinePhysicalFootprintBytes": 17_000_000,
        "peakPhysicalFootprintBytes": 53_000_000,
        "recoveredPhysicalFootprintBytes": 36_000_000,
        "stressCycles": 2,
        "firstCyclePeakPhysicalFootprintBytes": 52_000_000,
        "firstCycleRecoveredPhysicalFootprintBytes": 35_000_000,
        "secondCyclePeakPhysicalFootprintBytes": 53_000_000,
        "secondCycleRecoveredPhysicalFootprintBytes": 36_000_000,
        "plateauAllowancePhysicalFootprintBytes": 8_388_608,
        "safetyLimitPhysicalFootprintBytes": 60_000_000,
        "safetyLimitReached": False,
        "stopStage": "none",
        "highestTCPFlowsWithinLimit": 240,
        "highestUDPFlowsWithinLimit": 480,
        "closedConnections": 1440,
    }:
        raise AssertionError(f"unexpected parsed memory result: {memory_result}")
    try:
        parse_memory_result(
            "XRAY_DEVICE_MEMORY_RESULT baselineRSS=18000000 peakRSS=52000000 "
            "recoveredRSS=51000000 baselinePhysicalFootprint=17000000 "
            "peakPhysicalFootprint=52000000 recoveredPhysicalFootprint=19000000 "
            "stressCycles=2 firstCyclePeakPhysicalFootprint=51000000 "
            "firstCycleRecoveredPhysicalFootprint=19000000 "
            "secondCyclePeakPhysicalFootprint=52000000 "
            "secondCycleRecoveredPhysicalFootprint=19000000 "
            "plateauAllowancePhysicalFootprint=8388608 "
            "safetyLimitPhysicalFootprint=50331648 "
            "safetyLimitReached=false stopStage=none highestTCPFlows=240 "
            "highestUDPFlows=480 closedConnections=720"
        )
    except campaign_module["CampaignError"]:
        pass
    else:
        raise AssertionError("campaign runner accepted an inconsistent safety result")
    help_result = run(["--help"], root)
    if (
        help_result.returncode != 0
        or "--skip-test-build" not in help_result.stdout
        or "--memory-stress" not in help_result.stdout
    ):
        raise AssertionError("campaign help does not expose --skip-test-build")

    with tempfile.TemporaryDirectory(prefix="xray-apple-campaign-contract-") as raw:
        temporary = pathlib.Path(raw)
        source_xctestrun = temporary / "source.xctestrun"
        source_xctestrun.write_bytes(
            plistlib.dumps(
                {
                    "TestConfigurations": [
                        {
                            "TestTargets": [
                                {
                                    "BlueprintName": "XrayClientUITests",
                                    "EnvironmentVariables": {},
                                }
                            ]
                        }
                    ]
                },
                fmt=plistlib.FMT_BINARY,
            )
        )
        generated_xctestrun = prepare_xctestrun(
            source_xctestrun,
            "secure-memory",
            240,
            5,
            "https://127.0.0.1/probe",
            "127.0.0.1",
            53053,
            True,
            {"XRAY_DEVICE_MEMORY_STRESS_TOKEN": "a" * 64},
        )
        if generated_xctestrun.stat().st_mode & 0o777 != 0o600:
            raise AssertionError("generated xctestrun is not owner-only")
        with generated_xctestrun.open("rb") as input_file:
            generated_document = plistlib.load(input_file)
        generated_environment = generated_document["TestConfigurations"][0][
            "TestTargets"
        ][0]["EnvironmentVariables"]
        if generated_environment.get("XRAY_DEVICE_MEMORY_STRESS_TOKEN") != "a" * 64:
            raise AssertionError("generated xctestrun omitted the memory token")
        generated_xctestrun.unlink()

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

        missing_load_endpoint = run(
            [
                *common,
                "--campaign-id",
                "memory-missing-endpoint",
                "--campaign-dir",
                str(temporary / "memory-missing-endpoint"),
                "--duration-seconds",
                "240",
                "--rehearsal",
                "--memory-stress",
            ],
            root,
        )
        if missing_load_endpoint.returncode == 0 or (
            "memory stress requires" not in missing_load_endpoint.stderr
        ):
            raise AssertionError(
                "memory stress accepted a missing endpoint/token: "
                + missing_load_endpoint.stderr
            )

        token = temporary / "load.token"
        token.write_text("a" * 64 + "\n", encoding="ascii")
        token.chmod(0o600)
        memory_rehearsal = run(
            [
                *common,
                "--campaign-id",
                "memory-rehearsal",
                "--campaign-dir",
                str(temporary / "memory-rehearsal"),
                "--duration-seconds",
                "510",
                "--rehearsal",
                "--memory-stress",
                "--load-host",
                "127.0.0.1",
                "--load-port",
                "53053",
                "--load-token-file",
                str(token),
            ],
            root,
        )
        if memory_rehearsal.returncode == 0 or expected not in memory_rehearsal.stderr:
            raise AssertionError(
                "memory stress did not reach DerivedData validation: "
                + memory_rehearsal.stderr
            )
        if ("a" * 64) in memory_rehearsal.stdout + memory_rehearsal.stderr:
            raise AssertionError("memory stress exposed the load token")

    print("Apple device campaign build-reuse contract test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

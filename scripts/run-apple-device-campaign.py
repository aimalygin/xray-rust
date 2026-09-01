#!/usr/bin/env python3
"""Build, run, and collect the Apple physical-device soak harness."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import plistlib
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
from typing import Any, IO


MIN_FORMAL_DURATION_SECONDS = 6 * 60 * 60
MAX_DURATION_SECONDS = 8 * 60 * 60
MAX_SAMPLE_INTERVAL_SECONDS = 60
SAMPLE_FIELDS = {
    "elapsedSeconds",
    "runtimeGeneration",
    "residentMemoryBytes",
    "threadCount",
    "activeConnections",
    "tunInboundPackets",
    "tunOutboundPackets",
    "fatalTunErrors",
    "unrecoveredTransitions",
}
CAMPAIGN_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
PASSED_PROBE = re.compile(
    r"^XRAY_DEVICE_PROBE kind=(http|udp) result=passed sequence=([1-9][0-9]*)$"
)


class CampaignError(Exception):
    pass


def run_capture(arguments: list[str], root: pathlib.Path) -> str:
    completed = subprocess.run(
        arguments,
        cwd=root,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode != 0:
        raise CampaignError(f"command failed ({arguments[0]}): {completed.stdout.strip()}")
    return completed.stdout


def redact(line: str, secrets: list[str]) -> str:
    redacted = line
    for secret in sorted((value for value in secrets if value), key=len, reverse=True):
        redacted = redacted.replace(secret, "<redacted>")
    redacted = re.sub(r"vless://\S+", "<redacted-vless-url>", redacted, flags=re.IGNORECASE)
    return redacted


def write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written == 0:
            raise CampaignError("short write while recording campaign evidence")
        offset += written


def atomic_write_json(path: pathlib.Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            write_all(
                descriptor,
                (json.dumps(value, sort_keys=True) + "\n").encode("utf-8"),
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def append_json_line(path: pathlib.Path, value: dict[str, Any]) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        write_all(
            descriptor,
            (json.dumps(value, sort_keys=True) + "\n").encode("utf-8"),
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def stream_command(
    arguments: list[str],
    root: pathlib.Path,
    log: IO[str],
    secrets: list[str],
) -> int:
    process = subprocess.Popen(
        arguments,
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    assert process.stdout is not None
    for raw_line in process.stdout:
        line = redact(raw_line, secrets)
        log.write(line)
        log.flush()
        sys.stdout.write(line)
        sys.stdout.flush()
    return process.wait()


def prepare_xctestrun(
    source: pathlib.Path,
    campaign_id: str,
    duration_seconds: int,
    sample_interval_seconds: int,
    HTTP_url: str,
    UDP_host: str,
    UDP_port: int,
    debug_logging_enabled: bool,
) -> pathlib.Path:
    destination = source.with_name(f"XrayClient_{campaign_id}_iphoneos-arm64.xctestrun")
    if destination.exists():
        raise CampaignError(f"generated xctestrun already exists: {destination}")
    with source.open("rb") as input_file:
        document = plistlib.load(input_file)
    configurations = document.get("TestConfigurations", [])
    targets = configurations[0].get("TestTargets", []) if configurations else []
    target = next(
        (item for item in targets if item.get("BlueprintName") == "XrayClientUITests"),
        None,
    )
    if target is None:
        raise CampaignError("XrayClientUITests is missing from generated xctestrun")
    environment = target.setdefault("EnvironmentVariables", {})
    environment.update(
        {
            "XRAY_DEVICE_CAMPAIGN_ENABLED": "1",
            "XRAY_DEVICE_CAMPAIGN_DURATION_SECONDS": str(duration_seconds),
            "XRAY_DEVICE_CAMPAIGN_SAMPLE_INTERVAL_SECONDS": str(
                sample_interval_seconds
            ),
            "XRAY_DEVICE_CAMPAIGN_HTTP_URL": HTTP_url,
            "XRAY_DEVICE_CAMPAIGN_UDP_HOST": UDP_host,
            "XRAY_DEVICE_CAMPAIGN_UDP_PORT": str(UDP_port),
            "XRAY_DEVICE_CAMPAIGN_DEBUG_LOGGING": (
                "1" if debug_logging_enabled else "0"
            ),
        }
    )
    target["DefaultTestExecutionTimeAllowance"] = duration_seconds + 600
    target["UserAttachmentLifetime"] = "keepAlways"
    with destination.open("wb") as output_file:
        plistlib.dump(document, output_file, fmt=plistlib.FMT_BINARY)
    return destination


def find_xctestrun(derived_data: pathlib.Path) -> pathlib.Path:
    products = derived_data / "Build" / "Products"
    matches = sorted(
        path
        for path in products.glob("XrayClient_XrayClient_iphoneos*-arm64.xctestrun")
        if path.is_file() and not path.is_symlink()
    )
    if len(matches) != 1:
        raise CampaignError(
            f"expected one arm64 XrayClient xctestrun under {products}, found {len(matches)}"
        )
    return matches[0]


def validate_samples(path: pathlib.Path) -> list[dict[str, int]]:
    try:
        raw_samples = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CampaignError(f"invalid samples attachment: {error}") from error
    if not isinstance(raw_samples, list) or len(raw_samples) < 2:
        raise CampaignError("samples attachment must contain at least two samples")
    samples: list[dict[str, int]] = []
    previous_elapsed = -1
    for index, raw_sample in enumerate(raw_samples):
        if not isinstance(raw_sample, dict) or set(raw_sample) != SAMPLE_FIELDS:
            raise CampaignError(f"sample {index} has an invalid field set")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in raw_sample.values()
        ):
            raise CampaignError(f"sample {index} contains a non-negative-integer violation")
        if raw_sample["elapsedSeconds"] <= previous_elapsed:
            raise CampaignError("sample elapsed time is not strictly increasing")
        if raw_sample["residentMemoryBytes"] == 0 or raw_sample["threadCount"] == 0:
            raise CampaignError(f"sample {index} is missing resource telemetry")
        if raw_sample["fatalTunErrors"] != 0 or raw_sample["unrecoveredTransitions"] != 0:
            raise CampaignError(f"sample {index} reports a fatal or unrecovered failure")
        previous_elapsed = raw_sample["elapsedSeconds"]
        samples.append(raw_sample)
    if samples[-1]["activeConnections"] != 0:
        raise CampaignError("final sample still has active connections")
    if not any(
        sample["tunInboundPackets"] > 0 and sample["tunOutboundPackets"] > 0
        for sample in samples
    ):
        raise CampaignError("samples do not demonstrate bidirectional TUN traffic")
    return samples


def export_samples(
    root: pathlib.Path,
    result_bundle: pathlib.Path,
    campaign_dir: pathlib.Path,
) -> tuple[pathlib.Path, dict[str, Any]]:
    summary_text = run_capture(
        [
            "xcrun",
            "xcresulttool",
            "get",
            "test-results",
            "summary",
            "--path",
            str(result_bundle),
            "--compact",
        ],
        root,
    )
    summary = json.loads(summary_text)
    if summary.get("result") != "Passed" or summary.get("failedTests") != 0:
        raise CampaignError("xcresult summary is not passing")

    export_dir = campaign_dir / ".attachments-export"
    if export_dir.exists():
        raise CampaignError(f"attachment export path already exists: {export_dir}")
    run_capture(
        [
            "xcrun",
            "xcresulttool",
            "export",
            "attachments",
            "--path",
            str(result_bundle),
            "--output-path",
            str(export_dir),
        ],
        root,
    )
    manifest = json.loads((export_dir / "manifest.json").read_text(encoding="utf-8"))
    attachments = [
        attachment
        for test in manifest
        for attachment in test.get("attachments", [])
        if attachment.get("suggestedHumanReadableName", "").startswith(
            "apple-device-samples"
        )
    ]
    if len(attachments) != 1:
        raise CampaignError(
            f"expected one apple-device-samples attachment, found {len(attachments)}"
        )
    source = export_dir / attachments[0]["exportedFileName"]
    destination = campaign_dir / "apple-device-samples.json"
    shutil.copyfile(source, destination)
    shutil.rmtree(export_dir)
    return destination, summary


def UTC_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def elapsed_since(started_at: str, observed_at: str) -> int:
    start = dt.datetime.fromisoformat(started_at.replace("Z", "+00:00"))
    observed = dt.datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
    return max(0, int((observed - start).total_seconds()))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device-id", required=True)
    parser.add_argument("--campaign-id", required=True)
    parser.add_argument("--campaign-dir", required=True, type=pathlib.Path)
    parser.add_argument("--duration-seconds", type=int, default=MIN_FORMAL_DURATION_SECONDS)
    parser.add_argument("--sample-interval-seconds", type=int, default=30)
    parser.add_argument("--http-url", required=True)
    parser.add_argument("--udp-host", required=True)
    parser.add_argument("--udp-port", type=int, required=True)
    parser.add_argument(
        "--artifact-prefix",
        help="artifact path prefix relative to the eventual campaign.json directory",
    )
    parser.add_argument(
        "--derived-data",
        type=pathlib.Path,
        default=pathlib.Path("/private/tmp/xray-apple-device-campaign-derived"),
    )
    parser.add_argument("--rehearsal", action="store_true")
    parser.add_argument("--skip-xcframework-build", action="store_true")
    parser.add_argument("--skip-test-build", action="store_true")
    parser.add_argument("--skip-instruments", action="store_true")
    args = parser.parse_args()

    root = pathlib.Path(__file__).resolve().parent.parent
    if not CAMPAIGN_ID.fullmatch(args.campaign_id):
        raise CampaignError("--campaign-id has invalid characters")
    parsed_HTTP_url = urllib.parse.urlsplit(args.http_url)
    if (
        parsed_HTTP_url.scheme != "https"
        or not parsed_HTTP_url.hostname
        or parsed_HTTP_url.username is not None
        or parsed_HTTP_url.password is not None
        or parsed_HTTP_url.fragment
    ):
        raise CampaignError("--http-url must be an absolute HTTPS URL")
    if (
        not 1 <= args.udp_port <= 65535
        or not args.udp_host
        or len(args.udp_host) > 253
        or not args.udp_host.isprintable()
    ):
        raise CampaignError("--udp-host/--udp-port are invalid")
    minimum_duration = 30 if args.rehearsal else MIN_FORMAL_DURATION_SECONDS
    if not minimum_duration <= args.duration_seconds <= MAX_DURATION_SECONDS:
        raise CampaignError(
            f"--duration-seconds must be between {minimum_duration} "
            f"and {MAX_DURATION_SECONDS}"
        )
    if not 5 <= args.sample_interval_seconds <= MAX_SAMPLE_INTERVAL_SECONDS:
        raise CampaignError("--sample-interval-seconds must be between 5 and 60")
    if not args.rehearsal and args.skip_instruments:
        raise CampaignError("formal campaigns cannot skip Instruments")
    if not args.rehearsal and args.skip_test_build:
        raise CampaignError("formal campaigns cannot skip the Xcode test build")
    if args.campaign_dir.exists():
        raise CampaignError(f"campaign directory already exists: {args.campaign_dir}")

    revision = run_capture(["git", "rev-parse", "HEAD"], root).strip()
    dirty = bool(run_capture(["git", "status", "--porcelain"], root).strip())
    if dirty and not args.rehearsal:
        raise CampaignError("formal campaigns require a clean Git worktree")

    args.campaign_dir.mkdir(parents=True)
    log_path = args.campaign_dir / "sanitized-log.txt"
    timeline_path = args.campaign_dir / "transition-timeline.jsonl"
    state_path = args.campaign_dir / ".apple-campaign-state.json"
    result_bundle = args.campaign_dir / "apple-device.xcresult"
    trace_path = args.campaign_dir / "resource-profile.trace"
    trace_archive = args.campaign_dir / "resource-profile.trace.zip"
    secrets = [args.device_id, args.http_url, args.udp_host]

    generated_xctestrun: pathlib.Path | None = None
    instrument_process: subprocess.Popen[str] | None = None
    instrument_output: IO[str] | None = None
    soak_started_at: str | None = None
    try:
        build_started_at = UTC_now()
        atomic_write_json(
            state_path,
            {
                "schemaVersion": 1,
                "campaignId": args.campaign_id,
                "phase": "building",
            },
        )
        timeline_path.write_text(
            json.dumps(
                {"event": "campaign-build-start", "at": build_started_at},
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        with log_path.open("w", encoding="utf-8") as log:
            if not args.skip_xcframework_build and not args.rehearsal:
                if stream_command(
                    [str(root / "scripts" / "build-apple-xcframework.sh")],
                    root,
                    log,
                    secrets,
                ) != 0:
                    raise CampaignError("Apple XCFramework build failed")

            if not args.skip_test_build:
                build_arguments = [
                    "xcodebuild",
                    "build-for-testing",
                    "-project",
                    str(root / "platform/apple/XrayClient/XrayClient.xcodeproj"),
                    "-scheme",
                    "XrayClient",
                    "-configuration",
                    "Debug",
                    "-destination",
                    f"id={args.device_id}",
                    "-derivedDataPath",
                    str(args.derived_data),
                    "-only-testing:XrayClientUITests/XrayClientUITests/testPhysicalDeviceCampaign",
                ]
                if stream_command(build_arguments, root, log, secrets) != 0:
                    raise CampaignError("Xcode test build failed")

            generated_xctestrun = prepare_xctestrun(
                find_xctestrun(args.derived_data),
                args.campaign_id,
                args.duration_seconds,
                args.sample_interval_seconds,
                args.http_url,
                args.udp_host,
                args.udp_port,
                args.rehearsal,
            )
            test_arguments = [
                "xcodebuild",
                "test-without-building",
                "-xctestrun",
                str(generated_xctestrun),
                "-destination",
                f"id={args.device_id}",
                "-resultBundlePath",
                str(result_bundle),
                "-only-testing:XrayClientUITests/XrayClientUITests/testPhysicalDeviceCampaign",
            ]
            test_process = subprocess.Popen(
                test_arguments,
                cwd=root,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
            )
            assert test_process.stdout is not None
            for raw_line in test_process.stdout:
                line = redact(raw_line, secrets)
                log.write(line)
                log.flush()
                if soak_started_at is None and raw_line.startswith("XRAY_DEVICE_SAMPLE "):
                    soak_started_at = UTC_now()
                    append_json_line(
                        timeline_path,
                        {"event": "campaign-start", "at": soak_started_at},
                    )
                    atomic_write_json(
                        state_path,
                        {
                            "schemaVersion": 1,
                            "campaignId": args.campaign_id,
                            "phase": "running",
                            "startedAt": soak_started_at,
                        },
                    )
                    if not args.skip_instruments:
                        instrument_output = open(os.devnull, "w", encoding="utf-8")
                        instrument_process = subprocess.Popen(
                            [
                                "xcrun",
                                "xctrace",
                                "record",
                                "--template",
                                "Activity Monitor",
                                "--device",
                                args.device_id,
                                "--attach",
                                "Tunnel",
                                "--output",
                                str(trace_path),
                                "--time-limit",
                                f"{args.duration_seconds + 600}s",
                                "--no-prompt",
                            ],
                            cwd=root,
                            text=True,
                            stdout=instrument_output,
                            stderr=subprocess.STDOUT,
                        )
                probe = PASSED_PROBE.fullmatch(raw_line.rstrip("\r\n"))
                if soak_started_at is not None and probe is not None:
                    observed_at = UTC_now()
                    append_json_line(
                        timeline_path,
                        {
                            "event": "probe",
                            "at": observed_at,
                            "elapsedSeconds": elapsed_since(
                                soak_started_at, observed_at
                            ),
                            "kind": probe.group(1),
                            "result": "passed",
                            "sequence": int(probe.group(2)),
                        },
                    )
                sys.stdout.write(line)
                sys.stdout.flush()
            test_return_code = test_process.wait()
            if test_return_code != 0:
                raise CampaignError("physical-device UI campaign failed")

        if instrument_process is not None:
            time.sleep(3)
            if instrument_process.poll() is None:
                instrument_process.send_signal(signal.SIGINT)
            try:
                instrument_return_code = instrument_process.wait(timeout=60)
            except subprocess.TimeoutExpired as error:
                instrument_process.terminate()
                raise CampaignError("Instruments did not finish after tunnel teardown") from error
            if instrument_return_code != 0 or not trace_path.exists():
                raise CampaignError("Instruments resource profile failed")
            run_capture(
                [
                    "ditto",
                    "-c",
                    "-k",
                    "--sequesterRsrc",
                    "--keepParent",
                    str(trace_path),
                    str(trace_archive),
                ],
                root,
            )
        elif not args.skip_instruments:
            raise CampaignError("Instruments never started because no sample was observed")

        samples_path, summary = export_samples(root, result_bundle, args.campaign_dir)
        samples = validate_samples(samples_path)
        if soak_started_at is None:
            raise CampaignError("campaign passed without recording its first sample time")
        devices = summary.get("devicesAndConfigurations", [])
        if len(devices) != 1:
            raise CampaignError("xcresult does not identify exactly one device")
        device = devices[0].get("device", {})
        if device.get("deviceId") != args.device_id:
            raise CampaignError("xcresult device does not match --device-id")
        device_hash = hashlib.sha256(args.device_id.encode("utf-8")).hexdigest()
        info_plist = (
            args.derived_data / "Build/Products/Debug-iphoneos/XrayClient.app/Info.plist"
        )
        with info_plist.open("rb") as source:
            app_info = plistlib.load(source)
        started_at_value = dt.datetime.fromisoformat(
            soak_started_at.replace("Z", "+00:00")
        )
        ended_at = (
            started_at_value + dt.timedelta(seconds=samples[-1]["elapsedSeconds"])
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
        append_json_line(
            timeline_path,
            {
                "event": "campaign-end",
                "at": ended_at,
                "elapsedSeconds": samples[-1]["elapsedSeconds"],
                "result": "passed",
            },
        )
        metadata = {
            "schemaVersion": 1,
            "campaignId": args.campaign_id,
            "candidate": {"revision": revision, "dirty": dirty},
            "rehearsal": args.rehearsal,
            "startedAt": soak_started_at,
            "endedAt": ended_at,
            "requestedDurationSeconds": args.duration_seconds,
            "observedDurationSeconds": samples[-1]["elapsedSeconds"],
            "sampleIntervalSeconds": args.sample_interval_seconds,
            "device": {
                "physical": True,
                "model": device.get("modelName"),
                "osVersion": device.get("osVersion"),
                "architecture": "arm64",
                "identifierHash": device_hash,
            },
            "app": {
                "bundleIdentifier": app_info.get("CFBundleIdentifier"),
                "version": app_info.get("CFBundleShortVersionString"),
                "build": app_info.get("CFBundleVersion"),
            },
            "artifacts": {
                "samples": samples_path.name,
                "resourceProfile": trace_archive.name if trace_archive.exists() else None,
                "sanitizedLog": log_path.name,
                "transitionTimeline": timeline_path.name,
                "xcresult": result_bundle.name,
            },
        }
        (args.campaign_dir / "apple-run.json").write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if not args.rehearsal:
            report_output = run_capture(
                [
                    sys.executable,
                    str(root / "scripts/build-apple-device-report.py"),
                    str(args.campaign_dir),
                    "--artifact-prefix",
                    args.artifact_prefix or args.campaign_dir.name,
                ],
                root,
            )
            print(report_output.strip())
        print(f"Apple device campaign passed: {args.campaign_dir}")
        return 0
    except Exception as error:
        try:
            append_json_line(
                timeline_path,
                {
                    "event": "campaign-end",
                    "at": UTC_now(),
                    "result": "failed",
                    "errorType": type(error).__name__,
                },
            )
        except (CampaignError, OSError):
            pass
        raise
    finally:
        if instrument_process is not None and instrument_process.poll() is None:
            instrument_process.terminate()
        if instrument_output is not None:
            instrument_output.close()
        if generated_xctestrun is not None:
            generated_xctestrun.unlink(missing_ok=True)
        state_path.unlink(missing_ok=True)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CampaignError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)

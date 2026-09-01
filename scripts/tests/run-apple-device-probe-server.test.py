#!/usr/bin/env python3
"""Contract test for the Apple physical-device UDP oracle server."""

from __future__ import annotations

import json
import pathlib
import socket
import subprocess
import sys


DNS_QUERY = bytes(
    (
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x25, 0x78, 0x72, 0x61,
        0x79, 0x2D, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35,
        0x36, 0x37, 0x38, 0x39, 0x61, 0x62, 0x63, 0x64,
        0x65, 0x66, 0x07, 0x65, 0x78, 0x61, 0x6D, 0x70,
        0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D,
        0x00, 0x00, 0x01, 0x00, 0x01,
    )
)


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[2]
    process = subprocess.Popen(
        [
            sys.executable,
            str(root / "scripts/run-apple-device-probe-server.py"),
            "--bind-host",
            "127.0.0.1",
            "--port",
            "0",
            "--max-requests",
            "1",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    ready = json.loads(process.stdout.readline())
    if ready.get("event") != "ready" or not isinstance(ready.get("port"), int):
        raise AssertionError(f"invalid ready event: {ready}")

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(3)
    try:
        invalid_query = bytearray(DNS_QUERY)
        invalid_query[2] |= 0x80
        client.sendto(invalid_query, ("127.0.0.1", ready["port"]))
        rejected = json.loads(process.stdout.readline())
        if rejected.get("event") != "rejected" or (
            "standard recursive DNS query" not in rejected.get("reason", "")
        ):
            raise AssertionError(f"invalid query was not rejected: {rejected}")

        unrelated_query = bytearray(DNS_QUERY)
        unrelated_query[13:18] = b"other"
        client.sendto(unrelated_query, ("127.0.0.1", ready["port"]))
        rejected = json.loads(process.stdout.readline())
        if rejected.get("event") != "rejected" or "nonce label" not in rejected.get(
            "reason", ""
        ):
            raise AssertionError(f"unrelated query was not rejected: {rejected}")

        client.sendto(DNS_QUERY, ("127.0.0.1", ready["port"]))
        response, _ = client.recvfrom(4096)
    finally:
        client.close()

    if response[0:2] != DNS_QUERY[0:2]:
        raise AssertionError("response transaction ID does not match")
    if response[2] & 0x80 == 0 or response[3] & 0x0F != 0:
        raise AssertionError("response does not contain a successful DNS reply")
    if response[-4:] != bytes((203, 0, 113, 1)):
        raise AssertionError("response does not contain the documentation address")

    stdout_tail, stderr = process.communicate(timeout=3)
    if process.returncode != 0:
        raise AssertionError(f"probe server failed: {stderr}")
    events = [json.loads(line) for line in stdout_tail.splitlines()]
    if [event.get("event") for event in events] != ["response", "stopped"]:
        raise AssertionError(f"unexpected server events: {events}")
    print("Apple UDP oracle server contract test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

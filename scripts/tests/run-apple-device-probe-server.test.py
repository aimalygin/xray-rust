#!/usr/bin/env python3
"""Contract test for the Apple UDP oracle and authenticated TCP load server."""

from __future__ import annotations

import json
import pathlib
import runpy
import socket
import subprocess
import sys
import tempfile


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
    server_module = runpy.run_path(
        str(root / "scripts/run-apple-device-probe-server.py")
    )
    token = b"a" * 64
    token_file = tempfile.NamedTemporaryFile(
        prefix="xray-apple-load-token-", delete=False
    )
    token_path = pathlib.Path(token_file.name)
    token_file.write(token + b"\n")
    token_file.close()
    token_path.chmod(0o600)
    insecure_token = token_path.with_name(token_path.name + "-insecure")
    insecure_token.write_bytes(token + b"\n")
    insecure_token.chmod(0o640)
    try:
        server_module["load_auth_token"](insecure_token)
    except server_module["ProbeError"]:
        pass
    else:
        raise AssertionError("probe server accepted a group-readable ordinary token")
    finally:
        insecure_token.unlink(missing_ok=True)
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
            "--tcp-load-token-file",
            str(token_path),
            "--max-tcp-clients",
            "2",
        ],
        cwd=root,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert process.stdout is not None
    try:
        ready_line = process.stdout.readline()
        if not ready_line:
            assert process.stderr is not None
            raise AssertionError("probe server failed before ready: " + process.stderr.read())
        ready = json.loads(ready_line)
        if (
            ready.get("event") != "ready"
            or not isinstance(ready.get("port"), int)
            or ready.get("tcpLoadEnabled") is not True
        ):
            raise AssertionError(f"invalid ready event: {ready}")

        invalid_TCP = socket.create_connection(("127.0.0.1", ready["port"]), timeout=3)
        invalid_TCP.sendall(b"XRAY-MEMORY-HOLD/1 " + b"b" * 64 + b"\n")
        if invalid_TCP.recv(1) != b"":
            raise AssertionError("invalid TCP load token was accepted")
        invalid_TCP.close()
        rejected_TCP = json.loads(process.stdout.readline())
        if rejected_TCP != {"event": "tcp-rejected", "reason": "authentication"}:
            raise AssertionError(f"invalid TCP token was not rejected: {rejected_TCP}")

        held_TCP = socket.create_connection(("127.0.0.1", ready["port"]), timeout=3)
        held_TCP.sendall(b"XRAY-MEMORY-HOLD/1 " + token + b"\n")
        if held_TCP.recv(128) != b"XRAY-MEMORY-HOLD/1 READY\n":
            raise AssertionError("valid TCP load request was not acknowledged")
        accepted_TCP = json.loads(process.stdout.readline())
        if accepted_TCP != {"accepted": 1, "event": "tcp-accepted"}:
            raise AssertionError(f"valid TCP load request was not accepted: {accepted_TCP}")

        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(3)
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
        token_path.unlink(missing_ok=True)
        if "held_TCP" in locals():
            held_TCP.close()
        if "client" in locals():
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
    stopped = events[-1]
    if (
        stopped.get("tcpAccepted") != 1
        or stopped.get("tcpRejected") != 1
        or stopped.get("tcpPeak") != 1
    ):
        raise AssertionError(f"invalid TCP load summary: {stopped}")
    print("Apple UDP oracle server contract test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

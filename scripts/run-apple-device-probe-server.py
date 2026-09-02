#!/usr/bin/env python3
"""Serve the Apple UDP oracle and optional authenticated TCP load holds."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hmac
import json
import pathlib
import re
import selectors
import signal
import socket
import sys
import time
from types import FrameType


MAX_DNS_DATAGRAM_BYTES = 4096
MAX_LOAD_REQUEST_BYTES = 128
LOAD_PROTOCOL_PREFIX = b"XRAY-MEMORY-HOLD/1 "
LOAD_READY = b"XRAY-MEMORY-HOLD/1 READY\n"
LOAD_TOKEN = re.compile(rb"^[0-9a-f]{64}$")
TEST_ADDRESS = bytes((203, 0, 113, 1))


class ProbeError(Exception):
    pass


@dataclass
class LoadClient:
    connection: socket.socket
    deadline: float
    request: bytearray = field(default_factory=bytearray)
    authenticated: bool = False


def dns_question_end(query: bytes) -> int:
    if len(query) < 17:
        raise ProbeError("DNS query is too short")
    offset = 12
    while True:
        if offset >= len(query):
            raise ProbeError("DNS question name is truncated")
        label_length = query[offset]
        offset += 1
        if label_length == 0:
            break
        if label_length & 0xC0 or label_length > 63:
            raise ProbeError("compressed or invalid DNS question name")
        offset += label_length
        if offset > len(query):
            raise ProbeError("DNS question label is truncated")
    end = offset + 4
    if end > len(query):
        raise ProbeError("DNS question type/class is truncated")
    return end


def build_dns_response(query: bytes) -> bytes:
    question_end = dns_question_end(query)
    if len(query) != question_end:
        raise ProbeError("probe query must contain only one DNS question")
    if query[2:4] != b"\x01\x00":
        raise ProbeError("probe requires a standard recursive DNS query")
    if query[4:12] != b"\x00\x01\x00\x00\x00\x00\x00\x00":
        raise ProbeError("probe requires exactly one DNS question and no records")
    question = query[12:question_end]
    expected_suffix = b"\x07example\x03com\x00\x00\x01\x00\x01"
    if len(question) != 1 + 37 + len(expected_suffix):
        raise ProbeError("probe question has an invalid size")
    nonce_label = question[1:38]
    if question[0] != len(nonce_label) or not nonce_label.startswith(b"xray-"):
        raise ProbeError("probe question has an invalid nonce label")
    nonce = nonce_label[len(b"xray-") :]
    if any(byte not in b"0123456789abcdef" for byte in nonce):
        raise ProbeError("probe question has an invalid nonce")
    if question[38:] != expected_suffix:
        raise ProbeError("probe question must request xray-<nonce>.example.com A/IN")
    header = query[0:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x00\x00\x04" + TEST_ADDRESS
    return header + question + answer


def emit(event: str, **fields: object) -> None:
    print(json.dumps({"event": event, **fields}, sort_keys=True), flush=True)


def load_auth_token(path: pathlib.Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ProbeError("TCP load token path must be a regular file")
    non_owner_permissions = path.stat().st_mode & 0o077
    systemd_credential = str(path).startswith("/run/credentials/")
    if non_owner_permissions and not (
        systemd_credential and non_owner_permissions == 0o040
    ):
        raise ProbeError("TCP load token file must not be accessible by group or others")
    token = path.read_bytes().strip()
    if not LOAD_TOKEN.fullmatch(token):
        raise ProbeError("TCP load token must contain exactly 64 lowercase hex characters")
    return token


def close_load_client(
    selector: selectors.BaseSelector,
    clients: dict[int, LoadClient],
    client: LoadClient,
) -> None:
    descriptor = client.connection.fileno()
    try:
        selector.unregister(client.connection)
    except (KeyError, ValueError):
        pass
    clients.pop(descriptor, None)
    client.connection.close()


def serve(
    bind_host: str,
    port: int,
    max_requests: int | None,
    load_token: bytes | None,
    max_tcp_clients: int,
    tcp_idle_seconds: int,
) -> int:
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    selector = selectors.DefaultSelector()
    UDP_server = socket.socket(family, socket.SOCK_DGRAM)
    UDP_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    UDP_server.setblocking(False)
    UDP_server.bind((bind_host, port))
    actual_port = UDP_server.getsockname()[1]
    selector.register(UDP_server, selectors.EVENT_READ, "udp")
    TCP_server: socket.socket | None = None
    if load_token is not None:
        TCP_server = socket.socket(family, socket.SOCK_STREAM)
        TCP_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        TCP_server.setblocking(False)
        TCP_server.bind((bind_host, actual_port))
        TCP_server.listen(max_tcp_clients)
        selector.register(TCP_server, selectors.EVENT_READ, "tcp-listener")
    stopped = False

    def stop(_signal: int, _frame: FrameType | None) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    emit(
        "ready",
        bindHost=bind_host,
        port=actual_port,
        tcpLoadEnabled=load_token is not None,
    )

    handled = 0
    TCP_accepted = 0
    TCP_rejected = 0
    TCP_peak = 0
    clients: dict[int, LoadClient] = {}

    def reject(client: LoadClient, reason: str) -> None:
        nonlocal TCP_rejected
        TCP_rejected += 1
        emit("tcp-rejected", reason=reason)
        close_load_client(selector, clients, client)

    try:
        while not stopped and (max_requests is None or handled < max_requests):
            for key, _ in selector.select(timeout=0.25):
                if key.data == "udp":
                    try:
                        query, peer = UDP_server.recvfrom(MAX_DNS_DATAGRAM_BYTES)
                        response = build_dns_response(query)
                        UDP_server.sendto(response, peer)
                        handled += 1
                        emit("response", request=handled, bytes=len(response))
                    except ProbeError as error:
                        emit("rejected", reason=str(error))
                    continue

                if key.data == "tcp-listener":
                    assert TCP_server is not None
                    while True:
                        try:
                            connection, _ = TCP_server.accept()
                        except BlockingIOError:
                            break
                        connection.setblocking(False)
                        if len(clients) >= max_tcp_clients:
                            connection.close()
                            TCP_rejected += 1
                            emit("tcp-rejected", reason="capacity")
                            continue
                        client = LoadClient(
                            connection=connection,
                            deadline=time.monotonic() + tcp_idle_seconds,
                        )
                        clients[connection.fileno()] = client
                        selector.register(connection, selectors.EVENT_READ, client)
                    continue

                client = key.data
                assert isinstance(client, LoadClient)
                try:
                    chunk = client.connection.recv(MAX_LOAD_REQUEST_BYTES + 1)
                except BlockingIOError:
                    continue
                if not chunk:
                    close_load_client(selector, clients, client)
                    continue
                client.deadline = time.monotonic() + tcp_idle_seconds
                if client.authenticated:
                    reject(client, "unexpected-data")
                    continue
                client.request.extend(chunk)
                if len(client.request) > MAX_LOAD_REQUEST_BYTES:
                    reject(client, "request-too-long")
                    continue
                if b"\n" not in client.request:
                    continue
                expected = LOAD_PROTOCOL_PREFIX + load_token + b"\n"
                if not hmac.compare_digest(bytes(client.request), expected):
                    reject(client, "authentication")
                    continue
                sent = client.connection.send(LOAD_READY)
                if sent != len(LOAD_READY):
                    reject(client, "short-ready-write")
                    continue
                client.authenticated = True
                TCP_accepted += 1
                TCP_peak = max(
                    TCP_peak,
                    sum(item.authenticated for item in clients.values()),
                )
                emit("tcp-accepted", accepted=TCP_accepted)

            now = time.monotonic()
            for client in list(clients.values()):
                if client.deadline <= now:
                    reject(client, "idle-timeout")
    finally:
        for client in list(clients.values()):
            close_load_client(selector, clients, client)
        if TCP_server is not None:
            selector.unregister(TCP_server)
            TCP_server.close()
        selector.unregister(UDP_server)
        UDP_server.close()
        selector.close()
    emit(
        "stopped",
        requests=handled,
        tcpAccepted=TCP_accepted,
        tcpRejected=TCP_rejected,
        tcpPeak=TCP_peak,
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=53053)
    parser.add_argument("--max-requests", type=int)
    parser.add_argument("--tcp-load-token-file", type=pathlib.Path)
    parser.add_argument("--max-tcp-clients", type=int, default=320)
    parser.add_argument("--tcp-idle-seconds", type=int, default=900)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        raise ProbeError("--port must be between 0 and 65535")
    if args.max_requests is not None and args.max_requests < 1:
        raise ProbeError("--max-requests must be positive")
    if not 1 <= args.max_tcp_clients <= 1024:
        raise ProbeError("--max-tcp-clients must be between 1 and 1024")
    if not 30 <= args.tcp_idle_seconds <= 3600:
        raise ProbeError("--tcp-idle-seconds must be between 30 and 3600")
    load_token = (
        load_auth_token(args.tcp_load_token_file)
        if args.tcp_load_token_file is not None
        else None
    )
    return serve(
        args.bind_host,
        args.port,
        args.max_requests,
        load_token,
        args.max_tcp_clients,
        args.tcp_idle_seconds,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ProbeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Serve the bounded DNS-over-UDP oracle used by Apple device campaigns."""

from __future__ import annotations

import argparse
import json
import signal
import socket
import sys
from types import FrameType


MAX_DNS_DATAGRAM_BYTES = 4096
TEST_ADDRESS = bytes((203, 0, 113, 1))


class ProbeError(Exception):
    pass


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


def serve(bind_host: str, port: int, max_requests: int | None) -> int:
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    server = socket.socket(family, socket.SOCK_DGRAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((bind_host, port))
    actual_port = server.getsockname()[1]
    stopped = False

    def stop(_signal: int, _frame: FrameType | None) -> None:
        nonlocal stopped
        stopped = True
        server.close()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    emit("ready", bindHost=bind_host, port=actual_port)

    handled = 0
    try:
        while not stopped and (max_requests is None or handled < max_requests):
            try:
                query, peer = server.recvfrom(MAX_DNS_DATAGRAM_BYTES)
                response = build_dns_response(query)
                server.sendto(response, peer)
                handled += 1
                emit("response", request=handled, bytes=len(response))
            except ProbeError as error:
                emit("rejected", reason=str(error))
            except OSError:
                if not stopped:
                    raise
    finally:
        server.close()
    emit("stopped", requests=handled)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind-host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=53053)
    parser.add_argument("--max-requests", type=int)
    args = parser.parse_args()
    if not 0 <= args.port <= 65535:
        raise ProbeError("--port must be between 0 and 65535")
    if args.max_requests is not None and args.max_requests < 1:
        raise ProbeError("--max-requests must be positive")
    return serve(args.bind_host, args.port, args.max_requests)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ProbeError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)

#!/usr/bin/env python3
"""Existing bounded Apple fixture with private logs and public byte/timing metadata."""
import asyncio
import importlib.util
import json
import time
from pathlib import Path

ROOT = next(
    path for path in Path(__file__).resolve().parents
    if (path / "scripts/run-v07-apple-protocol-fixture.py").is_file()
)
SPEC = importlib.util.spec_from_file_location(
    "fixture", ROOT / "scripts/run-v07-apple-protocol-fixture.py"
)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
EVENTS = []
NEXT_FLOW = 0
OUTPUT = None


def emit(**row):
    # No endpoints, keys, DNS names, or payload content enter this file.
    row["monotonic"] = time.monotonic()
    row["unixTime"] = time.time()
    EVENTS.append(row)
    (OUTPUT / "backend-metadata.json").write_text(json.dumps(EVENTS))


async def echo(reader, writer, byte_limit=1024 * 1024):
    global NEXT_FLOW
    NEXT_FLOW += 1
    flow = NEXT_FLOW
    received = sent = 0
    reason = "eof"
    emit(event="tcp-open", flow=flow)
    try:
        while received < byte_limit:
            data = await asyncio.wait_for(reader.read(min(8192, byte_limit - received)), 10)
            if not data:
                break
            received += len(data)
            emit(event="tcp-read", flow=flow, bytes=len(data))
            writer.write(data)
            await asyncio.wait_for(writer.drain(), 10)
            sent += len(data)
            emit(event="tcp-write", flow=flow, bytes=len(data))
    except (TimeoutError, ConnectionError) as error:
        reason = type(error).__name__
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except ConnectionError:
            pass
        emit(event="tcp-close", flow=flow, received=received, sent=sent, reason=reason)


class Echo(fixture.Echo):
    def datagram_received(self, data, address):
        emit(event="udp-echo", bytes=len(data))
        super().datagram_received(data, address)


original_write = fixture.write_fixtures


def write(*args, **kwargs):
    global OUTPUT
    OUTPUT = args[0]
    original_write(*args, **kwargs)
    path = args[0] / "server.json"
    data = json.loads(path.read_text())
    data["log"]["loglevel"] = "debug"
    path.write_text(json.dumps(data))


fixture.write_fixtures = write
fixture.tcp_echo = echo
fixture.Echo = Echo
if __name__ == "__main__":
    fixture.main()

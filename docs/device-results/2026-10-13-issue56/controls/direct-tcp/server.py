#!/usr/bin/env python3
"""Bounded, nonce-logging plain TCP backend; portable startup for the control."""

import argparse
import asyncio
import json
import signal
import time


async def handler(reader, writer):
    nonce = None
    result = ""
    try:
        data = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
        nonce = next(line.split(b": ", 1)[1].decode()
                     for line in data.split(b"\r\n")
                     if line.startswith(b"X-Probe-Nonce: "))
        assert len(nonce) == 32 and all(c in "0123456789abcdef" for c in nonce)
        writer.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        await writer.drain()
        result = "replied"
    except Exception as error:
        result = type(error).__name__
    finally:
        print(json.dumps({"time": time.time(), "nonce": nonce, "result": result}), flush=True)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def main(args):
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    server = await asyncio.start_server(handler, args.bind, args.port)
    print(json.dumps({"event": "listening", "port": server.sockets[0].getsockname()[1]}), flush=True)
    try:
        await asyncio.wait_for(stop.wait(), 600)
    except TimeoutError:
        pass
    finally:
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=0)
    asyncio.run(main(parser.parse_args()))

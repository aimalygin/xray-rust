#!/usr/bin/env python3
"""Compare actual Rust/Go SOCKS clients on a local delayed XHTTP/H2 path.

This is an application-byte delay line, not TCP packet netem or an iOS/CDN
measurement. Only loopback sockets are opened. No user configuration is read.
Requires Python 3.9+, openssl and prebuilt release client binaries.
"""

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import platform
import random
import signal
import socket
import statistics
import subprocess
import time
import uuid


BLOCK = random.Random(28).randbytes(65536)


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def sha256(path):
    with path.open("rb") as stream:
        digest = hashlib.sha256()
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
        return digest.hexdigest()


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def close(writer):
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


class DelayLine:
    def __init__(self, port, rtt_ms, rate_mbps):
        self.port = port
        self.delay = rtt_ms / 2000
        self.rate = rate_mbps * 1e6 / 8
        self.next_slot = [0.0, 0.0]
        self.opened = 0
        self.tasks = set()

    async def copy(self, reader, writer, direction):
        queue = asyncio.Queue(256)  # At most 4 MiB queued in each direction.

        async def enqueue():
            while data := await reader.read(16384):
                now = time.monotonic()
                if self.rate:
                    self.next_slot[direction] = max(self.next_slot[direction], now) + len(data) / self.rate
                    now = self.next_slot[direction]
                await queue.put((now + self.delay, data))
            await queue.put((0, b""))

        producer = asyncio.create_task(enqueue())
        try:
            while True:
                due, data = await queue.get()
                if not data:
                    return
                await asyncio.sleep(max(0, due - time.monotonic()))
                writer.write(data)
                await writer.drain()
        finally:
            producer.cancel()
            await asyncio.gather(producer, return_exceptions=True)

    async def handle(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        self.opened += 1
        upstream = None
        copies = []
        try:
            peer, upstream = await asyncio.open_connection("127.0.0.1", self.port)
            copies = [asyncio.create_task(self.copy(reader, upstream, 0)),
                      asyncio.create_task(self.copy(peer, writer, 1))]
            done, _ = await asyncio.wait(copies, return_when=asyncio.FIRST_COMPLETED)
            for item in done:
                item.result()
        except (ConnectionError, OSError):
            pass
        finally:
            for item in copies:
                item.cancel()
            await asyncio.gather(*copies, return_exceptions=True)
            await close(writer)
            if upstream:
                await close(upstream)
            self.tasks.discard(task)

    async def stop(self):
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def origin(reader, writer):
    try:
        while True:
            line = await asyncio.wait_for(reader.readline(), 30)
            if line == b"PING\n":
                writer.write(b"PONG\n")
                await writer.drain()
                continue
            if not line.startswith(b"READ "):
                return
            size = int(line.split()[1])
            if not 0 < size <= 512 * 1024 * 1024:
                raise ValueError("payload outside harness limit")
            for offset in range(0, size, len(BLOCK)):
                writer.write(BLOCK[:min(len(BLOCK), size - offset)])
                await writer.drain()
            return
    except (ConnectionError, OSError, asyncio.TimeoutError):
        pass
    finally:
        await close(writer)


async def connect(port, target=None):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        if target is not None:
            writer.write(b"\x05\x01\x00")
            await writer.drain()
            if await reader.readexactly(2) != b"\x05\x00":
                raise RuntimeError("SOCKS authentication failed")
            writer.write(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target.to_bytes(2, "big"))
            await writer.drain()
            header = await reader.readexactly(4)
            if header[:3] != b"\x05\x00\x00":
                raise RuntimeError("SOCKS CONNECT failed")
            length = {1: 4, 4: 16}.get(header[3])
            if header[3] == 3:
                length = (await reader.readexactly(1))[0]
            if length is None:
                raise RuntimeError("invalid SOCKS address type")
            await reader.readexactly(length + 2)
        return reader, writer
    except BaseException:
        await close(writer)
        raise


async def download(port, size, target=None):
    expected = hashlib.sha256()
    for offset in range(0, size, len(BLOCK)):
        expected.update(BLOCK[:min(len(BLOCK), size - offset)])
    begin = time.monotonic()
    reader, writer = await connect(port, target)
    setup = time.monotonic() - begin
    try:
        start = time.monotonic()
        writer.write(f"READ {size}\n".encode())
        await writer.drain()
        digest = hashlib.sha256()
        received = 0
        first_byte = None
        last_byte = None
        while data := await reader.read(65536):
            last_byte = time.monotonic() - start
            if first_byte is None:
                first_byte = last_byte
            received += len(data)
            if received > size:
                raise RuntimeError("excess payload")
            digest.update(data)
        eof_seconds = time.monotonic() - start
        if received != size or digest.digest() != expected.digest():
            raise RuntimeError("payload length or SHA-256 mismatch")
        # EOF can follow the last payload byte after a transport grace period.
        # Keep that latency visible, but do not call it payload transfer time.
        return dict(bytes=received, seconds=last_byte, mbps=received * 8 / last_byte / 1e6,
                    first_byte_seconds=first_byte, socks_setup_seconds=setup,
                    eof_seconds=eof_seconds, eof_tail_seconds=eof_seconds - last_byte,
                    total_seconds=time.monotonic() - begin, sha256=digest.hexdigest())
    finally:
        await close(writer)


async def ready(process, port):
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError("engine exited during startup; see its log")
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
            await close(writer)
            return
        except OSError:
            await asyncio.sleep(.05)
    raise RuntimeError("engine startup timeout")


async def stop(process):
    if process.poll() is None:
        process.terminate()
        for _ in range(100):
            if process.poll() is not None:
                break
            await asyncio.sleep(.05)
        else:
            process.kill()
    process.wait()


async def run(args):
    os.umask(0o077)
    root = args.out.resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / "runner.py").write_bytes(Path(__file__).read_bytes())
    user = str(uuid.uuid4())
    cert, key = root / "certificate.pem", root / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=issue28.test", "-keyout", str(key), "-out", str(cert)],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    der = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
    pin = hashlib.sha256(der).hexdigest()
    origin_server = await asyncio.start_server(origin, "127.0.0.1", 0)
    target = origin_server.sockets[0].getsockname()[1]
    server_port = free_port()
    xhttp = {"path": "/issue28/", "mode": "packet-up", "scMinPostsIntervalMs": 1,
             "xmux": {"maxConnections": "2-3", "hMaxRequestTimes": 1000000, "hMaxReusableSecs": 3600}}
    server_config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": server_port, "protocol": "vless",
                      "settings": {"clients": [{"id": user}], "decryption": "none"},
                      "streamSettings": {"network": "xhttp", "security": "tls", "xhttpSettings": xhttp,
                                         "tlsSettings": {"alpn": ["h2"], "certificates": [
                                             {"certificateFile": str(cert), "keyFile": str(key)}]}}}],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]}
    save(root / "server.json", server_config)
    results = dict(platform=platform.platform(), added_rtt_ms=args.rtt_ms, rounds=args.rounds,
                   payload_mib=args.payload_mib, warmup_mib=args.warmup_mib,
                   mode="packet-up", xmux_max_connections="2-3", ingress="SOCKS5; no TUN",
                   delay_model="bounded application-byte relay; not TCP packet netem",
                   rust_binary_sha256=sha256(args.rust_bin), go_binary_sha256=sha256(args.go_bin),
                   go_version=subprocess.check_output([str(args.go_bin), "version"], text=True),
                   runner_sha256=sha256(Path(__file__)), conditions=[])
    with (root / "server.log").open("w") as log:
        server = subprocess.Popen([str(args.go_bin), "run", "-config", str(root / "server.json")], stdout=log, stderr=subprocess.STDOUT)
    try:
        await ready(server, server_port)
        for rate in args.rates_mbps:
            condition = dict(rate_mbps=rate, trials=[])
            results["conditions"].append(condition)
            for upstream, label in [(target, "relay_control"), (server_port, "clients")]:
                line = DelayLine(upstream, args.rtt_ms, rate)
                relay = await asyncio.start_server(line.handle, "127.0.0.1", 0)
                port = relay.sockets[0].getsockname()[1]
                try:
                    if label == "relay_control":
                        reader, writer = await connect(port)
                        pings = []
                        for _ in range(5):
                            start = time.monotonic()
                            writer.write(b"PING\n")
                            await writer.drain()
                            if await reader.readline() != b"PONG\n":
                                raise RuntimeError("delay calibration failed")
                            pings.append((time.monotonic() - start) * 1000)
                        await close(writer)
                        condition["relay_ping_ms"] = pings
                        condition["relay_control"] = await asyncio.wait_for(download(port, args.payload_mib * 2**20), 120)
                        continue
                    for iteration in range(args.rounds):
                        order = ["rust", "go"] if iteration % 2 == 0 else ["go", "rust"]
                        for engine in order:
                            name = f"rate-{rate:g}-round-{iteration + 1}-{engine}"
                            socks = free_port()
                            config = {"log": {"loglevel": "warning"}, "inbounds": [
                                {"tag": "socks-in", "listen": "127.0.0.1", "port": socks, "protocol": "socks",
                                 "settings": {"auth": "noauth", "udp": False}}], "outbounds": [
                                {"tag": "proxy", "protocol": "vless", "settings": {"vnext": [
                                    {"address": "127.0.0.1", "port": port, "users": [{"id": user, "encryption": "none"}]}]},
                                 "streamSettings": {"network": "xhttp", "security": "tls", "xhttpSettings": xhttp,
                                                    "tlsSettings": {"serverName": "issue28.test", "alpn": ["h2"],
                                                                    "pinnedPeerCertSha256": pin, "fingerprint": "chrome"}}}]}
                            config_path = root / (name + ".json")
                            save(config_path, config)
                            binary = args.rust_bin if engine == "rust" else args.go_bin
                            with (root / (name + ".log")).open("w") as log:
                                process = subprocess.Popen([str(binary), "run", "-config", str(config_path)], stdout=log, stderr=subprocess.STDOUT)
                            opened = line.opened
                            try:
                                await ready(process, socks)
                                warmup = await asyncio.wait_for(download(socks, args.warmup_mib * 2**20, target), 120)
                                await asyncio.sleep(.3)
                                trial = await asyncio.wait_for(download(socks, args.payload_mib * 2**20, target), 120)
                                trial.update(engine=engine, round=iteration + 1, warmup=warmup,
                                             transport_connections_opened=line.opened - opened)
                                condition["trials"].append(trial)
                                print(json.dumps(dict(rate_mbps=rate, engine=engine, round=iteration + 1,
                                                      mbps=trial["mbps"], seconds=trial["seconds"])), flush=True)
                            finally:
                                await stop(process)
                            save(root / "results.json", results)
                            await asyncio.sleep(.5)
                finally:
                    relay.close()
                    await relay.wait_closed()
                    await line.stop()
            condition["summary"] = {}
            for engine in ["rust", "go"]:
                values = [trial["mbps"] for trial in condition["trials"] if trial["engine"] == engine]
                condition["summary"][engine] = dict(median_mbps=statistics.median(values), min_mbps=min(values), max_mbps=max(values))
            save(root / "results.json", results)
        results["completed"] = True
    finally:
        origin_server.close()
        await origin_server.wait_closed()
        await stop(server)
        save(root / "results.json", results)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rust-bin", type=Path, required=True)
    parser.add_argument("--go-bin", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--rounds", type=int, default=6)
    parser.add_argument("--rtt-ms", type=float, default=113)
    parser.add_argument("--rates-mbps", type=float, nargs="+", default=[150, 0])
    parser.add_argument("--payload-mib", type=int, default=64)
    parser.add_argument("--warmup-mib", type=int, default=16)
    args = parser.parse_args()
    args.rust_bin = args.rust_bin.resolve(strict=True)
    args.go_bin = args.go_bin.resolve(strict=True)
    if args.rounds < 1 or args.rtt_ms < 0 or any(rate < 0 for rate in args.rates_mbps):
        parser.error("rounds must be positive; delay/rates must be nonnegative")
    if not all(0 < size <= 512 for size in [args.payload_mib, args.warmup_mib]):
        parser.error("payload/warmup must be between 1 and 512 MiB")
    asyncio.run(interruptible_run(args))


async def interruptible_run(args):
    task = asyncio.create_task(run(args))
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, task.cancel)
    await task


if __name__ == "__main__":
    main()

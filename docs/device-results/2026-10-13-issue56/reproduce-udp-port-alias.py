#!/usr/bin/env python3
"""Bounded loopback-only reproduction of Darwin UDP ephemeral port aliasing.

Baseline: dual-stack [::]:0, selected by pinned Xray's default Go
ListenPacket("udp", "0.0.0.0:0"). Control: IPv4 127.0.0.1:0, matching the
fixture backend. A non-reproduction is inconclusive. All sockets are owned by
this process; no reference source, routes, firewall or OS settings change.
"""

import contextlib
import json
import select
import socket
import time


def trial(family, attempts=100_000):
    with contextlib.ExitStack() as resources:
        backend = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        decoy = resources.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        backend.bind(("127.0.0.1", 0))
        decoy.bind(("127.0.0.1", 0))
        port = decoy.getsockname()[1]
        row = {"family": "dual-stack" if family == socket.AF_INET6 else "ipv4",
               "decoyPort": port}
        started = time.monotonic()
        for attempt in range(1, attempts + 1):
            outbound = socket.socket(family, socket.SOCK_DGRAM)
            try:
                if family == socket.AF_INET6:
                    outbound.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                outbound.bind(("::" if family == socket.AF_INET6 else "127.0.0.1", 0))
                if outbound.getsockname()[1] == port:
                    resources.enter_context(outbound)
                    break
            except BaseException:
                outbound.close()
                raise
            outbound.close()
        else:
            return {**row, "attempts": attempts, "collision": False,
                    "seconds": time.monotonic() - started}

        row.update(attempts=attempt, collision=True, seconds=time.monotonic() - started)
        destination = "::ffff:127.0.0.1" if family == socket.AF_INET6 else "127.0.0.1"
        outbound.sendto(b"nonce-query", (destination, backend.getsockname()[1]))
        backend.settimeout(1)
        data, peer = backend.recvfrom(100)
        assert data == b"nonce-query"
        backend.sendto(b"nonce-reply", peer)
        ready, _, _ = select.select([outbound, decoy], [], [], 1)
        row["replyReceiver"] = [
            "outbound" if sock is outbound else "unrelated-ipv4-socket" for sock in ready
        ]
        for sock in ready:
            assert sock.recv(100) == b"nonce-reply"
        return row


def main():
    rows = [trial(socket.AF_INET6), trial(socket.AF_INET)]
    print(json.dumps(rows, indent=2))
    if rows[1]["collision"]:
        raise SystemExit("IPv4 control unexpectedly collided")
    if not rows[0]["collision"]:
        raise SystemExit("No dual-stack collision in the bounded sample; inconclusive on this host")
    assert rows[0]["replyReceiver"] == ["unrelated-ipv4-socket"]


if __name__ == "__main__":
    main()

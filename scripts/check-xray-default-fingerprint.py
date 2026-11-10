#!/usr/bin/env python3
"""Hold the pinned Xray-core binary's own ClientHellos to the uTLS fixtures.

The raw ClientHello fixtures under tests/fixtures/reality come from uTLS run
under a zeroed crypto/rand, which is what lets the Rust tests compare them
byte for byte. This script closes the other side: it captures what the
pinned `xray` binary itself sends over TLS for an empty fingerprint,
`chrome`, `hellochrome_155` and `hellochrome_133`, and checks each against
the fixture the Rust profile is held to.

A live hello differs from the zero-seed one in what uTLS draws per
connection, so those are compared by shape: GREASE values (any RFC 8701
value), the extension order (Chrome shuffles it), key share and ECH bytes
(their lengths and the ECH cipher suite are compared) and the ECH payload
length (one of uTLS's four candidates). Everything else must match byte for
byte, the trust anchor IDs and the signature algorithms included.

Usage: check-xray-default-fingerprint.py <xray> <fixture directory>
"""

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time

CASES = (
    ("", "clienthello_raw_chrome.json"),
    ("chrome", "clienthello_raw_chrome.json"),
    ("hellochrome_155", "clienthello_raw_chrome.json"),
    ("hellochrome_133", "clienthello_raw_hellochrome_133.json"),
)
KEY_SHARE = 0x0033
ECH = 0xFE0D
SERVER_NAME = "example.com"
# BoringGREASEECH draws its payload from {128, 160, 192, 224}; with the
# 16-byte tag and the outer header that is one of these extension lengths.
ECH_LENGTHS = {186, 218, 250, 282}


def is_grease(value):
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


def u16s(data):
    return [int.from_bytes(data[i : i + 2], "big") for i in range(0, len(data), 2)]


def grease_free(values):
    return ["GREASE" if is_grease(v) else v for v in values]


def parse(hello):
    """A ClientHello handshake message, without its record header."""
    i = 4 + 2 + 32
    i += 1 + hello[i]
    cipher_len = int.from_bytes(hello[i : i + 2], "big")
    ciphers = u16s(hello[i + 2 : i + 2 + cipher_len])
    i += 2 + cipher_len
    i += 1 + hello[i]
    end = i + 2 + int.from_bytes(hello[i : i + 2], "big")
    i += 2
    extensions = {}
    while i < end:
        kind = int.from_bytes(hello[i : i + 2], "big")
        length = int.from_bytes(hello[i + 2 : i + 4], "big")
        key = "GREASE" if is_grease(kind) else kind
        extensions.setdefault(key, []).append(hello[i + 4 : i + 4 + length])
        i += 4 + length
    return grease_free(ciphers), extensions


def comparable(kind, body):
    """What of one extension body must match: all of it, or its shape."""
    if kind == "GREASE":
        return len(body)
    if kind == KEY_SHARE:
        shares, i = [], 2
        while i < len(body):
            group = int.from_bytes(body[i : i + 2], "big")
            length = int.from_bytes(body[i + 2 : i + 4], "big")
            shares.append(("GREASE" if is_grease(group) else group, length))
            i += 4 + length
        return shares
    if kind == ECH:
        # type, KDF, AEAD; then the config id (drawn), the enc length and enc
        # (drawn), the payload length and payload (drawn).
        enc_len = int.from_bytes(body[6:8], "big")
        return (body[:5].hex(), enc_len, len(body) in ECH_LENGTHS)
    if kind in (0x000A, 0x000D, 0x002B):
        # supported_groups, signature_algorithms, supported_versions: one
        # GREASE slot each, drawn per connection.
        width = 1 if kind == 0x002B else 2
        return (len(body), grease_free(u16s(body[width:])))
    return body.hex()


def shape(hello):
    ciphers, extensions = parse(hello)
    return ciphers, {
        str(kind): sorted(str(comparable(kind, body)) for body in bodies)
        for kind, bodies in extensions.items()
    }


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def capture(xray, fingerprint):
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    server.settimeout(20)
    socks_port = free_port()
    config = {
        "inbounds": [
            {"listen": "127.0.0.1", "port": socks_port, "protocol": "socks"}
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "address": "127.0.0.1",
                    "port": server.getsockname()[1],
                    "id": "27848739-7e62-4138-9fd3-098a63964b6b",
                    "encryption": "none",
                },
                "streamSettings": {
                    "network": "raw",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": SERVER_NAME,
                        "fingerprint": fingerprint,
                    },
                },
            }
        ],
    }
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "config.json")
        with open(path, "w", encoding="utf-8") as stream:
            json.dump(config, stream)
        process = subprocess.Popen(
            [xray, "run", "-c", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = time.monotonic() + 10
            while True:
                try:
                    client = socket.create_connection(("127.0.0.1", socks_port), 1)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.1)
            with client:
                client.sendall(b"\x05\x01\x00")
                client.recv(2)
                client.sendall(
                    b"\x05\x01\x00\x03\x0bexample.org" + struct.pack(">H", 80)
                )
                peer, _ = server.accept()
                with peer:
                    peer.settimeout(10)
                    record = b""
                    while len(record) < 5 or len(record) < 5 + int.from_bytes(
                        record[3:5], "big"
                    ):
                        chunk = peer.recv(65536)
                        if not chunk:
                            break
                        record += chunk
        finally:
            process.terminate()
            process.wait()
            server.close()
    if record[:1] != b"\x16":
        raise SystemExit(f"{fingerprint!r}: no TLS handshake record captured")
    return record[5 : 5 + int.from_bytes(record[3:5], "big")]


def main():
    xray, fixtures = sys.argv[1], sys.argv[2]
    failures = []
    for fingerprint, fixture in CASES:
        with open(os.path.join(fixtures, fixture), encoding="utf-8") as stream:
            expected = bytes.fromhex(json.load(stream)["client_hello_hex"])
        got = shape(capture(xray, fingerprint))
        want = shape(expected)
        label = fingerprint or '""'
        if got == want:
            print(f"ok     {label} sends the shape of {fixture}")
            continue
        failures.append(label)
        print(f"FAIL   {label} differs from {fixture}")
        if got[0] != want[0]:
            print(f"       cipher suites {got[0]} != {want[0]}")
        for kind in sorted(set(got[1]) | set(want[1])):
            if got[1].get(kind) != want[1].get(kind):
                print(f"       extension {kind}: {got[1].get(kind)} != {want[1].get(kind)}")
    if failures:
        raise SystemExit(f"{len(failures)} fingerprint(s) differ: {', '.join(failures)}")


if __name__ == "__main__":
    main()

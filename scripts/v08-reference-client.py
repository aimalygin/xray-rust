#!/usr/bin/env python3
"""Prepare pinned full clients for the synthetic v0.8 SOCKS comparison.

Preparation happens before the measured binary is spawned. No Python/OpenSSL
process, native-library adapter or config translator is included in client CPU.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

METHODS = ("2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
           "2022-blake3-chacha20-poly1305")
CIPHERS = ("auto", "aes-128-gcm", "chacha20-poly1305")


def translate(config, mode, cert):
    config = copy.deepcopy(config)
    inbound, = config["inbounds"]
    outbound, = config["outbounds"]
    settings = outbound["settings"]
    stream = outbound["streamSettings"]
    protocol = outbound["protocol"]
    if (mode not in ("xray", "singbox") or inbound.get("protocol") != "socks"
            or inbound.get("listen") != "127.0.0.1"
            or settings.get("address") != "127.0.0.1"
            or stream.get("network") != "raw" or outbound.get("mux")):
        raise ValueError("only the synthetic loopback/raw SOCKS comparison is supported")
    if protocol == "shadowsocks" and settings.get("method") not in METHODS:
        raise ValueError("SS2022 method required")
    if protocol == "vmess" and (settings.get("security") not in CIPHERS
                                or settings.get("alterId", 0) != 0
                                or settings.get("experiments")):
        raise ValueError("standard VMess AEAD profile required")
    if protocol not in ("trojan", "shadowsocks", "vmess"):
        raise ValueError("unsupported comparison protocol")
    if protocol != "trojan" and stream.get("security", "none") != "none":
        raise ValueError("protocol AEAD comparison must not add outer TLS")
    if protocol == "trojan":
        tls = stream.get("tlsSettings", {})
        if (stream.get("security") != "tls" or tls.get("allowInsecure")
                or tls.get("fingerprint") != "chrome"):
            raise ValueError("verified Chrome-shaped TLS required for Trojan")
        der = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-outform", "DER"])
        if hashlib.sha256(der).hexdigest() != tls["pinnedPeerCertSha256"]:
            raise ValueError("fixture certificate does not match the measured pin")
    if mode == "xray":
        return config, ["run", "-config"], "xray"
    out = {"type": protocol, "tag": "proxy", "server": settings["address"],
           "server_port": settings["port"]}
    if protocol == "trojan":
        public = subprocess.check_output(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"])
        spki = subprocess.check_output(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public)
        out.update(password=settings["password"], tls={
            "enabled": True, "server_name": tls["serverName"], "alpn": tls["alpn"],
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "certificate_public_key_sha256": [base64.b64encode(hashlib.sha256(spki).digest()).decode()]})
    elif protocol == "shadowsocks":
        out.update(method=settings["method"], password=settings["password"])
    else:
        # Both Rust and the pinned Xray enable global padding for AEAD and use
        # XUDP on the non-DNS/non-QUIC destination ports selected by the driver.
        out.update(uuid=settings["id"], security=settings["security"], alter_id=0,
                   global_padding=True, authenticated_length=False, packet_encoding="xudp")
    return {"log": {"level": "error"}, "inbounds": [{
        "type": "socks", "listen": "127.0.0.1", "listen_port": inbound["port"]}],
        "outbounds": [out], "route": {"final": "proxy"}}, ["run", "-c"], "singbox"


def main():
    if len(sys.argv) != 4 or sys.argv[1:3] != ["prepare", "-config"]:
        raise ValueError("expected prepare -config FILE")
    spec = json.loads(Path(sys.argv[0] + ".json").read_text())
    source = Path(sys.argv[3])
    config, args, kind = translate(json.loads(source.read_text()), spec["mode"],
                                   os.environ.get("BENCH_REFERENCE_CERT", ""))
    target = source.with_name("reference-client.json")
    target.write_text(json.dumps(config, indent=2) + "\n")
    print(json.dumps({"binary": spec["binaries"][kind], "args": [*args, str(target)]}))


if __name__ == "__main__":
    main()

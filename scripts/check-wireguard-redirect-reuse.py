#!/usr/bin/env python3
"""Isolated-network reference check: UDP tuple reuse with Xray freedom redirect.

Uses an existing private fixture only for ephemeral keys. Run inside a fresh Linux network namespace with unshare --net. Carrier sockets
use loopback; synthetic service IPs exist only on that namespace's loopback.
No host routes/TUN or application retries.
"""
import argparse
import base64
import hashlib
import json
import os
import pathlib
import select
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!' + 'H' * (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def packet(source_port, destination, payload):
    host, port = destination
    udp = struct.pack('!HHHH', source_port, port, len(payload) + 8, 0) + payload
    pseudo = socket.inet_aton('10.44.0.2') + socket.inet_aton(host) + struct.pack('!BBH', 0, 17, len(udp))
    udp = udp[:6] + struct.pack('!H', checksum(pseudo + udp) or 65535) + udp[8:]
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                     socket.inet_aton('10.44.0.2'), socket.inet_aton(host))
    return ip[:10] + struct.pack('!H', checksum(ip)) + ip[12:] + udp


def udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def run_case(args, config, client, redirect, parent):
    procs = []
    done = threading.Event()
    echoes = []
    with tempfile.TemporaryDirectory(prefix='r-', dir=parent) as work:
        work = pathlib.Path(work)
        try:
            for host in (['127.0.0.1', '127.0.0.1'] if redirect else ['198.51.100.7', '198.51.100.53']):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.bind((host, 0))
                echoes.append(s)

            def echo():
                while not done.is_set():
                    for s in select.select(echoes, [], [], .1)[0]:
                        data, address = s.recvfrom(2048)
                        s.sendto(data, address)
            worker = threading.Thread(target=echo)
            worker.start()
            server_port = udp_port()
            server = json.loads(json.dumps(config))
            server['inbounds'] = [server['inbounds'][0]]
            server['inbounds'][0].update(listen='127.0.0.1', port=server_port)
            server['routing']['rules'][0]['ip'].append('127.0.0.0/8')
            settings = server['outbounds'][1]['settings']
            settings['finalRules'] = [{'action': 'allow', 'ip': ['127.0.0.0/8', '198.51.100.0/24']}]
            if redirect:
                settings['redirect'] = '127.0.0.1:0'
            else:
                settings.pop('redirect', None)
            path = work/'server.json'
            path.write_text(json.dumps(server)); path.chmod(0o600)
            log = (work/'process.log').open('wb')
            procs.append(subprocess.Popen([args.xray_binary, 'run', '-c', str(path)], stdout=log, stderr=log))
            time.sleep(.4)
            if procs[-1].poll() is not None:
                raise RuntimeError('loopback reference server startup failed')
            bridge_path = work/'bridge.sock'
            client_path = work/'client.sock'
            c = {'listen': f'127.0.0.1:{udp_port()}',
                 'endpoint': f'127.0.0.1:{server_port}',
                 'privateKey': base64.b64decode(client['secretKey']).hex(),
                 'peerKey': base64.b64decode(client['peers'][0]['publicKey']).hex(),
                 'presharedKey': base64.b64decode(client['peers'][0]['preSharedKey']).hex(),
                 'packetSocket': str(bridge_path), 'packetClient': str(client_path), 'verbose': True}
            path = work/'client.json'; path.write_text(json.dumps(c)); path.chmod(0o600)
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as bridge:
                bridge.bind(str(client_path)); bridge.settimeout(5)
                procs.append(subprocess.Popen([args.go_binary, str(path)], stdout=log, stderr=log))
                until = time.monotonic() + 3
                while not bridge_path.exists() and time.monotonic() < until:
                    time.sleep(.02)
                if not bridge_path.exists():
                    raise RuntimeError('packet bridge startup failed')
                a = ('198.51.100.7', echoes[0].getsockname()[1])
                b = ('198.51.100.53', echoes[1].getsockname()[1])
                results = []
                for label, source_port, destination in [('first-target', 55000, a), ('reused-port-new-target', 55000, b), ('fresh-port-new-target', 55001, b)]:
                    payload = ('synthetic-' + label).encode()
                    begun = time.monotonic()
                    bridge.sendto(packet(source_port, destination, payload), str(bridge_path))
                    try:
                        received = bridge.recv(2048)
                    except TimeoutError:
                        print(json.dumps({'redirect': redirect, 'failedCase': label, 'processReturnCodes': [p.poll() for p in procs]}), flush=True)
                        text = (work/'process.log').read_text()
                        for key in [client['secretKey'], client['peers'][0]['preSharedKey']]:
                            text = text.replace(key, '[redacted]').replace(base64.b64decode(key).hex(), '[redacted]')
                        print(text, flush=True)
                        raise
                    assert received[0] >> 4 == 4 and received[9] == 17
                    offset = (received[0] & 15) * 4
                    source = (socket.inet_ntoa(received[12:16]), struct.unpack_from('!H', received, offset)[0])
                    target_port = struct.unpack_from('!H', received, offset+2)[0]
                    assert target_port == source_port and received[offset+8:] == payload
                    results.append({'case': label, 'innerSourcePort': source_port, 'expectedReplySource': list(destination), 'observedReplySource': list(source), 'sourceMatches': source == destination, 'payloadMatches': True, 'seconds': time.monotonic()-begun, 'applicationRetries': 0})
                expected = [True, False, True] if redirect else [True, True, True]
                print(json.dumps({'redirect': redirect, 'results': results}), flush=True)
                assert [r['sourceMatches'] for r in results] == expected, 'reference behavior differs from hypothesized redirect collision'
                return {'redirect': redirect, 'expectedPatternConfirmed': True, 'results': results}
        finally:
            for process in reversed(procs):
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            done.set()
            if 'worker' in locals():
                worker.join(timeout=1)
            for s in echoes:
                s.close()
            if 'log' in locals():
                log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fixture-dir', type=pathlib.Path, required=True)
    parser.add_argument('--xray-binary', required=True)
    parser.add_argument('--go-binary', required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    if sys.platform != 'linux' or os.readlink('/proc/self/ns/net') == os.readlink('/proc/1/ns/net'):
        parser.error('run in a fresh Linux network namespace using unshare --net')
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    for address in ['198.51.100.7/32', '198.51.100.53/32']:
        subprocess.run(['ip', 'addr', 'add', address, 'dev', 'lo'], check=True)
    config = json.loads((args.fixture_dir/'server.json').read_text())
    profile = json.loads((args.fixture_dir/'v07-probe.json').read_text())
    client_config = json.loads(profile['cases'][0]['configJSON'])
    client = next(o['settings'] for o in client_config['outbounds'] if o['protocol']=='wireguard')
    report = {'scope': 'Pinned Xray-core server and official wireguard-go raw client in isolated Linux network namespace; no xray-rust client code', 'xraySha256': hashlib.sha256(pathlib.Path(args.xray_binary).read_bytes()).hexdigest(), 'goReferenceSha256': hashlib.sha256(pathlib.Path(args.go_binary).read_bytes()).hexdigest(), 'cases': []}
    for redirect in [True, False]:
        report['cases'].append(run_case(args, config, client, redirect, args.fixture_dir.parent))
    args.output.write_text(json.dumps(report, indent=2)+'\n')
    print(json.dumps({'redirectCollisionReproduced': True, 'withoutRedirectSamePortReusePassed': True, 'applicationRetries': 0}))

if __name__ == '__main__':
    main()

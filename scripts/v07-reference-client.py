#!/usr/bin/env python3
"""Benchmark launcher: translate a synthetic Xray config and exec one client.

A generated adjacent .json pins mode and binaries. exec preserves the PID, so
resource samples belong to the real client, not to an unmeasured child process.
Only the synthetic loopback SOCKS/carrier benchmark is supported.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys


def translate(config, mode, cert):
    inbound, = config['inbounds']
    outbound, = config['outbounds']
    if inbound['protocol'] != 'socks' or inbound['listen'] != '127.0.0.1':
        raise ValueError('only the loopback SOCKS benchmark is supported')
    listen = f"127.0.0.1:{inbound['port']}"
    settings = outbound['settings']
    protocol = outbound['protocol']
    if mode == 'xray':
        if protocol == 'wireguard':
            settings['noKernelTun'] = True
        return config, ['run', '-config'], 'xray'
    if protocol == 'hysteria':
        stream = outbound['streamSettings']
        tls = stream['tlsSettings']
        if settings['address'] != '127.0.0.1':
            raise ValueError('carrier must be loopback')
        if mode == 'native':
            return {'server': f"127.0.0.1:{settings['port']}",
                    'auth': stream['hysteriaSettings']['auth'],
                    'tls': {'sni': tls['serverName'], 'insecure': True,
                            'pinSHA256': tls['pinnedPeerCertSha256']},
                    'socks5': {'listen': listen}}, ['client', '--log-level', 'error', '-c'], 'hysteria'
        der = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-outform', 'DER'])
        if hashlib.sha256(der).hexdigest() != tls['pinnedPeerCertSha256']:
            raise ValueError('fixture certificate does not match the measured pin')
        public = subprocess.check_output(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout'])
        spki = subprocess.check_output(['openssl', 'pkey', '-pubin', '-outform', 'DER'], input=public)
        out = {'type': 'hysteria2', 'tag': 'proxy', 'server': '127.0.0.1',
               'server_port': settings['port'], 'password': stream['hysteriaSettings']['auth'],
               'tls': {'enabled': True, 'server_name': tls['serverName'],
                       'certificate_public_key_sha256': [base64.b64encode(hashlib.sha256(spki).digest()).decode()]}}
        extra = {'outbounds': [out]}
    elif protocol == 'wireguard':
        peer, = settings['peers']
        address, port = peer['endpoint'].rsplit(':', 1)
        if address != '127.0.0.1':
            raise ValueError('carrier must be loopback')
        if mode == 'native':
            return {'listen': listen, 'private_key': settings['secretKey'],
                    'public_key': peer['publicKey'], 'preshared_key': peer['preSharedKey'],
                    'endpoint': peer['endpoint'], 'addresses': settings['address'],
                    'mtu': settings['mtu']}, [], 'wireguard'
        extra = {'endpoints': [{'type': 'wireguard', 'tag': 'proxy', 'system': False,
                  'mtu': settings['mtu'], 'address': settings['address'],
                  'private_key': settings['secretKey'], 'peers': [{'address': address,
                  'port': int(port), 'public_key': peer['publicKey'],
                  'pre_shared_key': peer['preSharedKey'], 'allowed_ips': peer['allowedIPs'],
                  'persistent_keepalive_interval': peer.get('keepAlive', 0)}]}]}
    else:
        raise ValueError('unsupported reference protocol')
    return {'log': {'level': 'error'}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1',
             'listen_port': inbound['port']}], 'route': {'final': 'proxy'}, **extra}, ['run', '-c'], 'singbox'


def main():
    if len(sys.argv) != 4 or (sys.argv[1] not in ('run', 'prepare') or sys.argv[2] != '-config'):
        raise ValueError('expected frozen driver invocation: run -config FILE')
    spec = json.loads(Path(sys.argv[0] + '.json').read_text())
    path = Path(sys.argv[3])
    config, args, kind = translate(json.loads(path.read_text()), spec['mode'],
                                   os.environ.get('BENCH_REFERENCE_CERT', ''))
    target = path.with_name('reference-client.json')
    target.write_text(json.dumps(config, indent=2) + '\n')
    binary = spec['binaries'][kind]
    if sys.argv[1] == 'prepare':
        print(json.dumps({'binary': binary, 'args': [*args, str(target)]}))
    else:
        os.execv(binary, [binary, *args, str(target)])


if __name__ == '__main__':
    main()

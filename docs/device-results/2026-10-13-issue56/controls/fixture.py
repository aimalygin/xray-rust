#!/usr/bin/env python3
"""Diagnostic fixture: source unchanged except portable repository lookup/formatting."""

import importlib.util, pathlib, sys, json, time, hashlib, os, asyncio, socket
root = pathlib.Path(__file__).resolve().parents[4]
spec = importlib.util.spec_from_file_location('android', root / 'scripts/run-v08-android-protocol-fixture.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

class Oracle(m.Oracle):

    def datagram_received(self, data, address):
        response = m.oracle_reply(data)
        print(json.dumps({'event': 'backend-recv', 'time': time.time(), 'bytes': len(data), 'tag': hashlib.sha256(data if response else data[:2] + bytes.fromhex('01000001000000000000') + data[12:67]).hexdigest()[:16], 'peer': address, 'local': self.transport.get_extra_info('sockname'), 'validQuery': response is not None}), flush=True)
        super().datagram_received(data, address)

    def error_received(self, exc):
        print(json.dumps({'event': 'backend-error', 'time': time.time(), 'error': repr(exc)}), flush=True)
m.fixture.Echo = Oracle
m.fixture.tcp_echo = m.http_probe
orig = m.write_fixtures

def write(*a, **kw):
    orig(*a, **kw)
    p = a[0] / 'server.json'
    v = json.loads(p.read_text())
    v['log']['loglevel'] = 'info'
    if os.environ.get('ISSUE56_UNFIXED') == '1':
        for outbound in v['outbounds']:
            outbound.pop('sendThrough', None)
    p.write_text(json.dumps(v))
    for _ in range(int(os.environ.get('ISSUE56_DECOYS', '0'))):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(('127.0.0.1', 0))
        sock.setblocking(False)
        decoys.append(sock)

        def received(sock=sock):
            data, peer = sock.recvfrom(65536)
            query = data[:2] + bytes.fromhex('01000001000000000000') + data[12:67]
            print(json.dumps({'event': 'misdelivered-reply', 'time': time.time(), 'bytes': len(data), 'tag': hashlib.sha256(query).hexdigest()[:16], 'local': sock.getsockname(), 'peer': peer}), flush=True)
        asyncio.get_running_loop().add_reader(sock.fileno(), received)
    print(json.dumps({'event': 'decoy-sockets', 'ports': [s.getsockname()[1] for s in decoys], 'count': len(decoys)}), flush=True)
decoys = []
m.fixture.write_fixtures = write
m.fixture.main()

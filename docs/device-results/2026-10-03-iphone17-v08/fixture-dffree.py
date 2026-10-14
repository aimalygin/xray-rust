"""Diagnostic fixture: unmodified Xray peer behind a UDP relay allowing IP fragmentation.

Only the temporary public UDP socket changes; no host route/sysctl/firewall changes.
This is a separate control, not evidence that the original network path passed.
"""
import importlib.util
import json
from pathlib import Path
import select
import socket
import threading
import time

spec = importlib.util.spec_from_file_location('fixture', Path(__file__).with_name('fixture.py'))
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)
original = fixture.write_client_fixtures

def relay(front, root):
    peers = {}
    reverse = {}
    while True:
        mode = int((root / 'df-mode').read_text())
        assert mode in (0, 1)
        front.setsockopt(socket.IPPROTO_IP, 10, mode)
        (root / 'df-applied.json').write_text(json.dumps({'IP_MTU_DISCOVER': front.getsockopt(socket.IPPROTO_IP, 10)}) + '\n')
        ready, _, _ = select.select([front, *reverse], [], [], 0.2)
        now = time.monotonic()
        for upstream, (client, touched) in list(reverse.items()):
            if now - touched > 60:
                peers.pop(client, None)
                reverse.pop(upstream)
                upstream.close()
        for current in ready:
            if current is front:
                packet, client = front.recvfrom(8193)
                if len(packet) > 8192:
                    continue
                upstream = peers.get(client)
                if upstream is None:
                    if len(peers) >= 256:
                        continue
                    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    upstream.connect(('127.0.0.1', 53053))
                    peers[client] = upstream
                reverse[upstream] = (client, now)
                upstream.send(packet)
            elif current in reverse:
                packet = current.recv(8193)
                client, _ = reverse[current]
                reverse[current] = (client, now)
                if len(packet) <= 8192:
                    front.sendto(packet, client)

def write(root, bind, tcp_port, udp_port, dns_port, protocol, port, mode, probe_host):
    assert protocol == 'shadowsocks2022' and port == 53053
    original(root, bind, tcp_port, udp_port, dns_port, protocol, port, mode, probe_host)
    p = root / 'server.json'
    config = json.loads(p.read_text())
    original_inbound = config['inbounds'][0]
    udp = json.loads(json.dumps(original_inbound))
    udp['listen'] = '127.0.0.1'
    udp['settings']['network'] = 'udp'
    original_inbound['settings']['network'] = 'tcp'
    config['inbounds'].append(udp)
    p.write_text(json.dumps(config, indent=2) + '\n')
    front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    front.setsockopt(socket.IPPROTO_IP, 10, 0)  # Linux IP_MTU_DISCOVER=IP_PMTUDISC_DONT
    assert front.getsockopt(socket.IPPROTO_IP, 10) == 0
    front.bind((bind, port))
    (root / 'df-mode').write_text('0\n')
    threading.Thread(target=relay, args=(front, root), daemon=True).start()

fixture.write_client_fixtures = write
fixture.main()

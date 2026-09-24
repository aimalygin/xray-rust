#!/usr/bin/env python3
"""Controlled userspace UDP delay for local Hysteria2/WireGuard benchmarks.

Adds symmetric latency without changing host routes or requiring a kernel TUN.
A bounded relay reports any drops/errors; such runs are not valid delay-only
comparisons. Use the same driver and pinned reference for every engine.
"""
import argparse
import contextlib
import copy
import heapq
import importlib.util
import socket
import threading
import time
from pathlib import Path

SPEC = importlib.util.spec_from_file_location('followup', Path(__file__).with_name('run-v07-performance-followup.py'))
followup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(followup)
bench = followup.bench


class Relay:
    def __init__(self, server, delay, rate_mbps):
        self.server = server
        self.delay = delay
        self.bytes_per_second = rate_mbps * 1_000_000 / 8
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 0))
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)
        self.port = self.socket.getsockname()[1]
        self.stop = threading.Event()
        self.stats = dict(received=0, forwarded=0, dropped=0, peak_queued_bytes=0, error=None, receive_buffer_bytes=self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF), send_buffer_bytes=self.socket.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF))
        self.thread = threading.Thread(target=self.run, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *unused):
        self.stop.set()
        self.thread.join(timeout=2)
        self.socket.close()
        if self.thread.is_alive():
            raise RuntimeError('relay thread did not stop')

    def run(self):
        queue, client, queued, sequence = [], None, 0, 0
        next_send = {True: 0.0, False: 0.0}
        try:
            while not self.stop.is_set():
                now = time.monotonic()
                while queue and queue[0][0] <= now:
                    _, _, data, target = heapq.heappop(queue)
                    queued -= len(data)
                    self.socket.sendto(data, target)
                    self.stats['forwarded'] += 1
                self.socket.settimeout(min(.005, max(0.00001, queue[0][0] - time.monotonic())) if queue else .005)
                try:
                    data, address = self.socket.recvfrom(65535)
                except socket.timeout:
                    continue
                self.stats['received'] += 1
                if address == self.server:
                    target = client
                else:
                    if client is not None and client != address:
                        raise RuntimeError('unexpected second client endpoint')
                    client, target = address, self.server
                if target is None or queued + len(data) > 32 * 1024 * 1024:
                    self.stats['dropped'] += 1
                    continue
                sequence += 1
                direction = address == self.server
                # Independent per-direction serialization prevents the relay
                # from releasing a multi-megabyte window in one UDP burst.
                next_send[direction] = max(time.monotonic(), next_send[direction]) + len(data) / self.bytes_per_second
                heapq.heappush(queue, (next_send[direction] + self.delay, sequence, data, target))
                queued += len(data)
                self.stats['peak_queued_bytes'] = max(queued, self.stats['peak_queued_bytes'])
        except Exception as error:
            self.stats['error'] = repr(error)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--engine', action='append', required=True, help='label=/absolute/binary')
    p.add_argument('--harness', type=Path, required=True)
    p.add_argument('--reference', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--protocol', choices=['hysteria2', 'wireguard'], action='append')
    p.add_argument('--traffic', choices=['upload', 'download', 'full-duplex'], action='append')
    p.add_argument('--repeats', type=int, default=3)
    p.add_argument('--iterations', type=int, default=32)
    p.add_argument('--connections', type=int, choices=[1, 8], action='append')
    p.add_argument('--one-way-ms', type=float, default=25)
    p.add_argument('--rate-mbps', type=float, default=100)
    p.add_argument('--path', choices=['socks', 'tun'], action='append')
    args = p.parse_args()
    engines = dict(item.split('=', 1) for item in args.engine)
    if len(engines) != len(args.engine) or not 1 <= args.repeats <= 20 or not 1 <= args.iterations <= 16384 or not 0 <= args.one_way_ms <= 500 or not 1 <= args.rate_mbps <= 1000:
        raise ValueError('invalid or duplicated arguments')
    binaries = [Path(b).resolve(strict=True) for b in [*engines.values(), args.harness, args.reference]]
    if followup.inventory(binaries):
        raise RuntimeError('benchmark processes already running')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    scripts = [Path(__file__), Path(followup.__file__), Path(bench.__file__), bench.ROOT/'scripts/run-v07-apple-protocol-fixture.py']
    hashes = {str(b): bench.sha(b) for b in [*binaries, *scripts]}
    cases = [c for c in bench.protocol_cases('new', False) if c['path'] in (args.path or ['socks']) and c['protocol'] in (args.protocol or ['hysteria2','wireguard']) and c['traffic'] in (args.traffic or ['upload','download']) and c['connections'] in (args.connections or [1,8])]
    for c in cases:
        c['iterations'] = args.iterations
    manifest = dict(schema_version=1, suite='new', diagnostic=True, smoke=False, cases=cases,
        one_way_delay_ms=args.one_way_ms, link_mbps_per_direction=args.rate_mbps, repeats=args.repeats, file_hashes=hashes,
        reference_commit=bench.REFERENCE, started_unix=time.time(), runs=[],
        relay_policy='one endpoint per run, 32 MiB userspace cap, no intentional loss; kernel UDP loss is not counted',
        versions={k:dict(binary=v,engine_sha256=bench.sha(v)) for k,v in engines.items()})
    bench.save(output/'manifest.json', manifest)
    for case in cases:
        for repeat in range(1, args.repeats+1):
            for version in list(engines) if repeat % 2 else reversed(engines):
                identifier = f"{case['id']}-{version}-{repeat}"
                with bench.fixture(args.reference, output/f'{identifier}-server') as configs:
                    config = copy.deepcopy(configs[case['protocol']])
                    settings = config['outbounds'][0]['settings']
                    if case['protocol'] == 'wireguard':
                        address, port = settings['peers'][0]['endpoint'].rsplit(':',1)
                        settings['noKernelTun'] = True
                    else:
                        address, port = settings['address'], settings['port']
                    with Relay((address, int(port)), args.one_way_ms / 1000, args.rate_mbps) as relay:
                        if case['protocol'] == 'wireguard':
                            settings['peers'][0]['endpoint'] = f'127.0.0.1:{relay.port}'
                        else:
                            settings.update(address='127.0.0.1',port=relay.port)
                        request = {k:case[k] for k in ['path','traffic','connections','iterations','payload_size']}
                        request.update(binary=str(Path(engines[version]).resolve()), config=config, output=str(output/identifier))
                        request_path = output/f'{identifier}.json'
                        bench.save(request_path, request)
                        result = bench.execute([str(args.harness), 'protocol-run', str(request_path)], output/f'{identifier}.log', bench.ROOT)
                    result['relay'] = dict(relay.stats)
                result.update(case=case['id'],version=version,repeat=repeat,output_relative=identifier,
                    remaining_engine_processes=followup.inventory(binaries))
                manifest['runs'].append(result)
                bench.save(output/'manifest.json',manifest)
                print(identifier,result['returncode'],round(result['seconds'],2),result['relay'],flush=True)
                if result['remaining_engine_processes'] or result['surviving_process_group'] or relay.stats['error'] or relay.stats['dropped']:
                    raise RuntimeError('invalid delay-only run; see retained manifest')
    if any(bench.sha(path) != digest for path,digest in hashes.items()):
        raise RuntimeError('input changed during measurement')
    manifest.update(finished_unix=time.time(),status='pass' if all(r['returncode']==0 for r in manifest['runs']) else 'fail')
    bench.save(output/'manifest.json',manifest)
    if manifest['status'] != 'pass':
        raise SystemExit(1)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Paired pre/post-migration clients, one frozen driver and local reference.

Build first. Inputs bind release binaries to source/build metadata. Each case
has five AB/BA pairs; --smoke runs one short pair. Never overwrites evidence.
No public network origins, host routes, worker overrides or client translators.
"""
import argparse
import base64
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('comparison', ROOT / 'scripts/run-v08-protocol-comparison.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
b = c.bench
REFERENCE = '1b1647cd9ddf0abc34b981d4611fc03bcac1ca74'
VERSIONS = ('before', 'after')
CARRIERS = ('vless-tls', 'reality-vision', 'ws', 'httpupgrade', 'grpc', 'xhttp-h1', 'xhttp-h2', 'xhttp-h3')
PROFILES = (*c.PROFILES, *CARRIERS, 'hysteria2', 'wireguard', 'freedom')
BULK = ('upload', 'download', 'full-duplex')
COMPILERS = {'rustc', 'cargo', 'clang', 'clang++', 'go', 'compile', 'link', 'xcodebuild', 'swift-frontend'}


def cases(profiles=PROFILES, smoke=False):
    rows = []
    for profile in profiles:
        paths = ('socks', 'tun') if profile in ('hysteria2', 'wireguard', 'freedom', 'vless-tls', 'reality-vision', 'xhttp-h1', 'xhttp-h2', 'xhttp-h3') else ('socks',)
        traffic = (*BULK, 'tcp-latency', 'udp') if profile in (*c.PROFILES, 'hysteria2', 'wireguard') else BULK
        for path in paths:
            for flows in (1, 8):
                for kind in traffic:
                    echo = kind in ('tcp-latency', 'udp')
                    rows.append(dict(id=f'{profile}-{path}-{kind}-{flows}', profile=profile, path=path,
                        traffic=kind, connections=flows, payload_size=1200 if kind == 'udp' else 1024 if echo else 65536,
                        iterations=(10 if echo else 4) if smoke else 1000 if echo else 256 if path == 'tun' else 4096))
    return rows


def order(index, repeat):
    return list(VERSIONS if (index + repeat - 1) % 2 == 0 else reversed(VERSIONS))


def stop(child):
    if child.poll() is None:
        child.terminate()
    try:
        child.wait(5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait()


@contextlib.contextmanager
def origin(binary, directory):
    with (directory / 'origin.log').open('w') as err:
        child = subprocess.Popen([str(binary), 'origin'], stdout=subprocess.PIPE, stderr=err, text=True)
        try:
            if not select.select([child.stdout], [], [], 10)[0]:
                raise RuntimeError('local REALITY cover origin did not become ready')
            address = json.loads(child.stdout.readline())['address']
            if not address.startswith('127.0.0.1:'):
                raise ValueError('cover origin must be loopback')
            yield address, child.pid
        finally:
            stop(child)


def configs(profile, directory, address=None):
    port = b.port()
    if profile in c.PROFILES:
        return c.configs(profile, directory, port)
    if profile == 'freedom':
        return {'outbounds': [{'protocol': 'freedom'}]}, None
    if profile in ('hysteria2', 'wireguard'):
        c.device.write_fixtures(directory, '127.0.0.1', 1, 2, 3, protocol=profile, port=port)
        server = json.loads((directory / 'server.json').read_text())
        server.pop('routing')
        server['outbounds'] = [{'protocol': 'freedom', 'settings': {'finalRules': [{'action': 'allow'}]}}]
        client = json.loads(json.loads((directory / 'v07-probe.json').read_text())['cases'][0]['configJSON'])
        for key in ('routing', 'dns', 'inbounds'):
            client.pop(key)
        if profile == 'wireguard':
            client['outbounds'][0]['settings']['peers'][0]['allowedIPs'] = ['0.0.0.0/0']
        return client, server
    # Reuse the reviewed pinned TLS fixture, then replace only its protocol/carrier.
    client, server = c.configs('trojan-tls', directory, port)
    out, inbound = client['outbounds'][0], server['inbounds'][0]
    user = {'id': b.UUID, 'encryption': 'none'}
    out.update(protocol='vless', settings={'vnext': [{'address': '127.0.0.1', 'port': port, 'users': [user]}]})
    inbound.update(protocol='vless', settings={'decryption': 'none', 'clients': [{'id': b.UUID}]})
    cs, ss = out['streamSettings'], inbound['streamSettings']
    if profile == 'reality-vision':
        if not address or not address.startswith('127.0.0.1:'):
            raise ValueError('local cover origin required')
        keyfile = str(directory / 'reality.pem')
        c.device.openssl('genpkey', '-algorithm', 'X25519', '-out', keyfile)
        private_key = base64.urlsafe_b64encode(c.device.openssl('pkey', '-in', keyfile, '-outform', 'DER')[-32:]).decode().rstrip('=')
        public_key = base64.urlsafe_b64encode(c.device.openssl('pkey', '-in', keyfile, '-pubout', '-outform', 'DER')[-32:]).decode().rstrip('=')
        user['flow'] = 'xtls-rprx-vision'
        inbound['settings']['clients'][0]['flow'] = 'xtls-rprx-vision'
        cs.clear(); ss.clear()
        cs.update(network='raw', security='reality', realitySettings={
            'serverName': 'encryption-oracle.test', 'fingerprint': 'chrome',
            'publicKey': public_key, 'shortId': '0123456789abcdef'})
        ss.update(network='raw', security='reality', realitySettings={
            'dest': address, 'serverNames': ['encryption-oracle.test'],
            'privateKey': private_key, 'shortIds': ['0123456789abcdef']})
    elif profile != 'vless-tls':
        network = 'xhttp' if profile.startswith('xhttp-') else profile
        cs['network'] = ss['network'] = network
        alpn = 'h3' if profile == 'xhttp-h3' else 'h2' if profile in ('grpc', 'xhttp-h2') else 'http/1.1'
        cs['tlsSettings']['alpn'] = ss['tlsSettings']['alpn'] = [alpn]
        setting, value = ('grpcSettings', {'serviceName': 'bench'}) if profile == 'grpc' else (network + 'Settings', {'path': '/bench'})
        cs[setting] = copy.deepcopy(value); ss[setting] = copy.deepcopy(value)
        if network == 'xhttp':
            cs[setting]['mode'] = {'xhttp-h1': 'packet-up', 'xhttp-h2': 'stream-up', 'xhttp-h3': 'stream-one'}[profile]
            ss[setting]['mode'] = 'auto'
        if profile == 'xhttp-h3':
            cs['finalmask'] = {'quicParams': {}}
    return client, server


@contextlib.contextmanager
def fixture(paths, directory, profile):
    directory.mkdir(parents=True, mode=0o700)
    with contextlib.ExitStack() as stack:
        address, origin_pid = stack.enter_context(origin(paths['origin'], directory)) if profile == 'reality-vision' else (None, None)
        client, server = configs(profile, directory, address)
        if server is None:
            yield client, []
            return
        b.save(directory / 'server.json', server)
        log = stack.enter_context((directory / 'server.log').open('w'))
        child = subprocess.Popen([str(paths['reference']), 'run', '-config', str(directory / 'server.json')], stdout=log, stderr=log, env=b.env())
        stack.callback(stop, child)
        time.sleep(8 if profile == 'reality-vision' else 1)
        if child.poll() is not None:
            raise RuntimeError('reference failed to start; see server.log')
        yield client, [pid for pid in (child.pid, origin_pid) if pid]


def cpu_seconds(value):
    days, value = value.split('-', 1) if '-' in value else ('0', value)
    seconds = 0.0
    for part in value.split(':'):
        seconds = seconds * 60 + float(part)
    return int(days) * 86400 + seconds


def processes():
    rows = {}
    for line in b.command(['ps', '-axo', 'pid=,ppid=,time=,comm=']).splitlines():
        pid, parent, elapsed, name = line.strip().split(None, 3)
        rows[int(pid)] = {'parent': int(parent), 'seconds': cpu_seconds(elapsed), 'name': Path(name).name}
    return rows


def ambient(previous, current, elapsed):
    own = {os.getpid()}
    while True:
        children = {pid for pid, row in current.items() if row['parent'] in own}
        if children <= own:
            break
        own |= children
    external = []
    compilers = []
    for pid, row in current.items():
        if pid in own:
            continue
        if row['name'] in COMPILERS:
            compilers.append({'pid': pid, 'name': row['name']})
        if pid in previous and previous[pid]['name'] == row['name']:
            cpu = max(0, (row['seconds'] - previous[pid]['seconds']) * 100 / elapsed)
            if cpu:
                external.append({'pid': pid, 'name': row['name'], 'cpu_percent': cpu})
    total = sum(p['cpu_percent'] for p in external)
    # An ordinary foreground session is retained, not described as an idle lab.
    # >= one full external core, or >= two cores in aggregate, invalidates a run.
    heavy = any(p['cpu_percent'] >= 100 for p in external) or total >= 200
    return {'external_cpu_percent': total, 'top_external': sorted(external, key=lambda p: -p['cpu_percent'])[:10],
            'compiler_load_detected': compilers, 'heavy_external_load': heavy, 'load_average': os.getloadavg()}


def measured_execute(args, log):
    done = threading.Event()
    samples, errors = [], []
    def observe():
        try:
            previous, started = processes(), time.monotonic()
            while True:
                finished = done.wait(1)
                # ps CPU counters have centisecond resolution. Never divide
                # a final tiny remainder by a few milliseconds. Complete a
                # full observation interval even when the workload has ended.
                remainder = 1 - (time.monotonic() - started)
                if remainder > 0:
                    time.sleep(remainder)
                current, now = processes(), time.monotonic()
                samples.append({'unix': time.time(), **ambient(previous, current, now - started)})
                previous, started = current, now
                if finished:
                    break
        except Exception as error:
            errors.append(str(error))
    observer = threading.Thread(target=observe)
    observer.start()
    try:
        result = b.execute(args, log, ROOT)
    finally:
        done.set(); observer.join()
    result['ambient_cpu'] = {'samples': samples, 'observer_errors': errors,
        'compiler_load_detected': [p for s in samples for p in s['compiler_load_detected']],
        'heavy_external_load': any(s['heavy_external_load'] for s in samples)}
    return result


def clean(run):
    q = run['ambient_cpu']
    return (run['returncode'] == 0 and run['process_group_empty_after_run'] and not run['surviving_process_group']
            and not run['remaining_engine_processes'] and not q['observer_errors']
            and not q['compiler_load_detected'] and not q['heavy_external_load'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--profile', choices=PROFILES, action='append')
    parser.add_argument('--smoke', action='store_true')
    a = parser.parse_args()
    if a.profile and len(a.profile) != len(set(a.profile)):
        raise ValueError('duplicate profile')
    for key in list(os.environ):
        if key.startswith(('XRAY_', 'CARGO_PROFILE_')) or key in ('GOMAXPROCS', 'TOKIO_WORKER_THREADS', 'GOMEMLIMIT', 'GOGC'):
            del os.environ[key]
    os.umask(0o077)
    inputs = json.loads(a.inputs.read_text())
    paths = {name: Path(inputs[name]['path']).resolve(strict=True) for name in (*VERSIONS, 'harness', 'reference', 'origin')}
    for name, path in paths.items():
        if b.sha(path) != inputs[name]['sha256']:
            raise ValueError('binary changed: ' + name)
    if inputs['reference']['commit'] != REFERENCE:
        raise ValueError('wrong reference source')
    c.device.verify_reference(paths['reference'])
    if c.followup.inventory(paths.values()) or c.ambient()['compiler_load_detected']:
        raise RuntimeError('benchmark/compiler already running')
    source = b.command(['git', 'rev-parse', 'HEAD'], ROOT)
    if b.command(['git', 'status', '--porcelain'], ROOT):
        raise RuntimeError('commit collector changes before measurement')
    output = a.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    selected = cases(a.profile or PROFILES, a.smoke)
    indexes = {case['id']: i for i, case in enumerate(cases(smoke=a.smoke))}
    scripts = [Path(__file__), Path(c.__file__), Path(b.__file__), Path(c.followup.__file__), Path(c.device.__file__)]
    hashes = {str(p): b.sha(p) for p in [*paths.values(), a.inputs.resolve(), *scripts]}
    manifest = {'schema_version': 1, 'status': 'running', 'smoke': a.smoke, 'repeats': 1 if a.smoke else 5,
        'cases': selected, 'inputs': inputs, 'collector_commit': source, 'file_hashes': hashes, 'runs': [],
        'host': {'platform': platform.platform(), 'cpu': b.command(['sysctl', '-n', 'machdep.cpu.brand_string']),
                 'model': b.command(['sysctl', '-n', 'hw.model']), 'memory_bytes': int(b.command(['sysctl', '-n', 'hw.memsize'])),
                 'logical_cpus': os.cpu_count(), 'os': b.command(['sw_vers']), 'power': b.command(['pmset', '-g', 'batt']),
                 'thermal_start': b.command(['pmset', '-g', 'therm'])},
        'started_unix': time.time(), 'scope': 'Rust before/after; common v26.10.21 server; local synthetic traffic; stock workers',
        'quality_policy': 'fail on compiler, observer/cleanup/protocol error, external process >=100% CPU or aggregate >=200%; retain failed blocks',
        'ordering': 'five adjacent AB/BA pairs per case; first position alternates across cases; no performance-based retries'}
    b.save(output / 'manifest.json', manifest)
    try:
        for case in selected:
            for repeat in range(1, manifest['repeats'] + 1):
                client_order = order(indexes[case['id']], repeat)
                with fixture(paths, output / f"{case['id']}-server-{repeat}", case['profile']) as (config, allowed):
                    for version in client_order:
                        name = f"{case['id']}-{version}-{repeat}"
                        request = {k: case[k] for k in ('path', 'traffic', 'connections', 'iterations', 'payload_size')}
                        request.update(binary=str(paths[version]), config=copy.deepcopy(config), output=str(output / name),
                            warmup=case['path'] == 'socks', client_preface=case['path'] == 'socks' and case['traffic'] in BULK)
                        b.save(output / (name + '.json'), request)
                        result = measured_execute([str(paths['harness']), 'protocol-run', str(output / (name + '.json'))], output / (name + '.log'))
                        result.update(case=case['id'], version=version, repeat=repeat, output_relative=name, client_order=client_order,
                            remaining_engine_processes=[p for p in c.followup.inventory(paths.values()) if int(p.split(None, 1)[0]) not in allowed])
                        manifest['runs'].append(result)
                        b.save(output / 'manifest.json', manifest)
                        print(name, result['returncode'], round(result['seconds'], 2), flush=True)
                        # Smoke validates functionality only; its timing is never
                        # publishable. Preserve background-load evidence but do
                        # not let it prevent checking the remaining fixtures.
                        functional = copy.deepcopy(result)
                        if a.smoke:
                            functional['ambient_cpu']['heavy_external_load'] = False
                        if not clean(functional):
                            raise RuntimeError('failed or contaminated trial; entire block retained')
                if c.followup.inventory(paths.values()):
                    raise RuntimeError('fixture process survived cleanup')
        if any(b.sha(p) != digest for p, digest in hashes.items()):
            raise RuntimeError('input changed during measurement')
        manifest['status'] = 'pass'
    except BaseException as error:
        manifest.update(status='fail', error=str(error))
        raise
    finally:
        manifest['finished_unix'] = time.time()
        manifest['host']['thermal_end'] = b.command(['pmset', '-g', 'therm'])
        b.save(output / 'manifest.json', manifest)


if __name__ == '__main__':
    main()

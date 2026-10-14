#!/usr/bin/env python3
"""Measure held RSS and verified resume on the same protocol connections.

Frozen full clients, rotating order, pinned Xray fixture. Python echo timings
are end-to-end diagnostics, not a replacement for the bulk Rust harness.
No compilation or other benchmark may overlap this campaign.
"""
import argparse
import asyncio
import copy
import ctypes
import platform
import importlib.util
import json
import os
from pathlib import Path
import resource
import signal
import socket
import statistics
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('comparison', ROOT / 'scripts/run-v08-protocol-comparison.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


# Layout from the macOS SDK sys/resource.h: rusage_info_v0 (96 bytes).
class RusageInfoV0(ctypes.Structure):
    _fields_ = [('uuid', ctypes.c_ubyte * 16)] + [(name, ctypes.c_uint64) for name in (
        'user_time', 'system_time', 'pkg_idle_wkups', 'interrupt_wkups', 'pageins',
        'wired_size', 'resident_size', 'phys_footprint', 'proc_start_abstime', 'proc_exit_abstime')]


LIBPROC = None
if platform.system() == 'Darwin':
    assert ctypes.sizeof(RusageInfoV0) == 96
    LIBPROC = ctypes.CDLL('/usr/lib/libproc.dylib', use_errno=True)
    LIBPROC.proc_pid_rusage.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    LIBPROC.proc_pid_rusage.restype = ctypes.c_int


def footprint(pid):
    if LIBPROC is None:
        return {}
    usage = RusageInfoV0()
    if LIBPROC.proc_pid_rusage(pid, 0, ctypes.byref(usage)):
        raise OSError(ctypes.get_errno(), 'proc_pid_rusage failed')
    return {'footprint_kib': usage.phys_footprint / 1024,
            'resident_kib': usage.resident_size / 1024, 'pageins': usage.pageins,
            'package_idle_wakeups': usage.pkg_idle_wkups, 'interrupt_wakeups': usage.interrupt_wkups}


def snapshot(pid):
    rss, cpu = subprocess.check_output(['ps', '-o', 'rss=,time=', '-p', str(pid)], text=True).split()
    parts = [float(p) for p in cpu.split(':')]
    seconds = sum(p * 60 ** i for i, p in enumerate(reversed(parts)))
    return {'unix': time.time(), 'rss_kib': int(rss), 'cpu_ms': round(seconds * 1000), **footprint(pid)}


async def run(binary, config, directory, count, warmup_bytes, idle_seconds):
    directory.mkdir()
    port = c.bench.port()
    config = copy.deepcopy(config)
    config['inbounds'] = [{'protocol': 'socks', 'listen': '127.0.0.1', 'port': port,
                           'settings': {'auth': 'noauth', 'udp': False}}]
    c.bench.save(directory / 'config.json', config)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.connect(('8.8.8.8', 80))  # Route lookup; sends no packets.
        ip = probe.getsockname()[0]
    accepted, clients, tasks = set(), [], set()
    phases = []
    checked = 0
    async def echo(reader, writer):
        accepted.add(writer)
        task = asyncio.current_task()
        tasks.add(task)
        try:
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.CancelledError):
            pass
        finally:
            writer.close()
            accepted.discard(writer)
            tasks.discard(task)
    server = await asyncio.start_server(echo, ip, 0)
    target_port = server.sockets[0].getsockname()[1]
    payload = (bytes(range(251)) * ((warmup_bytes + 250) // 251))[:warmup_bytes]
    async def exchange(reader, writer, data):
        nonlocal checked
        started = time.perf_counter_ns()
        writer.write(data)
        await writer.drain()
        received = await reader.readexactly(len(data))
        assert received == data
        checked += len(data)
        return (time.perf_counter_ns() - started) / 1000
    async def connect():
        reader, writer = await asyncio.open_connection('127.0.0.1', port)
        clients.append((reader, writer))
        writer.write(b'\x05\x01\x00')
        await writer.drain()
        assert await reader.readexactly(2) == b'\x05\x00'
        writer.write(b'\x05\x01\x00\x01' + socket.inet_aton(ip) + target_port.to_bytes(2, 'big'))
        await writer.drain()
        response = await reader.readexactly(4)
        assert response[:3] == b'\x05\x00\x00'
        size = {1: 4, 4: 16}.get(response[3])
        if response[3] == 3:
            size = (await reader.readexactly(1))[0]
        assert size is not None
        await reader.readexactly(size + 2)
        await exchange(reader, writer, payload)
    async def batch_bulk():
        for offset in range(0, len(clients), 16):
            await asyncio.gather(*(exchange(r, w, payload) for r, w in clients[offset:offset + 16]))
    def save_phase(name, **extra):
        assert child.poll() is None
        point = {'phase': name, **snapshot(child.pid), **extra}
        phases.append(point)
        c.bench.save(directory / 'partial.json', {'phases': phases, 'checked_bytes_each_direction': checked})
        print(directory.name, name, point['rss_kib'], flush=True)
    child = None
    try:
        with (directory / 'stdout.log').open('w') as stdout, (directory / 'stderr.log').open('w') as stderr:
            child = subprocess.Popen([str(binary), 'run', '-config', str(directory / 'config.json')],
                                     stdout=stdout, stderr=stderr, env=c.bench.env(), start_new_session=True)
            for _ in range(100):
                assert child.poll() is None
                try:
                    _, writer = await asyncio.open_connection('127.0.0.1', port)
                    writer.close()
                    await writer.wait_closed()
                    break
                except ConnectionError:
                    await asyncio.sleep(.05)
            else:
                raise RuntimeError('client did not start')
            save_phase('empty')
            started = time.monotonic()
            while len(clients) < count:
                await asyncio.wait_for(asyncio.gather(*(connect() for _ in range(min(16, count - len(clients))))), 30)
            assert len(accepted) == count
            save_phase('warm', elapsed_seconds=time.monotonic() - started)
            for cycle in range(2):
                samples = []
                started = time.monotonic()
                for delay in [1, 2, 5, idle_seconds]:
                    await asyncio.sleep(max(0, started + delay - time.monotonic()))
                    assert child.poll() is None and len(accepted) == count
                    samples.append(snapshot(child.pid))
                save_phase(f'idle-{cycle}', samples=samples)
                # One request per connection, in order: first request after
                # idle (including cold reallocations), not warmed percentiles.
                latencies = [await exchange(r, w, payload[:1024]) for r, w in clients]
                save_phase(f'first-request-{cycle}', latency_us=latencies)
                started = time.monotonic()
                await asyncio.wait_for(batch_bulk(), 60)
                save_phase(f'resumed-bulk-{cycle}', elapsed_seconds=time.monotonic() - started)
            assert checked == count * (3 * warmup_bytes + 2 * 1024)
    finally:
        for _, writer in clients:
            writer.close()
        if child is not None:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(5)
        server.close()
        for writer in list(accepted):
            writer.close()
        for task in list(tasks):
            task.cancel()
        await asyncio.gather(*list(tasks), return_exceptions=True)
        await asyncio.wait_for(server.wait_closed(), 5)
    return {'status': 'pass', 'engine_sha256': c.bench.sha(binary), 'phases': phases,
            'connections': count, 'warmup_bytes': warmup_bytes, 'idle_seconds': idle_seconds,
            'checked_bytes_each_direction': checked, 'client_returncode_after_stop': child.returncode}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', action='append', required=True, help='NAME=PATH')
    p.add_argument('--reference', type=Path, required=True)
    p.add_argument('--profile', choices=list(c.PROFILES), action='append', required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--connections', type=int, default=512)
    p.add_argument('--warmup-bytes', type=int, default=1048576)
    p.add_argument('--idle-seconds', type=int, default=11)
    p.add_argument('--repeats', type=int, default=3)
    a = p.parse_args()
    assert 1 <= a.connections <= 512 and 8192 <= a.warmup_bytes <= 1048576
    assert 10 < a.idle_seconds <= 60 and 1 <= a.repeats <= 10
    for var in ('GOMAXPROCS', 'TOKIO_WORKER_THREADS', 'GOMEMLIMIT', 'GOGC'):
        os.environ.pop(var, None)
    os.umask(0o077)
    _, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (4096 if hard == resource.RLIM_INFINITY else min(4096, hard), hard))
    binaries = {name: Path(path).resolve(strict=True) for name, path in (item.split('=', 1) for item in a.binary)}
    assert len(binaries) == len(a.binary) and all(n.replace('-', '').isalnum() for n in binaries)
    reference = a.reference.resolve(strict=True)
    c.device.verify_reference(reference)
    paths = [*binaries.values(), reference]
    assert not c.ambient()['compiler_load_detected'] and not c.followup.inventory(paths)
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    files = [*paths, Path(__file__).resolve(), Path(c.__file__), Path(c.bench.__file__), Path(c.followup.__file__)]
    hashes = {str(path): c.bench.sha(path) for path in files}
    manifest = {'started_unix': time.time(), 'file_hashes': hashes, 'runs': [],
                'repeats': a.repeats, 'arguments': vars(a) | {'reference': str(reference), 'output': str(out)}}
    stopped = threading.Event()
    samples, errors = [], []
    def observe():
        try:
            while not stopped.is_set():
                samples.append({'unix': time.time(), **c.ambient()})
                stopped.wait(1)
        except Exception as error:
            errors.append(str(error))
    observer = threading.Thread(target=observe)
    observer.start()
    try:
        for index, profile in enumerate(a.profile):
            for repeat in range(1, a.repeats + 1):
                with c.fixture(reference, out / f'{profile}-server-{repeat}', profile) as (config, pid):
                    order = list(binaries)
                    offset = (index + repeat - 1) % len(order)
                    order = order[offset:] + order[:offset]
                    for version in order:
                        assert not c.ambient()['compiler_load_detected']
                        name = f'{profile}-{version}-{repeat}'
                        result = asyncio.run(asyncio.wait_for(run(binaries[version], config, out / name,
                                             a.connections, a.warmup_bytes, a.idle_seconds), 240))
                        remaining = [s for s in c.followup.inventory(paths) if int(s.split(None, 1)[0]) != pid]
                        assert not remaining
                        result.update(profile=profile, version=version, repeat=repeat, client_order=order,
                                      remaining_engine_processes=remaining)
                        c.bench.save(out / name / 'result.json', result)
                        manifest['runs'].append({'output_relative': name, 'version': version, 'profile': profile, 'repeat': repeat})
                        c.bench.save(out / 'manifest.json', manifest)
                assert not c.followup.inventory(paths)
        assert all(c.bench.sha(Path(path)) == digest for path, digest in hashes.items())
        manifest['status'] = 'pass'
    except BaseException:
        manifest['status'] = 'fail'
        raise
    finally:
        stopped.set()
        observer.join()
        manifest['ambient_cpu'] = {'samples': samples, 'observer_errors': errors,
                                  'compiler_load_detected': [p for s in samples for p in s['compiler_load_detected']]}
        if errors or manifest['ambient_cpu']['compiler_load_detected']:
            manifest['status'] = 'fail'
        manifest['finished_unix'] = time.time()
        c.bench.save(out / 'manifest.json', manifest)
        if manifest['status'] != 'pass':
            raise RuntimeError('failed/contaminated campaign; all evidence retained')


if __name__ == '__main__':
    main()

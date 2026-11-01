#!/usr/bin/env python3
"""Interleaved A/B of two isolated xray-rust builds on xray-bench XHTTP H3 stream cases.

stream_ab.py --campaign DIR --rounds N [--scenario upload-32 ...]

DIR holds bin/before, bin/after and build/{before,after}.json from
scripts/build-isolated-release.py. Every round runs each scenario once per
version, alternating which version goes first across rounds and scenarios.
A pair is repeated (both versions) when either run failed or the
collector's ambient-load rule rejected it. Results go to DIR/stream-ab.jsonl.
"""
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import time

# The checkout these scripts live in: docs/benchmarks/results/<report>/scripts/.
WORKTREE = Path(__file__).resolve().parents[5]
HARNESS = Path('/Users/antonmalygin/xray-rust/target/benchmarks/2026-10-30-perf-final.noindex/bin/harness')
HARNESS_SHA256 = 'e5a9561f140ef79d62802940d1c1fb0097b3155bb9c7cdf55acd7b52e6cba933'
XRAY_CORE = Path('/private/tmp/xray-migration-tools/xray-v26.10.21')
XRAY_CORE_SHA256 = 'b8c58f14180eb0cad5665fa2cefb7d10897eec945d007212a053fc1de2257ee8'
SCENARIOS = [f'{traffic}-{flows}' for traffic in ('upload', 'full-duplex', 'download') for flows in (32, 1)]

spec = importlib.util.spec_from_file_location('campaign', WORKTREE / 'scripts/run-migration-campaign.py')
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)
collector = campaign.m

libproc = ctypes.CDLL('/usr/lib/libproc.dylib')
RUSAGE_INFO_V4 = 4
LIFETIME_MAX_FOOTPRINT_OFFSET = 16 + 28 * 8


def lifetime_max_footprint(pid):
    buffer = ctypes.create_string_buffer(512)
    if libproc.proc_pid_rusage(pid, RUSAGE_INFO_V4, buffer) != 0:
        return None
    return int.from_bytes(buffer.raw[LIFETIME_MAX_FOOTPRINT_OFFSET:LIFETIME_MAX_FOOTPRINT_OFFSET + 8], 'little')


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def client_pid(binary):
    out = subprocess.run(['pgrep', '-f', f'^{binary} run -config'], capture_output=True, text=True).stdout.split()
    return int(out[0]) if out else None


def run_once(binary, scenario, out_dir):
    traffic, flows = scenario.rsplit('-', 1)
    command = [str(HARNESS), 'run', '--engine', 'xray-rust', '--xray-rust-bin', str(binary),
               '--xray-core-bin', str(XRAY_CORE), '--no-auto-build', '--workload', 'stream-transport',
               '--stream-transport', 'xhttp-h3', '--xhttp-mode', 'stream-up', '--traffic', traffic,
               '--connections', flows, '--iterations', '4096', '--payload-size', '65536', '--runs', '1',
               '--run-timeout-ms', '300000', '--out-dir', str(out_dir)]
    samples, footprint = [], {'kib': None}
    done = threading.Event()

    def observe():
        previous, started = collector.processes(), time.monotonic()
        while not done.wait(1):
            current, now = collector.processes(), time.monotonic()
            samples.append(collector.ambient(previous, current, now - started))
            previous, started = current, now

    def watch_footprint():
        pid = None
        while not done.is_set():
            pid = pid or client_pid(binary)
            if pid:
                value = lifetime_max_footprint(pid)
                if value is not None:
                    footprint['kib'] = max(footprint['kib'] or 0, value // 1024)
            time.sleep(0.05)

    threads = [threading.Thread(target=observe), threading.Thread(target=watch_footprint)]
    for thread in threads:
        thread.start()
    started = time.time()
    with (out_dir.parent / (out_dir.name + '.log')).open('w') as log:
        returncode = subprocess.run(command, cwd=WORKTREE, stdout=log, stderr=subprocess.STDOUT).returncode
    done.set()
    for thread in threads:
        thread.join()
    results = list(out_dir.glob('*/xray-rust/stream-transport/result.json'))
    result = json.loads(results[0].read_text()) if results else {}
    heavy = any(s['heavy_external_load'] for s in samples)
    compilers = [c for s in samples for c in s['compiler_load_detected']]
    return {
        'returncode': returncode, 'status': result.get('status'), 'started_unix': started,
        'peak_rss_kib': result.get('peak_rss_kib'), 'peak_footprint_kib': footprint['kib'],
        'cpu_millis': result.get('cpu_millis'), 'cpu_millis_per_gib': result.get('cpu_millis_per_gib'),
        'throughput_mbps': result.get('throughput_mbps'), 'transfer_duration_ms': result.get('transfer_duration_ms'),
        'bytes_sent': result.get('bytes_sent'), 'bytes_received': result.get('bytes_received'),
        'heavy_external_load': heavy, 'compiler_load_detected': compilers,
        'max_external_cpu_percent': max((s['external_cpu_percent'] for s in samples), default=0),
        'top_external': max(samples, key=lambda s: s['external_cpu_percent'])['top_external'][:3] if samples else [],
    }


def accepted(run):
    return run['returncode'] == 0 and run['status'] == 'ok' and not run['heavy_external_load'] and not run['compiler_load_detected']


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--campaign', type=Path, required=True)
    parser.add_argument('--rounds', type=int, default=5)
    parser.add_argument('--scenario', action='append', choices=SCENARIOS)
    parser.add_argument('--attempts', type=int, default=12)
    args = parser.parse_args()
    root = args.campaign.resolve()
    builds = {name: json.loads((root / 'build' / f'{name}.json').read_text()) for name in ('before', 'after')}
    binaries = {name: root / 'bin' / name for name in builds}
    for name, path in binaries.items():
        if sha256(path) != builds[name]['sha256'] or not builds[name]['isolated_target']:
            raise SystemExit(f'{name} binary does not match its isolated build record')
    if sha256(HARNESS) != HARNESS_SHA256 or sha256(XRAY_CORE) != XRAY_CORE_SHA256:
        raise SystemExit('frozen harness or Xray-core changed')
    scenarios = args.scenario or SCENARIOS
    log = root / 'stream-ab.jsonl'
    # Resume: a (scenario, round) with an accepted pair is done; attempts continue numbering.
    previous = [json.loads(line) for line in log.open()] if log.exists() else []
    attempts_by_pair, accepted_pairs = {}, set()
    for run in previous:
        key = (run['scenario'], run['round'])
        attempts_by_pair[key] = max(attempts_by_pair.get(key, 0), run['attempt'])
    for key in attempts_by_pair:
        for attempt in range(1, attempts_by_pair[key] + 1):
            pair = [r for r in previous if (r['scenario'], r['round']) == key and r['attempt'] == attempt]
            if len(pair) == 2 and all(accepted(r) for r in pair):
                accepted_pairs.add(key)
    for round_number in range(1, args.rounds + 1):
        for index, scenario in enumerate(scenarios):
            if (scenario, round_number) in accepted_pairs:
                continue
            order = ['before', 'after'] if (round_number + index) % 2 else ['after', 'before']
            first = attempts_by_pair.get((scenario, round_number), 0) + 1
            for attempt in range(first, first + args.attempts):
                campaign.wait_for_quiet(window=5, needed=4)
                pair = {}
                for version in order:
                    out = root / 'stream' / f'{scenario}-r{round_number}-a{attempt}-{version}'
                    out.mkdir(parents=True, exist_ok=False)
                    run = run_once(binaries[version], scenario, out)
                    run.update(round=round_number, scenario=scenario, version=version, attempt=attempt,
                               order=order, commit=builds[version]['commit'], binary_sha256=builds[version]['sha256'])
                    pair[version] = run
                    with log.open('a') as stream:
                        stream.write(json.dumps(run) + '\n')
                    print(scenario, f'r{round_number}', f'a{attempt}', version, run['status'],
                          'rss', run['peak_rss_kib'], 'fp', run['peak_footprint_kib'], 'mbps', run['throughput_mbps'],
                          'cpu/GiB', run['cpu_millis_per_gib'], 'ext%', round(run['max_external_cpu_percent']),
                          'ACCEPTED' if accepted(run) else 'REJECTED', flush=True)
                if all(accepted(run) for run in pair.values()):
                    break
            else:
                raise SystemExit(f'{scenario} round {round_number}: no accepted pair in {args.attempts} attempts')
    print('ALL ROUNDS COMPLETE', flush=True)


if __name__ == '__main__':
    main()

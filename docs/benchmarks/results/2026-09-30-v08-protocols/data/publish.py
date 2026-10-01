#!/usr/bin/env python3
"""Publish verified numeric evidence without ephemeral fixture credentials."""
import collections
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tarfile

LABELS = {'candidate': 'xray-rust', 'xray': 'Xray-core', 'singbox': 'sing-box'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def save(path, data):
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', type=Path, required=True)
    parser.add_argument('--campaign', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    ROOT, CAMPAIGN, DEST = args.repo.resolve(), args.campaign.resolve(), args.destination.resolve()
    spec = importlib.util.spec_from_file_location('parity', ROOT / 'scripts/summarize-v07-protocol-parity.py')
    parity = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parity)
    full = CAMPAIGN / 'full'
    manifest = json.loads((full / 'manifest.json').read_text())
    assert len(manifest['cases']) == 70 and manifest['repeats'] == 5
    assert len(manifest['runs']) == 1050 and manifest['finished_unix']
    assert all(r['process_group_empty_after_run'] and not r['remaining_engine_processes']
               and not r['surviving_process_group'] for r in manifest['runs'])
    for path, sha in manifest['file_hashes'].items():
        assert digest(Path(path)) == sha, path
    for run in manifest['runs']:
        if run['returncode'] == 0:
            result = json.loads((full / run['output_relative'] / 'result.json').read_text())
            assert result['client_preface'] == (result['traffic'] not in ('tcp-latency', 'udp'))
    DEST.mkdir(parents=True, exist_ok=False)
    data = DEST / 'data'
    data.mkdir()
    strict = parity.summarize(full, 0)
    summary = parity.summarize(full, 3)
    save(data / 'summary-strict.json', strict)
    save(data / 'summary-mac-3pct.json', summary)
    for name in ('inputs.json', 'host.json'):
        shutil.copyfile(CAMPAIGN / name, data / name)
    shutil.copyfile(__file__, data / 'publish.py')
    raw_paths = {}
    with tarfile.open(DEST / 'measurements.tar.gz', 'w:gz') as archive:
        for group, source in [('full', full), ('smoke', CAMPAIGN / 'smoke'),
                              ('pre-preface-smoke', ROOT / 'target/v08-comparison-v2/smoke'),
                              ('initial-smoke', ROOT / 'target/v08-comparison/smoke')]:
            group_manifest = json.loads((source / 'manifest.json').read_text())
            files = [source / 'manifest.json', source / 'source.patch']
            for run in group_manifest['runs']:
                trial = source / run['output_relative']
                result = trial / 'result.json'
                if result.exists():
                    files.append(result)
                if run['returncode']:
                    files.extend(p for p in (trial / 'stdout.log', trial / 'stderr.log',
                                               source / (run['output_relative'] + '.log')) if p.exists())
            for path in files:
                arcname = group + '/' + str(path.relative_to(source))
                raw_paths[arcname] = digest(path)
                archive.add(path, arcname=arcname, recursive=False)
        for diagnostic in ('vmess-diagnostic', 'vmess-server-first'):
            source = ROOT / 'target/v08-comparison-v2' / diagnostic
            files = [*source.rglob('*.log'), *source.rglob('result.json')]
            for path in files:
                arcname = 'diagnostics/' + diagnostic + '/' + str(path.relative_to(source))
                raw_paths[arcname] = digest(path)
                archive.add(path, arcname=arcname, recursive=False)
    save(DEST / 'evidence-index.json', {
        'archive': 'measurements.tar.gz', 'archive_sha256': digest(DEST / 'measurements.tar.gz'),
        'file_sha256': raw_paths, 'retained_local_campaign': str(CAMPAIGN),
        'archive_scope': 'exact manifests and numeric raw results, failed smoke logs; generated credentials and binaries remain local'})

    axes = {case['id']: case for case in manifest['cases']}
    metrics = [
        ('throughput_mib_s', 'TCP bulk throughput (MiB/s)', 'bulk'),
        ('latency_us', 'Echo median RTT (microseconds)', 'echo'),
        ('latency_p95_us', 'Echo p95 RTT (microseconds)', 'echo'),
        ('latency_p99_us', 'Echo p99 RTT (microseconds)', 'echo'),
        ('rss_mib', 'Sampled peak client RSS (MiB)', 'all'),
        ('cpu_ms', 'Workload client CPU (ms)', 'all'),
        ('cpu_ms_per_mib', 'Workload client CPU per MiB (ms)', 'all'),
        ('client_startup_seconds', 'Client readiness plus verified warmup (seconds)', 'all'),
        ('client_startup_cpu_millis', 'Client startup CPU (ms)', 'all'),
        ('client_cpu_total_millis', 'Client CPU through final sample (ms)', 'all')]
    text = ['# All v0.8 comparison metrics', '',
            'Each cell is the median [minimum, maximum] of five fresh-process trials. '
            'Incomplete groups have no passing median. Full samples and paired ratio intervals are in '
            '[the JSON summary](data/summary-mac-3pct.json). CPU zeroes reflect coarse counters; '
            'echo traffic is not saturated throughput. Higher bulk throughput is better; '
            'other metrics are lower-is-better.', '']
    for metric, title, scope in metrics:
        text += ['## ' + title, '', '| Case | xray-rust | Xray-core | sing-box |', '| --- | ---: | ---: | ---: |']
        for row in summary['rows']:
            is_echo = axes[row['case']]['traffic'] in ('udp', 'tcp-latency')
            if scope == 'bulk' and is_echo or scope == 'echo' and not is_echo:
                continue
            cells = []
            for version in LABELS:
                m = row['versions'][version]['metrics'].get(metric)
                cells.append('incomplete' if m is None else f"{m['median']:.3f} [{m['min']:.3f}, {m['max']:.3f}]")
            text.append('| ' + row['case'] + ' | ' + ' | '.join(cells) + ' |')
        text.append('')
    (DEST / 'all-metrics.md').write_text('\n'.join(text))

    deficits = ['# Point differences outside the Mac comparison target', '',
        'RSS must be strictly lower. Throughput may be at most 3% lower; CPU, latency and startup '
        'at most 3% higher. Every failing point comparison is retained below, including correlated '
        'metrics. These are not independent failures or proven causal regressions. '
        'Paired bootstrap intervals contain five repeats and can be wide. See the strict summary '
        'for all zero-allowance differences.', '',
        '| Case | Reference | Metric | Rust | Reference value | Ratio [95% interval] |',
        '| --- | --- | --- | ---: | ---: | --- |']
    counts = collections.defaultdict(lambda: collections.Counter())
    for row in summary['rows']:
        for reference, comparison in row['comparisons'].items():
            for metric, m in comparison['metrics'].items():
                counts[metric]['total'] += 1
                if m['meets_point_target']:
                    counts[metric]['meets_mac_point'] += 1
                if m['meets_strict_point_target']:
                    counts[metric]['meets_strict_point'] += 1
                if not m['meets_point_target']:
                    interval = m['paired_bootstrap_95pct']
                    ratio = 'undefined' if m['ratio'] is None else f"{m['ratio']:.4f}"
                    ci = 'unavailable' if interval is None else f'{interval[0]:.4f}, {interval[1]:.4f}'
                    deficits.append(f"| {row['case']} | {LABELS[reference]} | {metric} | {m['candidate']:.4f} | {m['reference']:.4f} | {ratio} [{ci}] |")
    (DEST / 'point-deficits.md').write_text('\n'.join(deficits) + '\n')
    save(data / 'metric-counts.json', dict(counts))
    print(json.dumps({'destination': str(DEST), 'parity': summary['parity'],
                      'failures': summary['failures'], 'metric_counts': dict(counts)}, indent=2))


if __name__ == '__main__':
    main()

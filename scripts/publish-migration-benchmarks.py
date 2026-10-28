#!/usr/bin/env python3
"""Archive numeric evidence, verify all 200 x 2 x 5 trials, render migration charts.

collect --campaign DIR --accepted BLOCK [--accepted BLOCK ...] --report DIR
verify --report DIR
charts --report DIR    (matplotlib 3.10.8, numpy 2.3.5)
No configs, generated credentials, application logs or unrelated process names
are published. All attempts are indexed, including failed blocks and smoke.
"""
import argparse
import copy
import csv
import gzip
import hashlib
import importlib.util
import io
import itertools
import json
import math
from pathlib import Path
import statistics
import tarfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('migration', ROOT / 'scripts/run-migration-benchmarks.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def public_manifest(value):
    value = copy.deepcopy(value)
    for run in value['runs']:
        for item in [run['ambient_cpu'], *run['ambient_cpu']['samples']]:
            for compiler in item['compiler_load_detected']:
                compiler.pop('pid', None)
        for sample in run['ambient_cpu']['samples']:
            top = sample.pop('top_external')
            sample['peak_external_process_cpu_percent'] = max((p['cpu_percent'] for p in top), default=0)
    return value


def validate_trial(case, run, result, inputs):
    require(m.clean(run) and run['ambient_cpu']['samples'], 'failed/contaminated/unobserved trial: ' + run['output_relative'])
    require(result['status'] == 'pass', 'payload validation failed')
    for field in ('path', 'traffic', 'connections', 'iterations', 'payload_size'):
        require(result[field] == case[field], 'workload axis changed: ' + field)
    require(result['engine_sha256'] == inputs[run['version']]['sha256'], 'wrong engine hash')
    require(result['idle_connections'] == 0 and not result['prepare_client'] and not result['client_env'], 'non-stock client')
    require(result['warmup'] == (case['path'] == 'socks'), 'warmup mismatch')
    require(result['client_preface'] == (case['path'] == 'socks' and case['traffic'] in m.BULK), 'preface mismatch')
    expected_flows = 1 if case['path'] == 'tun' and case['traffic'] == 'tcp-latency' else case['connections']
    require(result['concurrent_flows'] == expected_flows, 'concurrency changed')
    count = case['connections'] * case['iterations'] * case['payload_size']
    require(result['bytes_sent'] == (0 if case['traffic'] == 'download' else count), 'sent byte count mismatch')
    require(result['bytes_received'] == (0 if case['traffic'] == 'upload' else count), 'received byte count mismatch')
    require(result['transfer_seconds'] > 0 and result['peak_rss_kib'] > 0 and len(result['samples']) >= 2, 'missing measurements')
    size = (result['bytes_sent'] + result['bytes_received']) / 2**20
    require(math.isclose(result['throughput_mib_s'], size / result['transfer_seconds'], rel_tol=1e-9), 'throughput accounting mismatch')
    values = {'throughput_mib_s': result['throughput_mib_s'], 'rss_mib': result['peak_rss_kib'] / 1024,
        'cpu_ms_per_gib': result['cpu_millis'] * 1024 / size, 'cpu_millis': result['cpu_millis'],
        'transfer_seconds': result['transfer_seconds'], 'startup_seconds': result['client_startup_seconds']}
    for key, value in (result['latency_us'] or {}).items():
        values['latency_' + key + '_us'] = value
    for key, value in (result['ready_latency_us'] or {}).items():
        values['ready_' + key + '_us'] = value
    require(all(math.isfinite(v) and v >= 0 for v in values.values()), 'invalid numeric metric')
    return values


def stats(values):
    return {'median': statistics.median(values), 'min': min(values), 'max': max(values), 'samples': values}


def paired(before, after):
    if any(x == 0 for x in before):
        return None
    values = [a / b for b, a in zip(before, after)]
    # Exact empirical percentile bootstrap over 5 paired observations (5**5).
    boot = sorted(statistics.median(sample) for sample in itertools.product(values, repeat=len(values)))
    result = stats(values)
    result['bootstrap_95_percentile'] = [boot[int(.025 * (len(boot) - 1))], boot[int(.975 * (len(boot) - 1))]]
    return result


def summarize(entries, accepted):
    expected_cases = {case['id']: case for case in m.cases()}
    observed, groups, case_blocks, hosts, inputs, quality = set(), {}, {}, [], None, []
    for block in accepted:
        manifest = json.loads(entries[block + '/manifest.json'])
        require(manifest['status'] == 'pass' and not manifest['smoke'] and manifest['repeats'] == 5, 'incomplete/non-publication block')
        if inputs is None:
            inputs = manifest['inputs']
            pins = {'before': '3ca380e7e32d82cfff55f38698117dba8bef077b',
                    'after': '53756feea4868e77114f71688cb27b34b8e57ffb',
                    'harness': '53756feea4868e77114f71688cb27b34b8e57ffb', 'reference': m.REFERENCE}
            require(all(inputs[k]['commit'] == pin for k, pin in pins.items()), 'wrong comparison source pin')
            require(inputs['before']['rustc'] == inputs['after']['rustc'] == inputs['harness']['rustc'], 'Rust compiler changed')
            for name in ('before', 'after', 'harness'):
                require('--release' in inputs[name]['command'] and '--locked' in inputs[name]['command']
                        and inputs[name]['incremental'] is False and inputs[name]['rustflags'] is None, 'nonstandard build')
        require(manifest['inputs'] == inputs, 'binary/build identities changed across blocks')
        hosts.append({k: manifest['host'][k] for k in ('cpu', 'model', 'memory_bytes', 'logical_cpus', 'os')})
        require(hosts[-1] == hosts[0], 'measurement host changed')
        cases = {case['id']: case for case in manifest['cases']}
        require(len(cases) == len(manifest['cases']), 'duplicate case in block')
        require(all(case == expected_cases.get(name) for name, case in cases.items()), 'unreviewed workload')
        for case in cases:
            require(case not in case_blocks, 'duplicate accepted case')
            case_blocks[case] = block
        expected = {(case, version, repeat) for case in cases for version in m.VERSIONS for repeat in range(1, 6)}
        keys = [(r['case'], r['version'], r['repeat']) for r in manifest['runs']]
        require(len(keys) == len(expected) and set(keys) == expected, 'missing/duplicate trial')
        for run in manifest['runs']:
            key = (run['case'], run['version'], run['repeat'])
            require(key not in observed, 'duplicate global trial')
            observed.add(key)
            index = list(expected_cases).index(run['case'])
            require(run['client_order'] == m.order(index, run['repeat']), 'pair order changed')
            result = json.loads(entries[block + '/' + run['output_relative'] + '/result.json'])
            values = validate_trial(cases[run['case']], run, result, inputs)
            groups.setdefault((run['case'], run['version']), {})[run['repeat']] = values
            quality.extend(run['ambient_cpu']['samples'])
    require(set(case_blocks) == set(expected_cases), 'incomplete 200-case matrix')
    rows = []
    for name, case in expected_cases.items():
        versions = {}
        for version in m.VERSIONS:
            trials = [groups[(name, version)][r] for r in range(1, 6)]
            require(all(set(t) == set(trials[0]) for t in trials), 'metric missing in a repeat')
            versions[version] = {metric: stats([trial[metric] for trial in trials]) for metric in trials[0]}
        ratios = {key: paired(versions['before'][key]['samples'], versions['after'][key]['samples']) for key in versions['before']}
        rows.append({'case': case, 'block': case_blocks[name], 'versions': versions, 'after_over_before': ratios})
    return {'schema_version': 1, 'cases': len(rows), 'trials': len(observed), 'repeats': 5, 'host': hosts[0], 'inputs': inputs,
        'quality': {'external_cpu_percent': stats([s['external_cpu_percent'] for s in quality]),
                    'peak_external_process_cpu_percent': max(s['peak_external_process_cpu_percent'] for s in quality)},
        'rows': rows}


def archive_entries(report):
    raw = (report / 'measurements.tar.gz').read_bytes()
    index = json.loads((report / 'evidence-index.json').read_text())
    require(digest(raw) == index['archive_sha256'], 'archive checksum mismatch')
    entries = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:gz') as archive:
        for member in archive:
            require(member.isfile() and member.name not in entries, 'unexpected/duplicate archive member')
            entries[member.name] = archive.extractfile(member).read()
    require({name: digest(data) for name, data in entries.items()} == index['members_sha256'], 'archive member mismatch')
    return entries, index


def collect(campaign, accepted, report):
    require(not report.exists(), 'report directory already exists')
    require(accepted and len(accepted) == len(set(accepted)), 'missing/duplicate accepted blocks')
    entries, attempts = {}, []
    for path in sorted(campaign.glob('*/manifest.json')):
        block = path.parent.name
        manifest = json.loads(path.read_text())
        public = public_manifest(manifest)
        entries[block + '/manifest.json'] = encoded(public)
        attempts.append({'block': block, 'status': manifest['status'], 'smoke': manifest['smoke'],
                         'trials': len(manifest['runs']), 'accepted': block in accepted,
                         'original_private_manifest_sha256': digest(path.read_bytes())})
        for run in manifest['runs']:
            result = path.parent / run['output_relative'] / 'result.json'
            if result.exists():
                entries[block + '/' + run['output_relative'] + '/result.json'] = result.read_bytes()
    summary = summarize(entries, accepted)
    report.mkdir(parents=True)
    with (report / 'measurements.tar.gz').open('wb') as stream:
        with gzip.GzipFile(fileobj=stream, mode='wb', mtime=0, filename='') as zipped:
            with tarfile.open(fileobj=zipped, mode='w') as archive:
                for name, data in sorted(entries.items()):
                    info = tarfile.TarInfo(name); info.size = len(data); info.mode = 0o644
                    archive.addfile(info, io.BytesIO(data))
    index = {'accepted_blocks': accepted, 'attempts': attempts,
        'archive_sha256': digest((report / 'measurements.tar.gz').read_bytes()),
        'members_sha256': {name: digest(data) for name, data in entries.items()},
        'privacy': 'Numeric results and manifests only; unrelated process names/PIDs removed from ambient samples; configs, private fixture keys and logs remain local.'}
    (report / 'evidence-index.json').write_bytes(encoded(index))
    (report / 'summary.json').write_bytes(encoded(summary))
    write_csv(report, summary)
    return summary


def write_csv(report, summary):
    with (report / 'results.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(['case', 'metric', 'before_median', 'before_min', 'before_max', 'after_median', 'after_min', 'after_max', 'paired_ratio_median', 'paired_ratio_min', 'paired_ratio_max', 'paired_bootstrap_low', 'paired_bootstrap_high'])
        for row in summary['rows']:
            for metric, ratio in row['after_over_before'].items():
                values = [row['case']['id'], metric]
                for version in m.VERSIONS:
                    values.extend(row['versions'][version][metric][key] for key in ('median', 'min', 'max'))
                values.extend([ratio[k] for k in ('median', 'min', 'max')] + ratio['bootstrap_95_percentile'] if ratio else [''] * 5)
                writer.writerow(values)


def charts(report, summary):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    plt.rcParams.update({'font.family': 'DejaVu Sans', 'svg.fonttype': 'none', 'font.size': 9})
    rows = {row['case']['id']: row for row in summary['rows']}
    for path in ('socks', 'tun'):
        names = [p for p in m.PROFILES if f'{p}-{path}-download-8' in rows]
        fig, axes = plt.subplots(1, 3, figsize=(14, max(5, len(names) * .38)), layout='constrained')
        for ax, (metric, title) in zip(axes, [('throughput_mib_s', 'Throughput · MiB/s ↑'), ('cpu_ms_per_gib', 'Client CPU · ms/GiB ↓'), ('rss_mib', 'Sampled peak RSS · MiB ↓')]):
            for i, (version, color) in enumerate([('before', '#64748b'), ('after', '#007f82')]):
                values = [rows[f'{p}-{path}-download-8']['versions'][version][metric] for p in names]
                med = np.array([v['median'] for v in values]); low = np.array([v['min'] for v in values]); high = np.array([v['max'] for v in values])
                ax.barh(np.arange(len(names)) + (i - .5) * .34, med, .31, label=version, color=color,
                        xerr=[med-low, high-med], capsize=2, error_kw={'elinewidth': .7})
            ax.invert_yaxis(); ax.set_yticks(range(len(names)), names if ax == axes[0] else [])
            ax.set_title(title, loc='left'); ax.grid(axis='x', alpha=.18); ax.set_axisbelow(True)
            ax.spines[['top', 'right']].set_visible(False); ax.set_xlim(left=0)
        axes[0].legend(frameon=False, ncol=2, loc='lower right')
        fig.suptitle(f'Xray migration · {path.upper()} · 8-flow download\nApple M6 · five pairs · bars: medians; whiskers: min/max', fontsize=13)
        for suffix in ('svg', 'png'):
            fig.savefig(report / f'{path}-download-8.{suffix}', dpi=150)
        plt.close(fig)
    # All bulk cases are visible; a fixed slice cannot hide a regression elsewhere.
    names = [(p, path) for p in m.PROFILES for path in ('socks', 'tun') if f'{p}-{path}-upload-1' in rows]
    cols = [(kind, n) for n in (1, 8) for kind in m.BULK]
    fig, axes = plt.subplots(1, 3, figsize=(14, len(names) * .35 + 1.8), layout='constrained')
    for ax, (metric, title, direction) in zip(axes, [('throughput_mib_s', 'Throughput change % · higher is better', 1), ('cpu_ms_per_gib', 'CPU cost change % · lower is better', -1), ('rss_mib', 'Peak RSS change % · lower is better', -1)]):
        data = np.array([[100 * (rows[f'{p}-{path}-{kind}-{n}']['after_over_before'][metric]['median'] - 1)
                          if rows[f'{p}-{path}-{kind}-{n}']['after_over_before'][metric] else np.nan for kind, n in cols] for p, path in names])
        ax.imshow(direction * data, cmap='RdYlGn', vmin=-20, vmax=20, aspect='auto')
        for (i, j), value in np.ndenumerate(data):
            ax.text(j, i, f'{value:+.0f}' if np.isfinite(value) else 'n/a', ha='center', va='center', fontsize=8)
        ax.set_xticks(range(len(cols)), [f'{k[:2]} {n}' for k, n in cols]); ax.xaxis.tick_top()
        ax.set_yticks(range(len(names)), [f'{p} · {path}' for p, path in names] if ax == axes[0] else [])
        ax.set_title(title, pad=25, fontsize=10)
    fig.suptitle('All bulk cases · median of five paired after/before ratios\nColor saturates at ±20%; labels retain exact rounded change. Green = favorable.', fontsize=13)
    for suffix in ('svg', 'png'):
        fig.savefig(report / f'bulk-changes.{suffix}', dpi=150)
    plt.close(fig)


    names = [(p, path) for p in m.PROFILES for path in ('socks', 'tun') if f'{p}-{path}-tcp-latency-1' in rows]
    cols = [(kind, n) for kind in ('tcp-latency', 'udp') for n in (1, 8)]
    fig, axes = plt.subplots(1, 3, figsize=(13, len(names) * .4 + 1.8), layout='constrained')
    for ax, quantile in zip(axes, ('median', 'p95', 'p99')):
        metric = 'latency_' + quantile + '_us'
        data = np.array([[100 * (rows[f'{p}-{path}-{kind}-{n}']['after_over_before'][metric]['median'] - 1)
                          for kind, n in cols] for p, path in names])
        ax.imshow(-data, cmap='RdYlGn', vmin=-20, vmax=20, aspect='auto')
        for (i, j), value in np.ndenumerate(data):
            ax.text(j, i, f'{value:+.0f}', ha='center', va='center', fontsize=9)
        ax.set_xticks(range(len(cols)), [f'{"TCP" if k == "tcp-latency" else "UDP"} {n}' for k, n in cols]); ax.xaxis.tick_top()
        ax.set_yticks(range(len(names)), [f'{p} · {path}' for p, path in names] if ax == axes[0] else [])
        ax.set_title(quantile + ' latency change % · lower is better', pad=25, fontsize=10)
    fig.suptitle('All echo cases · median of five paired after/before ratios\nGreen = lower latency; color saturates at ±20%. TUN TCP echo connections are sequential.', fontsize=12)
    for suffix in ('svg', 'png'):
        fig.savefig(report / f'latency-changes.{suffix}', dpi=150)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('collect', 'verify', 'charts'))
    parser.add_argument('--campaign', type=Path)
    parser.add_argument('--accepted', action='append')
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'collect':
        if not args.campaign or not args.accepted:
            parser.error('collect requires --campaign and --accepted')
        summary = collect(args.campaign, args.accepted, args.report)
    else:
        entries, index = archive_entries(args.report)
        summary = summarize(entries, index['accepted_blocks'])
        require(encoded(summary) == (args.report / 'summary.json').read_bytes(), 'summary differs from evidence')
    if args.action == 'charts':
        charts(args.report, summary)
    print(f"Verified {summary['cases']} cases, {summary['trials']} trials, five pairs on one host")


if __name__ == '__main__':
    main()

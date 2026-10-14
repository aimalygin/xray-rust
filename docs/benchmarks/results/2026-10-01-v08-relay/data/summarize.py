#!/usr/bin/env python3
"""Reproduce numeric summaries from manifests/results (no fixture secrets needed)."""
import collections
import json
from pathlib import Path
import statistics
import sys


def stats(values):
    return dict(median=statistics.median(values), min=min(values), max=max(values), samples=values)


def summarize(root):
    root = Path(root)
    output = {'groups': {}}
    for group, expected in [('isolated-controls', 54), ('batched-clean-controls', 108), ('aes-upload-confirmation', 21), ('aes-download-confirmation', 10), ('final-clean-controls', 144), ('stack-controls', 144), ('ss-aes-duplex-confirmation', 20)]:
        folder = root / group
        manifest = json.loads((folder / 'manifest.json').read_text())
        assert manifest['status'] == 'pass' and len(manifest['runs']) == expected
        rows = collections.defaultdict(lambda: collections.defaultdict(list))
        for run in manifest['runs']:
            assert run['returncode'] == 0 and run['process_group_empty_after_run']
            assert not run['remaining_engine_processes'] and not run['surviving_process_group']
            assert not run['ambient_cpu']['compiler_load_detected'] and not run['ambient_cpu']['observer_errors']
            result = json.loads((folder / run['output_relative'] / 'result.json').read_text())
            assert result['engine_sha256'] == manifest['file_hashes'][result['engine_binary']]
            metrics = {'cpu_ms': result['cpu_millis'], 'throughput_mib_s': result['throughput_mib_s'],
                       'rss_mib': result['peak_rss_kib'] / 1024,
                       'startup_cpu_ms': result['client_startup_cpu_millis']}
            for metric, value in metrics.items():
                rows[run['case'], run['version']][metric].append(value)
        output['groups'][group] = []
        for (case, version), metrics in sorted(rows.items()):
            assert all(len(v) == manifest['repeats'] for v in metrics.values())
            output['groups'][group].append(dict(case=case, version=version, metrics={k: stats(v) for k, v in metrics.items()}))
    for group, expected, key in [('held-memory', 36, 'held_memory'), ('final-held-memory', 24, 'intermediate_held_memory'), ('stack-held-memory', 24, 'final_held_memory')]:
        folder = root / group
        manifest = json.loads((folder / 'manifest.json').read_text())
        assert manifest['status'] == 'pass' and len(manifest['runs']) == expected
        assert not manifest['ambient_cpu']['observer_errors'] and not manifest['ambient_cpu']['compiler_load_detected']
        rows = collections.defaultdict(list)
        for run in manifest['runs']:
            result = json.loads((folder / run['output_relative'] / 'result.json').read_text())
            assert result['status'] == 'pass' and not result['remaining_engine_processes']
            assert result['engine_sha256'] == manifest['file_hashes'][result['binary']]
            assert result['checked_bytes_each_direction'] == 512 * 8192
            assert [p['connections'] for p in result['points']] == [0, 32, 128, 512]
            for point in result['points']:
                assert len(point['samples']) == 5
                assert point['rss_kib_median'] == statistics.median(s['rss_kib'] for s in point['samples'])
                rows[run['profile'], run['version'], point['connections']].append(point['rss_kib_median'] / 1024)
        output[key] = []
        for (profile, version, connections), values in sorted(rows.items()):
            assert len(values) == 3
            output[key].append(dict(profile=profile, version=version, connections=connections, rss_mib=stats(values)))
    return output


if __name__ == '__main__':
    Path(sys.argv[2]).write_text(json.dumps(summarize(sys.argv[1]), indent=2, sort_keys=True) + '\n')

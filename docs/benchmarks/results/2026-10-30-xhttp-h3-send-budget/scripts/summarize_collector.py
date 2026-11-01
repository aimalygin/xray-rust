#!/usr/bin/env python3
"""Summarize accepted collector blocks with the publisher's own trial checks and pairing.

summarize_collector.py DIR [--json OUT]
"""
import importlib.util
import json
from pathlib import Path
import statistics
import sys

# The checkout these scripts live in: docs/benchmarks/results/<report>/scripts/.
WORKTREE = Path(__file__).resolve().parents[5]
spec = importlib.util.spec_from_file_location('publish', WORKTREE / 'scripts/publish-migration-benchmarks.py')
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)
m = publish.m

root = Path(sys.argv[1]).resolve()
accepted = json.loads((root / 'accepted-blocks.json').read_text())
order = [case['id'] for case in m.cases()]
metrics = [('throughput_mib_s', 'Throughput, MiB/s'), ('cpu_ms_per_gib', 'CPU, ms/GiB'),
           ('footprint_mib', 'Peak footprint, MiB'), ('rss_mib', 'Sampled peak RSS, MiB')]
rows, inputs = [], None
for block in accepted:
    manifest = json.loads((root / block / 'manifest.json').read_text())
    publish.require(manifest['status'] == 'pass' and not manifest['smoke'] and manifest['repeats'] == 5, 'not a publication block')
    inputs = inputs or manifest['inputs']
    publish.require(manifest['inputs'] == inputs, 'inputs changed across blocks')
    cases = {case['id']: case for case in manifest['cases']}
    groups = {}
    for run in manifest['runs']:
        publish.require(run['client_order'] == m.order(order.index(run['case']), run['repeat']), 'pair order changed')
        result = json.loads((root / block / run['output_relative'] / 'result.json').read_text())
        groups.setdefault((run['case'], run['version']), {})[run['repeat']] = publish.validate_trial(cases[run['case']], run, result, inputs)
    for case in cases:
        row = {'case': case, 'block': block, 'collector_commit': manifest['collector_commit']}
        for metric, _ in metrics:
            before = [groups[(case, 'before')][r][metric] for r in range(1, 6)]
            after = [groups[(case, 'after')][r][metric] for r in range(1, 6)]
            row[metric] = {'before': before, 'after': after, 'paired': publish.paired(before, after)}
        rows.append(row)
rows.sort(key=lambda row: order.index(row['case']))
print(f'{len(rows)} cases, {sum(1 for _ in rows) * 10 * 1} pairs x 2 versions; inputs before={inputs["before"]["commit"][:8]} after={inputs["after"]["commit"][:8]}')
print('| Case | Metric | Before | After | Paired change | Bootstrap 95% |')
print('| --- | --- | ---: | ---: | ---: | --- |')
for row in rows:
    for metric, label in metrics:
        data = row[metric]
        pair = data['paired']
        if pair is None:
            continue
        low, high = pair['bootstrap_95_percentile']
        print(f"| `{row['case']}` | {label} | {statistics.median(data['before']):,.2f} | {statistics.median(data['after']):,.2f} | "
              f"{(pair['median'] - 1) * 100:+.2f}% | {(low - 1) * 100:+.2f}% to {(high - 1) * 100:+.2f}% |")
if len(sys.argv) > 3 and sys.argv[2] == '--json':
    Path(sys.argv[3]).write_text(json.dumps({'inputs': inputs, 'rows': rows}, indent=2) + '\n')

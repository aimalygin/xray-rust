#!/usr/bin/env python3
"""Summarize stream-ab.jsonl: accepted pairs only, medians and paired after/before ratios."""
import json
import statistics
import sys
from collections import defaultdict

runs = [json.loads(line) for line in open(sys.argv[1])]
accepted = lambda r: r['returncode'] == 0 and r['status'] == 'ok' and not r['heavy_external_load'] and not r['compiler_load_detected']
pairs = defaultdict(dict)
for run in runs:
    pairs[(run['scenario'], run['round'], run['attempt'])][run['version']] = run
good = {key: pair for key, pair in pairs.items() if len(pair) == 2 and all(accepted(r) for r in pair.values())}
metrics = [('peak_rss_kib', 'Peak RSS, MiB', 1 / 1024), ('peak_footprint_kib', 'Peak footprint, MiB', 1 / 1024),
           ('throughput_mbps', 'Throughput, Mbps', 1), ('cpu_millis_per_gib', 'CPU, ms/GiB', 1)]
scenarios = []
for scenario, _, _ in sorted(good, key=lambda k: (k[0], k[1])):
    if scenario not in scenarios:
        scenarios.append(scenario)
rejected = len(pairs) - len(good)
print(f'accepted pairs: {len(good)}, rejected or incomplete attempts: {rejected}')
print('| Case | Metric | Before | After | Median paired change | Range | Pairs |')
print('| --- | --- | ---: | ---: | ---: | ---: | ---: |')
for scenario in scenarios:
    chosen = [pair for (s, _, _), pair in sorted(good.items()) if s == scenario]
    for key, label, scale in metrics:
        before = [p['before'][key] for p in chosen if p['before'][key] is not None]
        after = [p['after'][key] for p in chosen if p['after'][key] is not None]
        ratios = [p['after'][key] / p['before'][key] - 1 for p in chosen
                  if p['before'][key] and p['after'][key] is not None]
        if not ratios:
            continue
        fmt = (lambda v: f'{v * scale:,.1f}') if scale != 1 else (lambda v: f'{v:,.0f}')
        print(f'| stream-xhttp-h3-{scenario} | {label} | {fmt(statistics.median(before))} | {fmt(statistics.median(after))} | '
              f'{statistics.median(ratios) * 100:+.1f}% | {min(ratios) * 100:+.1f}% to {max(ratios) * 100:+.1f}% | {len(ratios)} |')

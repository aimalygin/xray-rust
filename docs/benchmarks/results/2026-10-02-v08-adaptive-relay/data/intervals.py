#!/usr/bin/env python3
"""Paired bootstrap of ratios of repeated-workload medians; standard library only."""
import hashlib
import json
import random
import statistics
from pathlib import Path


def calculate(summary):
    result = {}
    for campaign, data in summary.items():
        if not campaign.startswith('chacha-') or data['kind'] == 'held':
            continue
        comparisons = {}
        for case, versions in data['cases'].items():
            for reference in sorted(set(versions) - {'candidate'}):
                metrics = {}
                for metric, values in versions['candidate'].items():
                    if metric not in {'cpu_millis', 'throughput_mib_s', 'peak_rss_kib',
                                      'latency_median', 'latency_p95', 'latency_p99'}:
                        continue
                    left = values['samples']
                    right = versions[reference][metric]['samples']
                    assert len(left) == len(right)
                    key = f'{campaign}/{case}/{reference}/{metric}'
                    rng = random.Random(int(hashlib.sha256(key.encode()).hexdigest(), 16))
                    ratios = []
                    for _ in range(10000):
                        indexes = [rng.randrange(len(left)) for _ in left]
                        ratios.append(statistics.median(left[i] for i in indexes) /
                                      statistics.median(right[i] for i in indexes))
                    ratios.sort()
                    metrics[metric] = {
                        'ratio_of_medians': statistics.median(left) / statistics.median(right),
                        'paired_bootstrap_95_percentile': [ratios[249], ratios[9749]],
                        'repeats': len(left),
                    }
                comparisons[f'{case}/candidate-vs-{reference}'] = metrics
        result[campaign] = comparisons
    return result


if __name__ == '__main__':
    root = Path(__file__).resolve().parent
    (root / 'intervals.json').write_text(json.dumps({
        'method': '10,000 paired resamples of repeat indexes; ratio of medians; 2.5/97.5 percentiles',
        'scope': 'Within-session sampling uncertainty; not a bound on host/session/WAN variation',
        'comparisons': calculate(json.loads((root / 'summary.json').read_text())),
    }, indent=2, sort_keys=True) + '\n')

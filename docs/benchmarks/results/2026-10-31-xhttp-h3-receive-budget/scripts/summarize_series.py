"""summarize_series.py data/series.jsonl: per campaign and build, each
32-download run's peak and median VmRSS (MiB) from run-mem.sh's 100 ms series."""
import collections, json, sys

runs = collections.defaultdict(list)
for line in open(sys.argv[1]):
    row = json.loads(line)
    rss = sorted(sample[1] / 1024 for sample in row['samples'])
    runs[(row['campaign'], row['variant'])].append((row['round'], round(rss[-1], 1), round(rss[len(rss) // 2], 1)))
for (campaign, variant), values in sorted(runs.items()):
    print(campaign, variant, ' '.join(f'r{r}: peak {p}, median {m}' for r, p, m in sorted(values)))

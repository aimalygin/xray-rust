"""Markdown rows for an ab2.sh campaign: median peak RSS before -> after with
the median paired change, and the median (min to max) paired change of
throughput and CPU per GiB. Pairs where either run failed are dropped."""
import collections, json, statistics as st, sys

rows = [json.loads(line) for path in sys.argv[1:] for line in open(path)]
runs = collections.defaultdict(dict)
for row in rows:
    x = row['result']
    runs[(row['profile'], row.get('iterations', 4096), x['traffic'], x['flows'], row['round'])][row['variant']] = x


def pct(a, b):
    return (b - a) / a * 100


order = {'download': 0, 'full-duplex': 1, 'upload': 2}
cases = sorted({k[:4] for k in runs}, key=lambda k: (k[0], k[1], -k[3], order.get(k[2], 9)))
for case in cases:
    pairs = [runs[case + (r,)] for r in sorted(k[4] for k in runs if k[:4] == case)]
    pairs = [p for p in pairs if 'before' in p and 'after' in p and p['before']['status'] == p['after']['status'] == 'ok']
    hwm = [p for p in pairs if p['before']['vm_hwm_kib'] and p['after']['vm_hwm_kib']]
    rss_b = st.median(p['before']['vm_hwm_kib'] for p in hwm) / 1024
    rss_a = st.median(p['after']['vm_hwm_kib'] for p in hwm) / 1024
    rss_c = st.median(pct(p['before']['vm_hwm_kib'], p['after']['vm_hwm_kib']) for p in hwm)

    def change(field):
        c = sorted(pct(p['before'][field], p['after'][field]) for p in pairs if p['before'][field] and p['after'][field])
        return f"{st.median(c):+.1f}% ({c[0]:+.1f} to {c[-1]:+.1f})"

    gbps = st.median(p['after']['throughput_mbps'] for p in pairs) / 1000
    print(f"| {case[0]} {case[1]} {case[2]}-{case[3]} | {len(pairs)} | {rss_b:.1f} → {rss_a:.1f} ({rss_c:+.1f}%) | "
          f"{change('throughput_mbps')} | {change('cpu_ms_per_gib')} | {gbps:.1f} |")

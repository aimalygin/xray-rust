"""Medians and median paired changes of an ab.sh campaign."""
import json, sys, statistics as st, collections
rows = [json.loads(l) for f in sys.argv[1:] for l in open(f)]
runs = collections.defaultdict(dict)
for r in rows:
    x = r['result']
    runs[(r['profile'], x['traffic'], x['flows'], r['round'])][r['variant']] = x
def pct(a, b):
    return (b - a) / a * 100 if a else float('nan')
keys = sorted({k[:3] for k in runs}, key=lambda k: (k[0], -k[2], k[1]))
metrics = [('vm_hwm_kib', 'peak RSS (VmHWM) MiB', 1024), ('peak_rss_anon_kib', 'peak RssAnon MiB', 1024),
           ('throughput_mbps', 'Mbps', 1), ('cpu_ms_per_gib', 'CPU ms/GiB', 1)]
for key in keys:
    pairs = [runs[key + (rnd,)] for rnd in sorted(r[3] for r in runs if r[:3] == key)]
    pairs = [p for p in pairs if 'before' in p and 'after' in p and p['before']['status'] == p['after']['status'] == 'ok']
    print(f"== {key[0]} {key[1]}-{key[2]}: {len(pairs)} ok pairs")
    for field, label, div in metrics:
        b = [p['before'][field] for p in pairs if p['before'].get(field) is not None and p['after'].get(field) is not None]
        a = [p['after'][field] for p in pairs if p['before'].get(field) is not None and p['after'].get(field) is not None]
        if not b:
            continue
        changes = sorted(pct(x, y) for x, y in zip(b, a))
        print(f"   {label:22s} {st.median(b)/div:9.1f} -> {st.median(a)/div:9.1f}  median paired {st.median(changes):+6.1f}%  pairs {[round(c, 1) for c in changes]}")

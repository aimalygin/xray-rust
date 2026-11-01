"""Markdown rows for an rb3.sh or rbn.sh campaign: summarize_rbn.py VARIANTS FILE.... For each case (profile, transfer
length, added round trip, scenario) and each variant against `before`, paired
by round: median peak RSS (VmHWM) before -> variant with the median paired
change, and the median (min to max) paired change of throughput and of CPU
per GiB, with both builds' median throughput. Pairs where either run failed
are dropped and counted."""
import collections, json, statistics as st, sys

VARIANTS = sys.argv[1].split(',')
rows = [json.loads(line) for path in sys.argv[2:] for line in open(path)]
runs = collections.defaultdict(dict)
for row in rows:
    x = row['result']
    key = (row['profile'], row.get('iterations', 4096), row.get('delay_ms', 0), x['traffic'], x['flows'])
    runs[key + (row['round'],)][row['variant']] = x


def pct(a, b):
    return (b - a) / a * 100


def spread(values):
    values = sorted(values)
    return f"{st.median(values):+.1f}% ({values[0]:+.1f} to {values[-1]:+.1f})" if values else "n/a"


order = {'download': 0, 'full-duplex': 1, 'upload': 2}
cases = sorted({k[:5] for k in runs}, key=lambda k: (k[0], k[1], k[2], -k[4], order.get(k[3], 9)))
print("| Case | Build | Pairs | Peak RSS, MiB | Mbit/s | Throughput | CPU per GiB |")
print("| --- | --- | ---: | ---: | ---: | ---: | ---: |")
for case in cases:
    rounds = sorted(k[5] for k in runs if k[:5] == case)
    label = f"{case[0]} {case[1]} +{case[2]}ms {case[3]}-{case[4]}"
    for variant in VARIANTS:
        pairs = [(runs[case + (r,)].get('before'), runs[case + (r,)].get(variant)) for r in rounds]
        failed = sum(1 for b, a in pairs if not (b and a and b['status'] == a['status'] == 'ok'))
        pairs = [(b, a) for b, a in pairs if b and a and b['status'] == a['status'] == 'ok']
        if not pairs:
            print(f"| {label} | {variant} | 0 ({failed} failed) | | | | |")
            continue
        hwm = [(b, a) for b, a in pairs if b['vm_hwm_kib'] and a['vm_hwm_kib']]
        rss_b = st.median(b['vm_hwm_kib'] for b, _ in hwm) / 1024
        rss_a = st.median(a['vm_hwm_kib'] for _, a in hwm) / 1024
        rss_c = st.median(pct(b['vm_hwm_kib'], a['vm_hwm_kib']) for b, a in hwm)
        mbps_b = st.median(b['throughput_mbps'] for b, _ in pairs)
        mbps_a = st.median(a['throughput_mbps'] for _, a in pairs)
        thr = spread(pct(b['throughput_mbps'], a['throughput_mbps']) for b, a in pairs)
        cpu = spread(pct(b['cpu_ms_per_gib'], a['cpu_ms_per_gib']) for b, a in pairs
                     if b['cpu_ms_per_gib'] and a['cpu_ms_per_gib'])
        note = f" ({failed} failed)" if failed else ""
        print(f"| {label} | {variant} | {len(pairs)}{note} | {rss_b:.1f} → {rss_a:.1f} ({rss_c:+.1f}%) | "
              f"{mbps_b:,.0f} → {mbps_a:,.0f} | {thr} | {cpu} |")

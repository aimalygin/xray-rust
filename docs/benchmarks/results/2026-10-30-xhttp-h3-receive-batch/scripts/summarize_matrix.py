import json, sys, statistics as st, collections
rows=[json.loads(l) for f in sys.argv[1:] for l in open(f)]
g=collections.defaultdict(list)
for r in rows:
    res=r['result']; g[(res['traffic'],res['flows'],r['variant'])].append(res)
variants=sorted({k[2] for k in g}, key=lambda v: (v.startswith('nogro'), -int(''.join(c for c in v if c.isdigit()) or 0) if v!='nogro' else 0))
med=lambda xs: st.median(xs) if xs else None
for sc in sorted({(k[0],k[1]) for k in g}, key=lambda s:(-s[1], s[0])):
    print(f"== {sc[0]}-{sc[1]}  (medians; n runs)")
    print(f"{'variant':10s} {'n':>2s} {'RSS MiB':>8s} {'Mbps':>7s} {'CPUms/GiB':>9s} {'recvbuf res MiB':>15s} {'recvbuf virt MiB':>16s}")
    for v in variants:
        xs=[x for x in g.get((sc[0],sc[1],v),[]) if x['status']=='ok']
        if not xs: continue
        f=lambda k:[x[k] for x in xs if x.get(k) is not None]
        print(f"{v:10s} {len(xs):2d} {med(f('peak_rss_kib'))/1024:8.1f} {med(f('throughput_mbps')):7.0f} {med(f('cpu_millis_per_gib')):9.0f} {med(f('recvbuf_peak_resident_kib'))/1024:15.1f} {med(f('recvbuf_virt_kib'))/1024:16.1f}")

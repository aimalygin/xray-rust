import sys
def parse(path):
    rows = []
    for line in open(path):
        d = {}
        for kv in line.split():
            k, _, v = kv.partition('=')
            d[k] = int(v)
        rows.append(d)
    return rows
M = 1 << 20
for path in sys.argv[1:]:
    rows = parse(path)
    peak = max(rows, key=lambda r: r['rss'])
    print(f"== {path.split('/')[-1]}: {len(rows)} samples; peak sample:")
    for k, v in peak.items():
        if k in ('rss', 'anon', 'file'):
            print(f"   {k:12s} {v/1024:8.1f} MiB")
        elif k in ('t_ms', 'n_recv', 'n_other', 'allocs', 'asm_chunks', 'defrags', 'chan_events', 'conns', 'buf_conns', 'ordblks') or k.startswith('buf_ge') or k == 'chan_conns':
            print(f"   {k:12s} {v}")
        else:
            print(f"   {k:12s} {v/M:8.1f} MiB")
    print("   series (t_ms rss anon | live_total live_recv asm_buf chan_bytes | uord ford arena | buf_conns buf_ge1_9m buf_max chan_max):")
    step = max(1, len(rows) // 40)
    for r in rows[::step]:
        print(f"   {r['t_ms']:6d} {r['rss']/1024:6.1f} {r['anon']/1024:6.1f} | {r['live_total']/M:6.1f} {r['live_recv']/M:6.1f} {r['asm_buf']/M:6.1f} {r['chan_bytes']/M:6.1f} | {r['uord']/M:6.1f} {r['ford']/M:6.1f} {r['arena']/M:6.1f} | {r['buf_conns']:3d} {r['buf_ge1_9m']:3d} {r['buf_max']/M:5.2f} {r['chan_max']/M:5.2f}")

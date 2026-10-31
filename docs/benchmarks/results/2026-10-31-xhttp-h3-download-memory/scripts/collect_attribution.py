"""Collects every instrumented run into one JSON line: harness result,
/proc peak, the memlog sample at peak RSS and a 500 ms series.

Usage: collect_attribution.py RUNS_DIR OUT_JSONL
RUNS_DIR holds mem/<label>-<traffic>-<flows>/ (run-mem.sh output) and
memlogs/<label>.log (the instrumented client's sampler).
"""
import glob, json, os, sys

BUILDS = {  # label prefix -> instrumented build
    'exp1': 'memexp1: tagging allocator, quinn assembler and channel counters',
    'exp2': 'memexp2: memexp1 + census of live datagram allocations, GRO switch',
    'exp3': 'memexp3: memexp2 + h3 BufList counters',
    'exp4': 'memexp4: memexp3 + h3 read-ahead variants (XRAY_EXP_H3_FIX)',
    'attr': 'memexp5: memexp4 with the census off and the final poll_data rule',
    'long5': 'memexp5, 16,384 x 64 KiB downloads',
}
SERIES = ['t_ms', 'rss', 'anon', 'live_recv', 'asm_buf', 'chan_bytes', 'h3_bytes', 'uord', 'ford']


def main(runs, out):
    with open(out, 'w') as sink:
        for log in sorted(glob.glob(os.path.join(runs, 'memlogs', '*.log'))):
            label = os.path.basename(log)[:-4]
            rows = [{k: int(v) for k, _, v in (kv.partition('=') for kv in line.split())} for line in open(log)]
            if not rows:
                continue
            run_dir = glob.glob(os.path.join(runs, 'mem', f'{label}-*'))
            result, hwm, env = {}, None, {}
            if run_dir:
                found = glob.glob(os.path.join(run_dir[0], 'bench', '*', 'xray-rust', 'stream-transport', 'result.json'))
                if found:
                    full = json.load(open(found[0]))
                    result = {k: full.get(k) for k in ('status', 'throughput_mbps', 'transfer_duration_ms', 'bytes_received', 'bytes_sent', 'connections', 'traffic')}
                series = os.path.join(run_dir[0], 'series')
                if os.path.exists(series):
                    hwm = max(int(l.split()[4]) for l in open(series) if len(l.split()) == 8)
            peak = max(rows, key=lambda r: r['rss'])
            step = max(1, round(500 / max(1, rows[1]['t_ms'] - rows[0]['t_ms']))) if len(rows) > 1 else 1
            sink.write(json.dumps({
                'label': label,
                'build': BUILDS.get(label.split('-')[0], 'unknown'),
                'variant': next((v for v in ('none', 'next', 'full', 'nogro') if label.endswith(v)), 'default'),
                'vm_hwm_kib': hwm,
                'result': result,
                'peak_sample': peak,
                'series_500ms': [[r.get(k) for k in SERIES] for r in rows[::step]],
                'series_fields': SERIES,
            }) + '\n')


if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])

"""Breakdown of each instrumented run at its peak RSS sample, and medians per variant.

Usage: summarize_attribution.py data/attribution-runs.jsonl [LABEL_PREFIX]
       summarize_attribution.py MEMLOG...
The JSONL form reads the peak samples collect_attribution.py stored (runs whose
label starts with LABEL_PREFIX, default "attr-"); the other form reads the
instrumented client's raw `key=value` memlogs, named *-none.log or *-full.log.
"""
import json, statistics, sys

MIB = 1 << 20


def breakdown(peak):
    return {
        'quinn stream receive buffers': peak['asm_buf'],
        'h3 frame buffers': peak['h3_bytes'],
        'packet headers, partly read datagrams': peak['live_recv'] - peak['asm_buf'] - peak['h3_bytes'],
        'other live heap': peak['uord'] - peak['live_recv'],
        'glibc free heap': peak['ford'],
        'mmapped and stacks (anon - arena)': peak['anon'] * 1024 - peak['uord'] - peak['ford'],
        'RssFile': peak['file'] * 1024,
        'RSS': peak['rss'] * 1024,
    }


def peaks(args):
    if args[0].endswith('.jsonl'):
        prefix = args[1] if len(args) > 1 else 'attr-'
        for line in open(args[0]):
            run = json.loads(line)
            if run['label'].startswith(prefix):
                yield run['label'], run['variant'], run['peak_sample']
        return
    for path in args:
        rows = [{k: int(v) for k, _, v in (kv.partition('=') for kv in l.split())} for l in open(path)]
        yield path.split('/')[-1], 'full' if path.endswith('-full.log') else 'none', max(rows, key=lambda r: r['rss'])


def main(args):
    by_variant = {}
    for label, variant, peak in peaks(args):
        b = breakdown(peak)
        by_variant.setdefault(variant, []).append(b)
        print(f"{label}: peak at {peak['t_ms']} ms, " + ', '.join(f"{k} {v / MIB:.1f}" for k, v in b.items()))
    for variant, runs in sorted(by_variant.items()):
        print(f"== {variant}: median of {len(runs)} runs (MiB)")
        for key in runs[0]:
            print(f"   {key:40s} {statistics.median(r[key] for r in runs) / MIB:6.1f}")


if __name__ == '__main__':
    main(sys.argv[1:])

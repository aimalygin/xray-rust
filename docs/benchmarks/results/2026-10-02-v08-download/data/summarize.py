#!/usr/bin/env python3
"""Validate complete paired campaigns and summarize all repetitions, without credentials."""
import collections
import json
from pathlib import Path
import statistics
import sys


def read(path):
    return json.loads(path.read_text())


def stats(values):
    return {'median': statistics.median(values), 'min': min(values), 'max': max(values), 'samples': values}


def controls(folder):
    m = read(folder/'manifest.json')
    assert m['status'] == 'pass'
    versions = sorted({r['version'] for r in m['runs']})
    expected = {(c['id'], v, i) for c in m['cases'] for v in versions for i in range(1, m['repeats']+1)}
    assert len(m['runs']) == len(expected)
    assert {(r['case'],r['version'],r['repeat']) for r in m['runs']} == expected
    rows = collections.defaultdict(lambda: collections.defaultdict(list))
    for r in m['runs']:
        assert r['returncode'] == 0 and r['process_group_empty_after_run']
        assert not r['remaining_engine_processes'] and not r['surviving_process_group']
        assert not r['ambient_cpu']['observer_errors'] and not r['ambient_cpu']['compiler_load_detected']
        x = read(folder/r['output_relative']/'result.json')
        assert x['status'] == 'pass' and x['engine_sha256'] == m['file_hashes'][x['engine_binary']]
        assert x['client_env'] == {} and x['warmup']
        payload = x['connections']*x['iterations']*x['payload_size']
        assert x['bytes_sent'] == (0 if x['traffic']=='download' else payload)
        assert x['bytes_received'] == (0 if x['traffic']=='upload' else payload)
        metrics = {'cpu_ms':x['cpu_millis'], 'throughput_mib_s':x['throughput_mib_s'], 'rss_mib':x['peak_rss_kib']/1024,
                   'startup_cpu_ms':x['client_startup_cpu_millis']}
        if x['latency_us']:
            metrics.update({f'latency_{k}_us':v for k,v in x['latency_us'].items()})
        for k,v in metrics.items(): rows[r['case'],r['version']][k].append(v)
    return [{'case':c,'version':v,'metrics':{k:stats(vs) for k,vs in metrics.items()}} for (c,v),metrics in sorted(rows.items())]


def memory(folder):
    m = read(folder/'manifest.json')
    assert m['status'] == 'pass'
    assert not m['ambient_cpu']['compiler_load_detected'] and not m['ambient_cpu']['observer_errors']
    assert len(m['runs']) == len({(r['profile'],r['version'],r['repeat']) for r in m['runs']})
    rows = collections.defaultdict(list)
    for r in m['runs']:
        x = read(folder/r['output_relative']/'result.json')
        assert x['status'] == 'pass' and not x['remaining_engine_processes']
        assert x['engine_sha256'] == m['file_hashes'][x['binary']]
        assert x['warmup_bytes_per_connection'] == m['warmup_bytes_per_connection']
        assert x['checked_bytes_each_direction'] == 512*x['warmup_bytes_per_connection']
        assert [p['connections'] for p in x['points']] == [0,32,128,512]
        for p in x['points']:
            assert len(p['samples']) == 5
            assert p['rss_kib_median'] == statistics.median(s['rss_kib'] for s in p['samples'])
            rows[r['profile'],r['version'],p['connections']].append(p['rss_kib_median']/1024)
    assert all(len(v)==m['repeats'] for v in rows.values())
    return [{'profile':p,'version':v,'connections':n,'rss_mib':stats(vs)} for (p,v,n),vs in sorted(rows.items())]


def main():
    root=Path(sys.argv[1]);out={}
    for spec in sys.argv[3:]:
        mode,group=spec.split(':',1)
        out[group]=(controls if mode=='controls' else memory)(root/group)
    Path(sys.argv[2]).write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')


if __name__=='__main__':main()

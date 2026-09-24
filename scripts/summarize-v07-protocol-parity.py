#!/usr/bin/env python3
"""Report every reference comparison against explicit per-metric targets.

Defaults are strict. An explicit performance allowance keeps RSS strictly lower
and preserves the original point differences and uncertainty intervals.
"""
import argparse
import importlib.util
import json
import math
from pathlib import Path
import random
import statistics
SPEC=importlib.util.spec_from_file_location('summary',Path(__file__).with_name('summarize-v07-performance.py'))
base=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(base)


def ratio_interval(candidate,reference):
    if len(candidate)<3 or len(candidate)!=len(reference) or statistics.median(reference)==0:return None
    rng=random.Random(6928);values=[];n=len(candidate)
    for _ in range(4000):
        indexes=rng.choices(range(n),k=n);den=statistics.median(reference[i] for i in indexes)
        if den:values.append(statistics.median(candidate[i] for i in indexes)/den)
    values.sort()
    return [values[int(.025*len(values))],values[min(len(values)-1,int(.975*len(values)))]] if values else None


def point_target(metric, candidate, reference, max_regression_pct=0):
    if metric == 'rss_mib':
        return candidate < reference
    allowance = max_regression_pct / 100
    return (candidate >= reference * (1 - allowance) if metric == 'throughput_mib_s'
            else candidate <= reference * (1 + allowance))


def summarize(root, max_regression_pct=0):
    if not math.isfinite(max_regression_pct) or not 0 <= max_regression_pct < 100:
        raise ValueError('performance allowance must be finite and in [0, 100) percent')
    summary=base.summarize(root);manifest=json.loads((root/'manifest.json').read_text());extra={}
    quality_path=root/'measurement-quality.json'
    quality=json.loads(quality_path.read_text()) if quality_path.exists() else {}
    controls=set(quality.get('internal_controls', []))
    explicit_references=quality.get('external_references')
    contaminated=bool(quality.get('compiler_load_detected')) or any(
        bool(run.get('ambient_cpu', {}).get('compiler_load_detected')) for run in manifest['runs'])
    roles={name: ('internal_control' if name in controls else 'external_reference')
           for name in manifest['versions'] if name != 'candidate'}
    if explicit_references is not None:
        unknown=set(roles)-controls-set(explicit_references)
        if unknown:raise ValueError('comparison roles missing for: '+', '.join(sorted(unknown)))
        if controls & set(explicit_references):raise ValueError('comparison cannot be both internal and external')

    for run in manifest['runs']:
        if run['returncode']:continue
        data=json.loads((root/run['output_relative']/'result.json').read_text())
        if manifest.get('warmup'):
            if not data.get('warmup') or data.get('engine_sha256') != manifest['file_hashes'].get(data.get('engine_binary')):
                raise ValueError('warmup or actual measured engine identity mismatch')
        lat=data.get('latency_us') or {};row=extra.setdefault((run['case'],run['version']),{})
        for metric in ['client_startup_seconds','client_startup_cpu_millis','client_cpu_total_millis']:
            if metric in data:row.setdefault(metric,[]).append(data[metric])
        for k in ['p95','p99']:
            if k in lat:row.setdefault('latency_'+k+'_us',[]).append(lat[k])
    for row in summary['rows']:
        for version,group in row['versions'].items():
            if group['complete']:
                for name,vals in extra.get((row['case'],version),{}).items():
                    if len(vals)==manifest['repeats']:group['metrics'][name]={'median':statistics.median(vals),'min':min(vals),'max':max(vals),'samples':vals}
        row['comparisons']={}
        current=row['versions'].get('candidate')
        if not current:continue
        for name,ref in row['versions'].items():
            if name=='candidate':continue
            compare={'complete':current['complete'] and ref['complete'],'role':roles[name],'metrics':{}}
            row['comparisons'][name]=compare
            if not compare['complete']:continue
            for metric in sorted(current['metrics'].keys() & ref['metrics'].keys()):
                a=current['metrics'][metric];b=ref['metrics'][metric];den=b['median'];ratio=a['median']/den if den else None
                meets=point_target(metric,a['median'],den,max_regression_pct)
                compare['metrics'][metric]={'candidate':a['median'],'reference':den,'ratio':ratio,
                    'meets_point_target':meets,'meets_strict_point_target':point_target(metric,a['median'],den),
                    'allowed_regression_pct':0 if metric=='rss_mib' else max_regression_pct,
                    'paired_bootstrap_95pct':ratio_interval(a['samples'],b['samples'])}
    comparisons=[c for row in summary['rows'] for c in row['comparisons'].values() if c['role']=='external_reference']
    metrics=[(name, metric) for c in comparisons if c['complete'] for name,metric in c['metrics'].items()]
    deficits=sum(not metric['meets_point_target'] for _,metric in metrics)
    uncertain=0
    for name,metric in metrics:
        interval=metric['paired_bootstrap_95pct']
        supported=interval is not None and (interval[0]>=1-max_regression_pct/100 if name=='throughput_mib_s' else interval[1]<1 if name=='rss_mib' else interval[1]<=1+max_regression_pct/100)
        uncertain+=not supported
    complete=bool(comparisons) and all(c['complete'] for c in comparisons)
    summary['parity']={'status':'invalid_measurements' if contaminated else 'not_met' if deficits or not complete else 'unproven' if uncertain else 'observed_targets_met',
                       'environmental_interference_detected':contaminated, 'reference_comparisons':len(comparisons),
                       'complete':complete,'point_deficit_metrics':deficits,'metrics_without_supporting_interval':uncertain,
                       'max_regression_pct':max_regression_pct,'memory_target':'strictly lower RSS',
                       'strict_point_deficit_metrics':sum(not metric['meets_strict_point_target'] for _,metric in metrics),
                       'scope':'observed workload and host only; explicit performance allowance does not waive memory, failed trials, environmental interference or uncertainty'}
    return summary


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('root',type=Path)
    p.add_argument('--max-regression-pct',type=float,default=0,help='explicit allowed throughput decrease or CPU/latency/startup increase; RSS remains strictly lower')
    p.add_argument('--output',type=Path,help='write a separate derived summary instead of ROOT/summary.json')
    p.add_argument('--check',action='store_true',help='fail unless every requested target has supporting measured evidence')
    a=p.parse_args();summary=summarize(a.root,a.max_regression_pct)
    (a.output or a.root/'summary.json').write_text(json.dumps(summary,indent=2,sort_keys=True)+'\n')
    print(json.dumps({'parity':summary['parity'],'cases':len(summary['rows']),'failures':summary['failures'],'comparisons_with_point_deficits':sum(any(not m['meets_point_target'] for m in c['metrics'].values()) for row in summary['rows'] for c in row['comparisons'].values())},indent=2))

    if a.check and summary['parity']['status']!='observed_targets_met':raise SystemExit(1)

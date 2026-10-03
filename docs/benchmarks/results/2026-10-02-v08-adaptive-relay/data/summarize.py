#!/usr/bin/env python3
"""Verify complete paired prototype workloads and held footprint/resume trials."""
import json,statistics
from pathlib import Path

def load(p):return json.loads(p.read_text())
def stats(rows):return {k:{'median':statistics.median(r[k] for r in rows),'min':min(r[k] for r in rows),'max':max(r[k] for r in rows),'samples':[r[k] for r in rows]} for k in rows[0]}
def bulk(path,repeats,versions=('baseline','candidate')):
 m=load(path/'manifest.json');assert m['status']=='pass' and m['repeats']==repeats
 expected={(c['id'],v,i) for c in m['cases'] for v in versions for i in range(1,repeats+1)}
 assert len(m['runs'])==len(expected) and {(r['case'],r['version'],r['repeat']) for r in m['runs']}==expected
 groups={};orders={}
 for row in m['runs']:
  assert row['returncode']==0 and not row['remaining_engine_processes'] and not row['surviving_process_group']
  assert not row['ambient_cpu']['compiler_load_detected'] and not row['ambient_cpu']['observer_errors']
  orders.setdefault(row['case'],{}).setdefault(row['repeat'],tuple(row['client_order']))
  r=load(path/row['output_relative']/'result.json');assert r['status']=='pass'
  cycles=m.get('profile_cycles',1)
  assert r.get('diagnostic_only',False)==m.get('diagnostic_only',False)
  if cycles!=1:
   assert cycles==8 and r['profile_cycles']==8 and m['profiler_attached']==False
  expected_hash=m['file_hashes'].get(r['engine_binary']) or m['versions'][row['version']]['engine_sha256']
  assert r['engine_sha256']==expected_hash
  n=r['connections']*r['iterations']*r['payload_size']*cycles
  assert r['bytes_sent']==(0 if r['traffic']=='download' else n)
  assert r['bytes_received']==(0 if r['traffic']=='upload' else n)
  metrics={k:r[k] for k in ['cpu_millis','throughput_mib_s','peak_rss_kib','transfer_seconds']}
  if r['latency_us']:metrics.update({'latency_'+k:v for k,v in r['latency_us'].items()})
  groups.setdefault((row['case'],row['version']),[]).append(metrics)
 for case,by_repeat in orders.items():
  assert len(by_repeat)==repeats
  for version in versions:
   for position in range(len(versions)):
    assert sum(order[position]==version for order in by_repeat.values())==repeats//len(versions)
 return {case:{v:stats(rows) for (c,v),rows in groups.items() if c==case} for case in sorted({c for c,v in groups})}
def held(path):
 m=load(path/'manifest.json');assert m['status']=='pass'
 assert not m['ambient_cpu']['compiler_load_detected'] and not m['ambient_cpu']['observer_errors']
 a=m['arguments'];expected={(p,v,i) for p in a['profile'] for v in ['baseline','candidate'] for i in range(1,m['repeats']+1)}
 assert len(expected)==len(m['runs']) and expected=={(r['profile'],r['version'],r['repeat']) for r in m['runs']}
 groups={}
 for row in m['runs']:
  r=load(path/row['output_relative']/'result.json');assert r['status']=='pass' and not r['remaining_engine_processes']
  binary=dict(item.split('=',1) for item in a['binary'])[row['version']]
  digest=next(v for k,v in m['file_hashes'].items() if k.endswith(binary))
  assert r['engine_sha256']==digest
  assert all(r[k]==row[k] for k in ['profile','version','repeat'])
  assert r['connections']==512 and r['checked_bytes_each_direction']==512*(3*a['warmup_bytes']+2048)
  phases={p['phase']:p for p in r['phases']};assert {'empty','warm','idle-0','first-request-0','resumed-bulk-0','idle-1','first-request-1','resumed-bulk-1'}==set(phases)
  metrics={}
  for phase,p in phases.items():
   for field in ['footprint_kib','rss_kib']:metrics[phase+'.'+field]=p[field]
  for cycle in [0,1]:
   start=phases['warm' if cycle==0 else 'resumed-bulk-0'];end=phases[f'idle-{cycle}']
   assert 10.9<=end['unix']-start['unix']<15
   metrics[f'idle-{cycle}.cpu_ms']=end['cpu_ms']-start['cpu_ms']
   values=sorted(phases[f'first-request-{cycle}']['latency_us']);assert len(values)==512
   metrics[f'first-request-{cycle}.p95_us']=values[int(.95*(len(values)-1))]
  groups.setdefault((row['profile'],row['version']),[]).append(metrics)
 return {profile:{v:stats(rows) for (p,v),rows in groups.items() if p==profile} for profile in sorted({p for p,v in groups})}
def run(base):
 result={}
 for p in sorted(base.glob('*/manifest.json')):
  m=load(p)
  if m.get('status')!='pass':continue
  name=p.parent.name
  if 'arguments' in m and 'warmup_bytes' in m['arguments']:
   result[name]={'kind':'held','clients':len(m['runs']),'cases':held(p.parent)}
  else:
   versions=tuple(dict.fromkeys(r['version'] for r in m['runs']))
   result[name]={'kind':'diagnostic' if m.get('diagnostic_only') else 'ordinary','trials':len(m['runs']),'cases':bulk(p.parent,m['repeats'],versions)}
 return result
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('base',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();s=run(a.base);a.output.write_text(json.dumps(s,indent=2,sort_keys=True)+'\n')
 print('Verified',len(s),'completed campaigns')

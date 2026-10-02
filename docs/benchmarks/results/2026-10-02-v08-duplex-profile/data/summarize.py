#!/usr/bin/env python3
"""Reconstruct ordinary controls, OS/libc counters and target-only on-CPU profiles."""
import collections,importlib.util,json,statistics
from pathlib import Path
OPS=['read','write','recv','send','recvfrom','sendto','readv','writev','recvmsg','sendmsg','getentropy','kevent','kevent64','writev_requested_segments','writev_iov_count','arc4random_buf']
def read(p):return json.loads(p.read_text())
def stats(rows):
 return {k:{'median':statistics.median(r[k] for r in rows),'min':min(r[k] for r in rows),'max':max(r[k] for r in rows),'samples':[r[k] for r in rows]} for k in rows[0]}
def validate_matrix(base,n):
 m=read(base/'manifest.json');assert m['status']=='pass' and not m['smoke'] and m['repeats']==n
 expected={(c['id'],v,i) for c in m['cases'] for v in m['versions'] for i in range(1,n+1)}
 assert expected=={(r['case'],r['version'],r['repeat']) for r in m['runs']} and len(expected)==len(m['runs'])
 for row in m['runs']:
  assert row['returncode']==0 and not row['remaining_engine_processes'] and not row['surviving_process_group']
  assert not row['ambient_cpu']['compiler_load_detected'] and not row['ambient_cpu']['observer_errors']
  r=read(base/row['output_relative']/'result.json');assert r['status']=='pass'
  size=r['connections']*r['iterations']*r['payload_size']
  assert r['bytes_sent']==(0 if r['traffic']=='download' else size)
  assert r['bytes_received']==(0 if r['traffic']=='upload' else size)
  assert r['engine_sha256']==m['file_hashes'][r['engine_binary']]
  yield row,r
def controls(base):
 manifest=read(base/'manifest.json')
 for case in manifest['cases']:
  selected=[r for r in manifest['runs'] if r['case']==case['id']]
  orders={i:{tuple(r['client_order']) for r in selected if r['repeat']==i} for i in range(1,7)}
  assert all(len(v)==1 for v in orders.values()) and len(set.union(*orders.values()))==6
 groups={}
 for row,r in validate_matrix(base,6):
  metrics={k:r[k] for k in ['cpu_millis','throughput_mib_s','peak_rss_kib','transfer_seconds']}
  metrics['cpu_ms_per_gib']=r['cpu_millis']/((r['bytes_sent']+r['bytes_received'])/2**30)
  groups.setdefault((row['case'],row['version']),[]).append(metrics)
 return {case:{v:stats(rows) for (c,v),rows in groups.items() if c==case} for case in sorted({c for c,v in groups})}
def census(base):
 groups={}
 for row,r in validate_matrix(base,4):
  assert r['diagnostic_only'];size=r['bytes_sent']+r['bytes_received']
  before=r['process_census']['before']['os'];after=r['process_census']['after_settle']['os']
  for snapshot in r['process_census'].values():
   s=snapshot['os'];assert 'error' not in s
   for name in ['user','system']:assert s[name+'_ns']==s[name+'_mach_ticks']*s['timebase_numer']//s['timebase_denom']
  d={k:after[k]-before[k] for k in ['user_ns','system_ns','syscalls_unix','syscalls_mach','context_switches']};assert min(d.values())>=0
  metrics={'unix_calls':d['syscalls_unix'],'unix_calls_per_mib':d['syscalls_unix']/(size/2**20),'mach_calls':d['syscalls_mach'],'context_switches':d['context_switches'],'user_ms':d['user_ns']/1e6,'system_ms':d['system_ns']/1e6,'cpu_ms':(d['user_ns']+d['system_ns'])/1e6}
  assert abs(metrics['cpu_ms']-r['cpu_millis'])<max(30,metrics['cpu_ms']*.08)
  if base.name=='libc':
   a=r['process_census']['before']['interpose'];b=r['process_census']['after_settle']['interpose'];assert a[:5]==b[:5] and a[0]==0x58524159434e5331 and a[3:5]==[16,16]
   delta=[v-u for u,v in zip(a[8:],b[8:])];assert min(delta)>=0;metrics={}
   for i,op in enumerate(OPS):
    v=delta[i*16:(i+1)*16]
    for key,n in zip(['calls','requested','returned','would_block','errors','zero'],v[:6]):metrics[op+'_'+key]=n
    assert sum(v[6:])+v[3]+v[4]==v[0]
   writes=sum(metrics[op+'_returned'] for op in ['write','sendto','writev','sendmsg']);assert size<=writes<size*1.05,(row,writes,size)
   metrics['deduplicated_write_calls']=sum(metrics[op+'_calls'] for op in ['write','sendto','writev','sendmsg']);metrics['deduplicated_write_bytes']=writes
   metrics['mean_write_bytes']=writes/metrics['deduplicated_write_calls']
  groups.setdefault((row['case'],row['version']),[]).append(metrics)
 return {case:{v:stats(rows) for (c,v),rows in groups.items() if c==case} for case in sorted({c for c,v in groups})}
def profiles(base):
 spec=importlib.util.spec_from_file_location('profile_summary',Path(__file__).with_name('profile-summary.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
 groups={};individual={}
 for version in ['rust','xray']:
  for index in range(1,5):
   directory=base/f'{version}-duplex-{index}';meta=read(directory/'capture.json');assert meta['status']=='pass' and meta['driver_returncode']==meta['profiler_returncode']==0
   assert meta['verified_bytes']=={'sent':256*2**20*meta['cycles'],'received':256*2**20*meta['cycles']}
   if index>1:
    assert meta['cycles']==96 and not meta['ambient']['errors'] and not any(s['compiler_load_detected'] for s in meta['ambient']['samples'])
   options=read(directory/'options.json')['Time Profiler'];assert options['recordKernelStacks'] and not options['recordWaitingThreads'] and not options['contextSwitchSampling']
   s,rows=m.analyze(directory/'time-profile.xml',meta['client_pid']);assert s==read(directory/'profile-summary.json')
   categories=collections.Counter();markers=collections.Counter();total=sum(r['weight_ns'] for r in rows)
   for r in rows:
    stack=r['stack'];names={n for n,b in stack};name,binary=stack[0];weight=r['weight_ns']
    if binary.startswith('kernel.'):category='kernel'
    elif 'aesv8_gcm_' in name or '/aes/gcm.gcmAes' in name:category='aes_gcm_assembly'
    elif name in ['_platform_memmove','_platform_memcpy','runtime.memmove']:category='memory_copy'
    elif 'vmess..stream..ClientStream' in name and 'poll_read' in name:category='vmess_poll_read'
    else:category='other'
    categories[category]+=weight
    for label,present in [('kevent',bool(names&{'kevent','kevent64'})),('write_syscall',bool(names&{'__sendto','writev','write','__write_nocancel'})),('read_syscall_or_readv_path',bool(names&{'__recvfrom','readv','read','__read_nocancel'}) or any('(*posixReader).Read' in n for n in names)),('padding_rng','ccrng_crypto_generate' in names)]:
     if present:markers[label]+=weight
   values={k+'_pct':100*categories[k]/total for k in ['kernel','aes_gcm_assembly','memory_copy','vmess_poll_read','other']}
   values.update({k+'_inclusive_pct':100*markers[k]/total for k in ['kevent','write_syscall','read_syscall_or_readv_path','padding_rng']})
   values['samples']=len(rows);values['sampled_cpu_ms']=total/1e6;values['active_threads']=len(s['thread_cpu_ms'])
   individual[directory.name]=values
   if index>1:groups.setdefault(version,[]).append(values)
 return {'individual':individual,'repeated':{v:stats(rows) for v,rows in groups.items()},'pilot_excluded':['rust-duplex-1','xray-duplex-1']}
def run(base):return {'ordinary':controls(base/'normal-controls'),'ordinary_confirmation':controls(base/'normal-confirmation'),'kernel':census(base/'kernel'),'libc':census(base/'libc'),'profiles':profiles(base)}
if __name__=='__main__':
 import argparse
 p=argparse.ArgumentParser();p.add_argument('base',type=Path);p.add_argument('--output',type=Path,required=True);a=p.parse_args();s=run(a.base);a.output.write_text(json.dumps(s,indent=2,sort_keys=True)+'\n')
 for group in ['ordinary','kernel','libc']:
  print(group)
  keys={'ordinary':['cpu_millis','throughput_mib_s','peak_rss_kib'],'kernel':['unix_calls','context_switches','user_ms','system_ms','cpu_ms'],'libc':['sendto_calls','writev_calls','recvfrom_calls','kevent_calls','deduplicated_write_calls','mean_write_bytes']}[group]
  for case,versions in s[group].items():
   for v,metrics in versions.items():print(case,v,{k:round(metrics[k]['median'],2) for k in keys})
 print('profiles')
 for v,metrics in s['profiles']['repeated'].items():print(v,{k:round(val['median'],2) for k,val in metrics.items()})

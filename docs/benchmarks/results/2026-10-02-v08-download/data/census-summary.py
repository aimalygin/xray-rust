#!/usr/bin/env python3
"""Reconstruct call counts only; never use instrumented timings as performance."""
import collections,json,statistics,sys
from pathlib import Path
OPS=['read','write','recv','send','recvfrom','sendto','readv','writev','recvmsg','sendmsg','getentropy','kevent','kevent64','writev_requested_segments','writev_iov_count','arc4random_buf']
def read(p):return json.loads(p.read_text())
def summarize(folder):
 m=read(folder/'manifest.json');assert m['status']=='pass' and m['diagnostic_only'] and m['repeats']==3
 expected={(c['id'],v,r) for c in m['cases'] for v in m['versions'] for r in range(1,4)}
 assert len(m['runs'])==12 and {(r['case'],r['version'],r['repeat']) for r in m['runs']}==expected
 groups=collections.defaultdict(list)
 for r in m['runs']:
  assert not r['returncode'] and not r['remaining_engine_processes'] and not r['surviving_process_group'] and r['process_group_empty_after_run'] and not r['ambient_cpu']['compiler_load_detected'] and not r['ambient_cpu']['observer_errors']
  x=read(folder/r['output_relative']/'result.json');assert x['diagnostic_only'] and x['status']=='pass' and x['engine_sha256']==m['file_hashes'][x['engine_binary']]
  n=x['connections']*x['iterations']*x['payload_size'];assert x['bytes_received']==n and x['bytes_sent']==0
  before=x['process_census']['before']['interpose'];after=x['process_census']['after_settle']['interpose'];assert before[:5]==after[:5] and before[0]==0x58524159434e5331 and before[3:5]==[16,16]
  delta=[v-u for u,v in zip(before[8:],after[8:])];assert min(delta)>=0;counts={}
  for i,op in enumerate(OPS):
   a=delta[i*16:(i+1)*16];assert sum(a[6:])+a[3]+a[4]==a[0]
   for key,v in zip(['calls','requested','returned','would_block','errors','zero'],a[:6]):counts[op+'_'+key]=v
  writes=sum(counts[k+'_returned'] for k in ['write','sendto','writev','sendmsg']);assert n<=writes<n*1.05
  calls=sum(counts[k+'_calls'] for k in ['write','sendto','writev','sendmsg']);counts['deduplicated_write_calls']=calls;counts['deduplicated_write_bytes']=writes;counts['mean_write_bytes']=writes/calls
  groups[r['case'],r['version']].append(counts)
 return [{'case':c,'version':v,'metrics':{k:{'median':statistics.median(row[k] for row in rows),'min':min(row[k] for row in rows),'max':max(row[k] for row in rows),'samples':[row[k] for row in rows]} for k in rows[0]}} for (c,v),rows in sorted(groups.items())]
if __name__=='__main__':
 result=summarize(Path(sys.argv[1]));Path(sys.argv[2]).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 for row in result:print(row['case'],row['version'],{k:round(row['metrics'][k]['median'],2) for k in ['deduplicated_write_calls','mean_write_bytes','getentropy_calls','arc4random_buf_calls']})

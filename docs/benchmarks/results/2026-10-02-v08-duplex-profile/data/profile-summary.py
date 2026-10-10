#!/usr/bin/env python3
"""Resolve xctrace ID/reference tables into target-only samples and weighted stacks."""
import argparse,collections,json,re,xml.etree.ElementTree as ET
from pathlib import Path

def analyze(path,pid):
 root=ET.parse(path).getroot(); ids={e.attrib['id']:e for e in root.iter() if 'id' in e.attrib}
 def resolve(e):
  while 'ref' in e.attrib:e=ids[e.attrib['ref']]
  return e
 def value(e):return resolve(e).text
 def frame(e):
  e=resolve(e);b=resolve(e.find('binary')) if e.find('binary') is not None else None
  name=re.sub(r'::h[0-9a-f]{16}$','',e.attrib['name'])
  return (name,b.attrib['name'] if b is not None else '<unknown>')
 samples=[];leaf=collections.Counter();inclusive=collections.Counter();threads=collections.Counter();states=collections.Counter();stacks=collections.Counter()
 for row in root.findall('.//row'):
  p=resolve(row.find('process'));actual=int(value(p.find('pid')))
  if actual!=pid:continue
  time=int(value(row.find('sample-time')));weight=int(value(row.find('weight')));thread=resolve(row.find('thread'));tid=int(value(thread.find('tid')));state=value(row.find('thread-state'))
  stack=resolve(row.find('tagged-backtrace'));frames=[frame(f) for f in stack]
  assert frames and weight>0 and state=='Running',(state,frames)
  samples.append({'time_ns':time,'weight_ns':weight,'tid':tid,'core':int(value(row.find('core'))),'stack':frames})
  leaf[frames[0]]+=weight
  for f in set(frames):inclusive[f]+=weight
  threads[tid]+=weight;states[state]+=weight;stacks[tuple(frames)]+=weight
 total=sum(threads.values())
 def ranked(c):return [{'name':k[0],'binary':k[1],'cpu_sample_ms':v/1e6,'percent':100*v/total} for k,v in sorted(c.items(),key=lambda item:(-item[1],item[0]))]
 summary={'pid':pid,'samples':len(samples),'sampled_cpu_ms':total/1e6,'first_sample_ns':min(x['time_ns'] for x in samples),'last_sample_ns':max(x['time_ns'] for x in samples),'thread_cpu_ms':{str(k):v/1e6 for k,v in threads.most_common()},'states':dict(states),'leaf':ranked(leaf),'inclusive':ranked(inclusive)}
 return summary,samples
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('directory',type=Path);a=p.parse_args();meta=json.loads((a.directory/'capture.json').read_text());s,rows=analyze(a.directory/'time-profile.xml',meta['client_pid']);(a.directory/'profile-summary.json').write_text(json.dumps(s,indent=2)+'\n');(a.directory/'samples.json').write_text(json.dumps(rows,separators=(',',':'))+'\n')
 print({k:v for k,v in s.items() if k not in ['leaf','inclusive']})
 print('LEAF');print('\n'.join(f"{r['percent']:5.1f}% {r['name']} ({r['binary']})" for r in s['leaf'][:30]))
 print('INCLUSIVE');print('\n'.join(f"{r['percent']:5.1f}% {r['name']} ({r['binary']})" for r in s['inclusive'][:38]))

#!/usr/bin/env python3
"""Publish complete numerical evidence, without generated connection credentials."""
import hashlib,importlib.util,json,shutil,sys,tarfile
from pathlib import Path
ROOT=Path('/Users/antonmalygin/xray-rust');BASE=ROOT/'target/v08-send-investigation';REPORT=ROOT/'docs/benchmarks/results/2026-10-01-v08-send'
def read(p):return json.loads(p.read_text())
def save(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def module(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def main():
 controls={'arc-controls':36,'pair-controls':54,'chacha-controls':36,'confirmation':40,'latency-controls':48}
 memories={'small-memory':12,'bulk-memory':12}
 summary=module('control_summary',BASE/'summarize.py');stats={}
 for name,count in {**controls,**memories}.items():
  m=read(BASE/name/'manifest.json');assert len(m['runs'])==count
  stats[name]=(summary.controls if name in controls else summary.memory)(BASE/name)
 full=BASE/'comparison';m=read(full/'manifest.json')
 assert m['status']=='pass' and len(m['runs'])==270 and len(m['cases'])==30
 assert all(not r['returncode'] and not r['ambient_cpu']['compiler_load_detected'] and not r['ambient_cpu']['observer_errors'] and r['process_group_empty_after_run'] and not r['remaining_engine_processes'] and not r['surviving_process_group'] for r in m['runs'])
 assert all(sha(Path(p))==h for p,h in m['file_hashes'].items())
 REPORT.mkdir(exist_ok=True);data=REPORT/'data';data.mkdir(exist_ok=True)
 save(data/'control-summary.json',stats)
 parity=module('parity',ROOT/'scripts/summarize-v07-protocol-parity.py')
 for allowance,name in [(0,'summary-strict.json'),(3,'summary-mac-3pct.json')]:save(data/name,parity.summarize(full,allowance))
 for name in ['inputs.json','host.json','builds.json','libc-summary.json','mobile-identity.json','summarize.py','compare-vmess.py','publish.py','verify.py']:
  shutil.copyfile(BASE/name,data/name)
 files={}
 with tarfile.open(REPORT/'measurements.tar.gz','w:gz') as archive:
  def add(p,name):
   assert name not in files;files[name]=sha(p);archive.add(p,arcname=name,recursive=False)
  def campaign(folder,prefix):
   m=read(folder/'manifest.json');add(folder/'manifest.json',prefix+'/manifest.json')
   if (folder/'source.patch').exists():add(folder/'source.patch',prefix+'/source.patch')
   for r in m['runs']:
    add(folder/r['output_relative']/'result.json',prefix+'/'+r['output_relative']+'/result.json')
   return m
  for group in [*controls,*memories,'comparison','libc']:
   folder=BASE/group;campaign(folder,group)
   if (folder/'selection.json').exists():add(folder/'selection.json',group+'/selection.json')
   for p in sorted((folder/'attempts').glob('*/manifest.json')):campaign(p.parent,group+'/attempts/'+p.parent.name)
  for rejected in sorted(BASE.glob('small-memory-rejected-*')):
   if not rejected.is_dir():continue
   campaign(rejected,rejected.name)
   for p in sorted(rejected.glob('*/partial.json')):add(p,rejected.name+'/'+str(p.relative_to(rejected)))
   add(BASE/(rejected.name+'.log'),rejected.name+'/collector.log')
  for name in ['arc.patch','pair.patch','arc-build.log','pair-build.log','committed-rebuild.log','arc-tests.log','pair-tests.log','core-tests.log','core-tests-sandbox-denied.log','clippy.log','xray-interop.log','xray-mux.log','singbox-interop.log','build-pair.sh','pair-controls.sh','memory.sh','confirm.sh','interop.sh','held-memory-source.py','census.py','census-summary.py','write-report.py','quiet-observation.json','mobile-verification.log']:
   add(BASE/name,'investigation/'+name)
 save(REPORT/'evidence-index.json',{'archive':'measurements.tar.gz','archive_sha256':sha(REPORT/'measurements.tar.gz'),'file_sha256':files,'excluded_from_performance':['libc: injected counters only; all timings, CPU and RSS excluded','core-tests-sandbox-denied.log: initial test socket permission errors; unsandboxed rerun passes','any compiler-contaminated comparison attempt; complete-case selection retains every attempt'],'scope':'All repeated measurements, manifests, source patches and validation logs. Generated credentials, configurations and executables remain local.'})
 print('Archived',len(files),'members to',REPORT)
if __name__=='__main__':main()

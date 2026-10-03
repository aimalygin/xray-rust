#!/usr/bin/env python3
"""Archive complete download experiments without connection credentials/configs."""
import hashlib,importlib.util,json,shutil,tarfile
from pathlib import Path
ROOT=Path('/Users/antonmalygin/xray-rust'); BASE=ROOT/'target/v08-download-investigation'; REPORT=ROOT/'docs/benchmarks/results/2026-10-02-v08-download'
CONTROLS={'read16-controls':72,'four-controls':72,'combined-controls':54,'confirmation':60,'latency-controls':48,'latency-confirmation':10}
MEMORIES={'small-memory':18,'bulk-memory':18}
def read(p):return json.loads(p.read_text())
def save(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def module(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m

def main():
 REPORT.mkdir(exist_ok=True);data=REPORT/'data';data.mkdir(exist_ok=True)
 helper=module('controls',BASE/'summarize.py');stats={}
 for group,count in {**CONTROLS,**MEMORIES}.items():
  m=read(BASE/group/'manifest.json');assert len(m['runs'])==count
  stats[group]=(helper.controls if group in CONTROLS else helper.memory)(BASE/group)
 save(data/'control-summary.json',stats)
 census=module('census',BASE/'census-summary.py');save(data/'libc-summary.json',census.summarize(BASE/'libc'))
 full=BASE/'comparison';parity=module('parity',ROOT/'scripts/summarize-v07-protocol-parity.py')
 for allowance,name in [(0,'summary-strict.json'),(3,'summary-mac-3pct.json')]:save(data/name,parity.summarize(full,allowance))
 for name in ['inputs.json','host.json','mobile-identity.json','ci-run.json','mobile-ci-run.json','summarize.py','census-summary.py','publish.py','verify.py','compare-vmess.py']:
  if (BASE/name).exists():shutil.copyfile(BASE/name,data/name)
 files={}
 with tarfile.open(REPORT/'measurements.tar.gz','w:gz') as archive:
  def add(p,name):
   assert name not in files;files[name]=sha(p);archive.add(p,arcname=name,recursive=False)
  def campaign(folder,prefix):
   m=read(folder/'manifest.json');add(folder/'manifest.json',prefix+'/manifest.json')
   if (folder/'source.patch').exists():add(folder/'source.patch',prefix+'/source.patch')
   for r in m['runs']:
    result=folder/r['output_relative']/'result.json'
    if result.exists():add(result,prefix+'/'+r['output_relative']+'/result.json')
  for group in [*CONTROLS,*MEMORIES,'comparison','libc']:
   folder=BASE/group;campaign(folder,group)
   if (folder/'selection.json').exists():add(folder/'selection.json',group+'/selection.json')
   for p in sorted((folder/'attempts').glob('*/manifest.json')):campaign(p.parent,group+'/attempts/'+p.parent.name)
  for rejected in sorted(BASE.glob('*-rejected-*')):
   if rejected.is_dir() and (rejected/'manifest.json').exists():
    campaign(rejected,rejected.name)
    for p in sorted(rejected.glob('*/partial.json')):add(p,rejected.name+'/'+str(p.relative_to(rejected)))
    if (BASE/(rejected.name+'.log')).exists():add(BASE/(rejected.name+'.log'),rejected.name+'/collector.log')
  for pattern in ['*.patch','*-build.log','*-tests.log','clippy.log','*-interop.log','xray-mux.log','*.sh','census.py','held-memory-source.py','mobile-verification.log','quiet.py','quiet-observation.json','write-report.py']:
   for p in sorted(BASE.glob(pattern)):
    name='investigation/'+p.name
    if name not in files:add(p,name)
 save(REPORT/'evidence-index.json',{'archive':'measurements.tar.gz','archive_sha256':sha(REPORT/'measurements.tar.gz'),'file_sha256':files,'excluded_from_performance':['libc: instrumented CPU/RSS/timing excluded; counters only','compiler-contaminated attempts: retained, never chosen by performance'],'scope':'All repeats, source variants and validation logs. Generated credentials/configs and executables excluded.'})
 print('Archived',len(files),'members')
if __name__=='__main__':main()

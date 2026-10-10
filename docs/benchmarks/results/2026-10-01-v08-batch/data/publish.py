#!/usr/bin/env python3
"""Archive complete numeric evidence, including rejected variants and failed probes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tarfile

repo=Path(sys.argv[1]).resolve();source=repo/'target/v08-batch-investigation'
report=repo/'docs/benchmarks/results/2026-10-01-v08-batch'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def save(p,x):p.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n')
def module(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
controls={'batch16-controls':72,'batch2-controls':72,'latency-controls':48,'confirmation-controls':60,'upload-confirmation':28}
memories={'active-held-memory':18,'small-held-memory':12,'bulk-held-memory':12}
summary=module('controls',source/'summarize.py');result={}
for group,count in {**controls,**memories}.items():
 m=read(source/group/'manifest.json');assert len(m['runs'])==count
 result[group]=(summary.controls if group in controls else summary.memory)(source/group)
full=source/'comparison';m=read(full/'manifest.json')
assert m['status']=='pass' and len(m['runs'])==270 and len(m['cases'])==30 and m['repeats']==3
assert all(not r['returncode'] and not r['ambient_cpu']['compiler_load_detected'] and not r['ambient_cpu']['observer_errors'] and r['process_group_empty_after_run'] and not r['remaining_engine_processes'] and not r['surviving_process_group'] for r in m['runs'])
for path,digest in m['file_hashes'].items():assert sha(Path(path))==digest,path
report.mkdir(parents=True,exist_ok=False);data=report/'data';data.mkdir()
save(data/'control-summary.json',result)
parity=module('parity',repo/'scripts/summarize-v07-protocol-parity.py')
for allowance,name in [(0,'summary-strict.json'),(3,'summary-mac-3pct.json')]:save(data/name,parity.summarize(full,allowance))
for name in ['inputs.json','host.json','builds.json','profile-summary.json','mobile-identity.json','summarize.py','compare-vmess.py','publish.py','verify.py','write-report.py']:
 shutil.copyfile(source/name,data/name)
files={}
with tarfile.open(report/'measurements.tar.gz','w:gz') as archive:
 def add(p,name):
  assert name not in files
  files[name]=sha(p);archive.add(p,arcname=name,recursive=False)
 def trial_group(folder,prefix):
  manifest=read(folder/'manifest.json');add(folder/'manifest.json',prefix+'/manifest.json')
  if (folder/'source.patch').exists():add(folder/'source.patch',prefix+'/source.patch')
  for r in manifest['runs']:
   trial=folder/r['output_relative'];p=trial/'result.json'
   if p.exists():add(p,prefix+'/'+r['output_relative']+'/result.json')
   if r.get('returncode'):
    for p in [trial/'stdout.log',trial/'stderr.log',folder/(r['output_relative']+'.log')]:
     if p.exists():add(p,prefix+'/'+str(p.relative_to(folder)))
  return manifest
 for group in [*controls,*memories,'comparison','profile-bounded','profile-runs']:
  folder=source/group;trial_group(folder,group)
  if (folder/'selection.json').exists():add(folder/'selection.json',group+'/selection.json')
  for p in sorted((folder/'attempts').glob('*/manifest.json')):trial_group(p.parent,group+'/attempts/'+p.parent.name)
  for p in sorted(folder.glob('*.sample.txt')):add(p,group+'/'+p.name)
 for name in ['builds.json','batch16.patch','batch2.patch','profile.py','held-memory.py','compare-vmess.py','confirm.sh','validate.sh','profile-summary.json','profile-build.log','batch16-build.log','batch2-build.log','proxy-tests.log','batch2-tests.log','clippy.log','final-proxy-tests.log','final-core-tests.log','final-clippy.log','xray-interop.log','xray-mux.log','singbox-interop.log','committed-rebuild.log','mobile-verification.log','ci-supply-chain-failure.log']:
  add(source/name,'investigation/'+name)
save(report/'evidence-index.json',{'archive':'measurements.tar.gz','archive_sha256':sha(report/'measurements.tar.gz'),'file_sha256':files,
 'excluded_from_performance':['profile-bounded: instrumented diagnostic traces only','profile-runs: failed oversized 1 GiB diagnostic probe; no performance conclusion','Any compiler-contaminated comparison attempts: every attempt and whole-case selection retained'],
 'scope':'All numeric results, manifests, source patches, diagnostic profiles and test logs. Generated credentials/configurations and executables remain local.'})
print('Archived',len(files),'evidence files:',report)

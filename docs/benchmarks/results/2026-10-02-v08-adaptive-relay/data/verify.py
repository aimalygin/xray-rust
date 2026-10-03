#!/usr/bin/env python3
"""Validate all archived members and reconstruct all completed measurements."""
import hashlib,importlib.util,json,tarfile,tempfile
from pathlib import Path
REPORT=Path(__file__).resolve().parents[1]
def load(p):return json.loads(p.read_text())
def sha(b):return hashlib.sha256(b).hexdigest()
inputs=load(REPORT/'data/inputs.json');index=load(REPORT/'evidence-index.json');archive=REPORT/index['archive']
assert sha(archive.read_bytes())==index['archive_sha256']
with tempfile.TemporaryDirectory(prefix='v08-adaptive-verify-') as tmp:
 root=Path(tmp)
 with tarfile.open(archive) as tar:
  members=tar.getmembers();assert len(members)==len(index['file_sha256']) and {m.name for m in members}==set(index['file_sha256'])
  for m in members:
   assert m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
   data=tar.extractfile(m).read();assert sha(data)==index['file_sha256'][m.name]
   p=root/m.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 identities={'baseline':inputs['baseline_sha256'],**{k:i['sha256'] for k,i in inputs['variants'].items()},'xray':inputs['xray']['sha256'],'singbox':inputs['singbox']['sha256']}
 for name,i in inputs['variants'].items():
  assert index['file_sha256'][i['patch']]==i['patch_sha256']
  identity=load(root/i['identity']);assert all(identity[k]==i[k] for k in ['sha256','base_commit','patch_sha256','compiler','build_args'])
 counts={}
 for name,meta in inputs['campaigns'].items():
  m=load(root/name/'manifest.json');assert len(m['runs'])==meta['runs'] and m['status']==meta['status']
  assert inputs['xray']['sha256'] in m['file_hashes'].values()
  for path,digest in m['file_hashes'].items():
   relative=('investigation/' if '/target/v08-quota-investigation/' in path else 'investigation/scripts/')+Path(path).name
   if relative in index['file_sha256']:assert index['file_sha256'][relative]==digest,(name,relative)
  for run in m['runs']:
   p=root/name/run['output_relative']/'result.json'
   if p.exists():
    r=load(p)
    if 'engine_sha256' in r:assert r['engine_sha256']==identities[meta['versions'][run['version']]],(name,run['version'],r['engine_sha256'])
  if m['status']=='pass':
   counts[meta['kind']]=counts.get(meta['kind'],0)+len(m['runs'])
   if meta['kind']=='held':
    for profile in m['arguments']['profile']:
     order={row['repeat']:load(root/name/row['output_relative']/'result.json')['client_order'] for row in m['runs'] if row['profile']==profile}
     for position in range(2):
      for version in ['baseline','candidate']:assert sum(o[position]==version for o in order.values())==m['repeats']//2
 spec=importlib.util.spec_from_file_location('summary',REPORT/'data/summarize.py');s=importlib.util.module_from_spec(spec);spec.loader.exec_module(s)
 assert s.run(root)==load(REPORT/'data/summary.json')
 validation=load(REPORT/'data/runtime-validation.json')
 for check in validation.values():
  if isinstance(check,dict) and 'archive_path' in check:
   assert check['passed'] and sha((root/check['archive_path']).read_bytes())==check['sha256']
 assert validation['source_matches_measured_patch']['patch_sha256']==inputs['variants']['chacha']['patch_sha256']
 spec=importlib.util.spec_from_file_location('intervals',REPORT/'data/intervals.py');intervals=importlib.util.module_from_spec(spec);spec.loader.exec_module(intervals)
 assert intervals.calculate(load(REPORT/'data/summary.json'))==load(REPORT/'data/intervals.json')['comparisons']
 print(json.dumps({'archive_members':len(members),'completed_trials':counts,'variants':len(inputs['variants']),'summaries_reconstructed':True},indent=2))

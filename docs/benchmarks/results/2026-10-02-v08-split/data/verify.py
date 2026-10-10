#!/usr/bin/env python3
"""Verify archived trials, frozen variant identities, balance and all summaries."""
import argparse,hashlib,importlib.util,json,subprocess,tarfile,tempfile
from pathlib import Path
REPORT=Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repo',type=Path);p.add_argument('--binary',type=Path);args=p.parse_args()
def read(p):return json.loads(p.read_text())
def sha(data):return hashlib.sha256(data).hexdigest()
index=read(REPORT/'evidence-index.json');inputs=read(REPORT/'data/inputs.json');archive=REPORT/index['archive']
assert sha(archive.read_bytes())==index['archive_sha256']
assert sha((REPORT/'data/shared-codec.patch').read_bytes())==inputs['variants']['v4']['patch_sha256']
restored=read(REPORT/'data/restored-runtime.json');assert restored['sha256']==inputs['baseline_sha256'] and restored['ordinary_release_restored_byte_identically']
if args.repo:
 subprocess.run(['git','-C',str(args.repo),'diff','--exit-code',inputs['baseline_runtime'],'--',':(glob)crates/*/src/**','Cargo.toml','Cargo.lock'],check=True,capture_output=True)
if args.binary:assert sha(args.binary.read_bytes())==inputs['baseline_sha256']
with tempfile.TemporaryDirectory(prefix='v08-split-verify-') as tmp:
 root=Path(tmp)
 with tarfile.open(archive) as tar:
  members=tar.getmembers();assert len(members)==len(index['file_sha256']) and {m.name for m in members}==set(index['file_sha256'])
  for m in members:
   assert m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
   data=tar.extractfile(m).read();assert sha(data)==index['file_sha256'][m.name]
   p=root/m.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 hashes={'baseline':inputs['baseline_sha256'],**{v:i['sha256'] for v,i in inputs['variants'].items()},**{v:inputs[v]['sha256'] for v in ['xray','singbox']}}
 for v,i in inputs['variants'].items():
  assert index['file_sha256'][i['patch']]==i['patch_sha256']
  identity=read(root/i['identity']);assert identity['candidate_sha256']==i['sha256'] and identity['source_commit']==i['base_commit']
 for campaign,mapping in inputs['campaign_variants'].items():
  m=read(root/campaign/'manifest.json');assert m['status']=='pass'
  expected=inputs['ordinary'].get(campaign,8);assert len(m['runs'])==expected
  assert inputs['xray']['sha256'] in m['file_hashes'].values()
  for path,digest in m['file_hashes'].items():
   relative='investigation/'+Path(path).name if path.endswith('/controls.py') else 'investigation/scripts/'+Path(path).name
   if relative in index['file_sha256']:assert digest==index['file_sha256'][relative]
  for run in m['runs']:
   r=read(root/campaign/run['output_relative']/'result.json');assert r['engine_sha256']==hashes[mapping[run['version']]]
  if campaign in inputs['held']:
   for profile in m['arguments']['profile']:
    orders={}
    for run in m['runs']:
     if run['profile']==profile:
      r=read(root/campaign/run['output_relative']/'result.json');orders[run['repeat']]=r['client_order']
    for position in range(2):
     for version in ['baseline','candidate']:assert sum(order[position]==version for order in orders.values())==m['repeats']//2
 rejected=read(root/'duplex-pilot-rejected-permission/manifest.json');assert rejected['status']=='fail' and len(rejected['runs'])==1
 assert rejected['runs'][0]['returncode']!=0
 spec=importlib.util.spec_from_file_location('summarize',REPORT/'data/summarize.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 assert module.run(root)==read(REPORT/'data/summary.json')
 print(json.dumps({'archive_members_verified':len(members),'ordinary_trials':sum(inputs['ordinary'].values()),'held_clients':8*len(inputs['held']),'rejected_before_payload':1,'variant_hashes_verified':len(inputs['variants']),'all_summaries_reconstructed':True},indent=2))

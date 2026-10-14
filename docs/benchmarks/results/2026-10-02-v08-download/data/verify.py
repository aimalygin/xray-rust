#!/usr/bin/env python3
"""Rehash archived evidence, reconstruct summaries and verify candidate identities."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo',type=Path,required=True);p.add_argument('--report',type=Path,required=True);p.add_argument('--rebuild',type=Path,required=True)
p.add_argument('--evidence-only',action='store_true',help='verify numeric/source evidence before CI finishes; does not mark CI successful')
a=p.parse_args();repo=a.repo.resolve();report=a.report.resolve()
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def read(p):return json.loads(p.read_text())
def module(name,p):
 s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
inputs=read(report/'data/inputs.json')
index=read(report/'evidence-index.json');archive=report/index['archive'];assert sha(archive)==index['archive_sha256']
with tempfile.TemporaryDirectory(prefix='v08-download-verify-',dir=repo/'target') as temp:
 extracted=Path(temp)
 with tarfile.open(archive) as tar:
  members=tar.getmembers();assert len(members)==len(index['file_sha256']) and {m.name for m in members}==set(index['file_sha256'])
  for m in members:
   assert m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
   content=tar.extractfile(m).read();assert hashlib.sha256(content).hexdigest()==index['file_sha256'][m.name]
   dest=extracted/m.name;dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(content)
 full=extracted/'comparison';m=read(full/'manifest.json');assert m['status']=='pass' and len(m['runs'])==270
 assert {c['profile'] for c in m['cases']}=={'vmess-aes128','vmess-chacha20','vmess-auto'}
 assert len(m['cases'])==30 and m['repeats']==3
 for c in m['cases']:
  selected=[r for r in m['runs'] if r['case']==c['id']]
  assert len(selected)==9 and {(r['version'],r['repeat']) for r in selected}=={(v,i) for v in ['candidate','xray','singbox'] for i in range(1,4)}
  origins={r['origin_manifest'] for r in selected};assert len(origins)==1
  parts=Path(next(iter(origins))).parts;position=parts.index('v08-download-investigation')
  original_path=extracted.joinpath(*parts[position+1:]);original=read(original_path)
  assert original['status']=='pass' and len(original['runs'])==9
  for r in selected:
   prior=next(x for x in original['runs'] if x['output_relative']==r['origin_output_relative'])
   assert prior['returncode']==0 and not prior['ambient_cpu']['compiler_load_detected'] and not prior['ambient_cpu']['observer_errors']
   assert prior['process_group_empty_after_run'] and not prior['remaining_engine_processes'] and not prior['surviving_process_group']
   stripped={k:v for k,v in r.items() if k not in ['origin_manifest','origin_output_relative']};stripped['output_relative']=r['origin_output_relative'];assert stripped==prior
   result_path=full/r['output_relative']/'result.json';assert sha(result_path)==sha(original_path.parent/r['origin_output_relative']/'result.json')
   result=read(result_path);assert result['status']=='pass' and result['engine_sha256']==m['file_hashes'][result['engine_binary']]
   n=result['connections']*result['iterations']*result['payload_size']
   assert result['bytes_sent']==(0 if result['traffic']=='download' else n)
   assert result['bytes_received']==(0 if result['traffic']=='upload' else n)
 parity=module('parity',repo/'scripts/summarize-v07-protocol-parity.py')
 for allowance,name in [(0,'summary-strict.json'),(3,'summary-mac-3pct.json')]:assert parity.summarize(full,allowance)==read(report/'data'/name)
 helper=module('controls',report/'data/summarize.py');actual={}
 for group,count in {'read16-controls':72,'four-controls':72,'combined-controls':54,'confirmation':60,'latency-controls':48,'latency-confirmation':10}.items():
  assert len(read(extracted/group/'manifest.json')['runs'])==count;actual[group]=helper.controls(extracted/group)
 for group,count in {'small-memory':18,'bulk-memory':18}.items():
  assert len(read(extracted/group/'manifest.json')['runs'])==count;actual[group]=helper.memory(extracted/group)
 assert actual==read(report/'data/control-summary.json')
 for group in ['read16-controls','four-controls','combined-controls','confirmation','latency-controls','latency-confirmation','small-memory','bulk-memory','libc']:
  manifest=read(extracted/group/'manifest.json')
  for version in {r['version'] for r in manifest['runs']}:
   identity=inputs[version]
   assert manifest['file_hashes'][identity['path']]==identity['sha256']
 for version in ['candidate','xray','singbox','harness']:
  identity=inputs[version];assert m['file_hashes'][identity['path']]==identity['sha256']
 for version in ['read16','four','combined']:
  assert sha(extracted/'investigation'/f'{version}.patch')==inputs[version]['patch_sha256']
 exact_patch=subprocess.check_output(['git','diff','--binary',inputs['source_commit'],inputs['candidate']['commit']],cwd=repo)
 assert exact_patch==(extracted/'investigation/combined.patch').read_bytes()
 for rejected in sorted(extracted.glob('*-rejected-*')):
  assert read(rejected/'manifest.json')['status']=='fail'
 census=module('census',report/'data/census-summary.py');assert census.summarize(extracted/'libc')==read(report/'data/libc-summary.json')
inputs=read(report/'data/inputs.json');builds=read(report/'data/inputs.json')
assert sha(a.rebuild)==inputs['candidate']['sha256']==inputs['combined']['sha256']
if a.evidence_only:
 result={'archive_files_verified':len(index['file_sha256']),'complete_case_selections_verified':30,'all_numeric_summaries_reproduced':True,'release_rebuild_sha256':sha(a.rebuild),'scope':'numeric archive and rebuild only; CI not checked'}
 (report/'data/verification-evidence.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,indent=2));raise SystemExit(0)
ci=read(report/'data/ci-run.json');mobile=read(report/'data/mobile-ci-run.json');sdk=read(report/'data/mobile-identity.json')
assert ci['headSha']==inputs['candidate']['commit'] and ci['event']=='workflow_dispatch' and ci['conclusion']=='success'
for name in ['rust','go-oracles','supply-chain','apple','android','controlled-network','rc-interop','host-hardening','fuzz-smoke']:
 assert next(j for j in ci['jobs'] if j['name']==name)['conclusion']=='success'
assert mobile['headSha']==sdk['commit'] and mobile['conclusion']=='success' and sdk['core_commit']==inputs['candidate']['commit']
assert subprocess.check_output(['git','rev-parse',inputs['candidate']['commit']+'^{tree}'],cwd=repo,text=True).strip()==inputs['candidate']['tree']
changed=subprocess.check_output(['git','diff','--name-only',builds['source_commit'],inputs['candidate']['commit']],cwd=repo,text=True).splitlines();assert changed==['crates/xray-proxy/src/record_buffer.rs','crates/xray-proxy/src/vmess/records.rs','crates/xray-proxy/src/vmess/stream.rs']
assert sha(report/'data/compare-vmess.py')==inputs['comparison_launcher_sha256']
result={'archive_files_verified':len(index['file_sha256']),'complete_case_selections_verified':30,'comparison_trials':270,'paired_control_trials':316,'held_memory_clients':36,'diagnostic_libc_trials':12,'all_numeric_summaries_reproduced':True,'release_rebuild_sha256':sha(a.rebuild),'runtime_commit':inputs['candidate']['commit'],'mobile_commit':sdk['commit'],'core_and_sdk_ci_pass':True}
(report/'data/verification.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');print(json.dumps(result,indent=2))

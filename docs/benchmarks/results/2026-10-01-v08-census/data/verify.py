#!/usr/bin/env python3
"""Reconstruct all census observations from hashed raw evidence."""
import argparse,hashlib,importlib.util,json,subprocess,tarfile,tempfile
from pathlib import Path
p=argparse.ArgumentParser(description=__doc__);p.add_argument('--repo',type=Path,required=True);p.add_argument('--report',type=Path,required=True);a=p.parse_args();repo=a.repo.resolve();report=a.report.resolve()
def read(p):return json.loads(p.read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
index=read(report/'evidence-index.json');builds=read(report/'data/builds.json')
with tempfile.TemporaryDirectory(prefix='v08-census-verify-',dir=repo/'target') as name:
 temp=Path(name)
 with tarfile.open(report/'measurements.tar.gz') as archive:
  members=archive.getmembers();assert len(members)==len(index) and {m.name for m in members}==set(index)
  for member in members:
   assert member.isfile() and not Path(member.name).is_absolute() and '..' not in Path(member.name).parts and member.size<8*1024*1024
   data=archive.extractfile(member).read();assert hashlib.sha256(data).hexdigest()==index[member.name]
   path=temp/member.name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(data)
 spec=importlib.util.spec_from_file_location('census_summary',temp/'summarize.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 summary=module.run(temp,temp/'recomputed.json');assert summary==read(report/'data/summary.json')
 assert summary['validated_runs']=={'kernel':36,'libc':36,'internal':12}
 for campaign in ['kernel','libc','internal']:
  manifest=read(temp/campaign/'manifest.json')
  for row in manifest['runs']:
   assert not row['ambient_cpu']['observer_errors'] and row['process_group_empty_after_run']
   result=read(temp/campaign/row['output_relative']/'result.json')
   assert result['engine_sha256']==manifest['file_hashes'][result['engine_binary']]
   assert Path(row['command'][0]).name=='census-harness'
  for file,digest in manifest['file_hashes'].items():
   # Binaries and measurement source must still match this local verification.
   assert sha(Path(file))==digest,file
 assert sha(temp/'interpose.c')==builds['sha256']['interpose.c']
 assert sha(temp/'instrumentation.patch')==builds['sha256']['instrumentation.patch']
 assert sha(temp/'census.rs')==builds['sha256']['census.rs']
 assert sha(temp/'task_info.rs')==builds['sha256']['task_info.rs']
 assert read(temp/'calibration.json')['status']=='pass'
 for file,digest in builds['original_file_sha256'].items():
  assert hashlib.sha256(subprocess.check_output(['git','show',builds['source_commit']+':'+file],cwd=repo)).hexdigest()==digest
  assert sha(repo/file)==digest,file
 subprocess.run(['git','apply','--check',str(temp/'instrumentation.patch')],cwd=repo,check=True)
normal=repo/'target/v08-comparison-driver/release/xray-rust'
assert sha(normal)=='784ce279f375de47332cfb3efa7dd90905767fdd226f8cf5364f27263eb3d937'
result={'status':'pass','archive_members_verified':len(index),'full_trials':84,'kernel_trials':36,'libc_trials':36,'internal_trials':12,'all_summaries_reproduced':True,'all_payload_and_internal_byte_totals_verified':True,'mach_conversion_verified':True,'frozen_inputs_unchanged':True,'production_source_unchanged':True,'restored_release_sha256':sha(normal),'runtime_commit':builds['runtime_commit'],'source_commit':builds['source_commit']}
(report/'data/verification.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))

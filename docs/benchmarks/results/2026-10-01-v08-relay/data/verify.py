#!/usr/bin/env python3
"""Rehash every archived member and reproduce comparison/control summaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import subprocess
import tempfile

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo',type=Path,required=True);p.add_argument('--report',type=Path,required=True)
p.add_argument('--rebuild',type=Path,required=True)
a=p.parse_args();repo=a.repo.resolve();report=a.report.resolve()
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def module(name,path):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
index=json.loads((report/'evidence-index.json').read_text());archive=report/index['archive']
assert sha(archive)==index['archive_sha256']
with tempfile.TemporaryDirectory(prefix='v08-relay-verify-',dir=repo/'target') as tmp:
    extracted=Path(tmp)
    with tarfile.open(archive) as tar:
        members=tar.getmembers()
        assert len(members)==len(index['file_sha256']) and {m.name for m in members}==set(index['file_sha256'])
        for member in members:
            assert member.isfile() and not Path(member.name).is_absolute() and '..' not in Path(member.name).parts
            content=tar.extractfile(member).read()
            assert hashlib.sha256(content).hexdigest()==index['file_sha256'][member.name]
            destination=extracted/member.name;destination.parent.mkdir(parents=True,exist_ok=True);destination.write_bytes(content)
    # Prove that accepted blocks are byte-for-byte selections of complete
    # original case blocks, and that quality selection did not splice repeats.
    verified_blocks=0
    for group in ['full','final-clean-controls','stack-controls']:
        m=json.loads((extracted/group/'manifest.json').read_text())
        for case in m['cases']:
            selected=[r for r in m['runs'] if r['case']==case['id']]
            origins={r['origin_manifest'] for r in selected}
            assert len(origins)==1
            origin=Path(next(iter(origins)))
            parts=origin.parts;position=parts.index('v08-relay-investigation')
            original_manifest=extracted.joinpath(*parts[position+1:])
            original=json.loads(original_manifest.read_text())
            original_runs=[r for r in original['runs'] if r['case']==case['id']]
            assert len(original_runs)==len(selected)
            assert {(r['version'],r['repeat']) for r in original_runs}=={(r['version'],r['repeat']) for r in selected}
            for run in selected:
                prior=next(r for r in original_runs if r['output_relative']==run['origin_output_relative'])
                assert not prior['ambient_cpu']['compiler_load_detected'] and not prior['ambient_cpu']['observer_errors']
                assert prior['process_group_empty_after_run'] and not prior['remaining_engine_processes'] and not prior['surviving_process_group']
                stripped={k:v for k,v in run.items() if k not in ['origin_manifest','origin_output_relative']}
                stripped['output_relative']=run['origin_output_relative']
                assert stripped==prior
                result=extracted/group/run['output_relative']/'result.json'
                raw=original_manifest.parent/run['origin_output_relative']/'result.json'
                assert result.exists()==raw.exists()
                if result.exists():assert sha(result)==sha(raw)
            verified_blocks+=1
    parity=module('parity',repo/'scripts/summarize-v07-protocol-parity.py')
    for allowance,name in [(0,'summary-strict.json'),(3,'summary-mac-3pct.json')]:
        assert parity.summarize(extracted/'full',allowance)==json.loads((report/'data'/name).read_text())
    controls=module('controls',report/'data/summarize.py')
    assert controls.summarize(extracted)==json.loads((report/'data/control-summary.json').read_text())
print(f'Verified {len(index["file_sha256"])} archived members, {verified_blocks} complete case selections and all numeric summaries.', flush=True)
inputs=json.loads((report/'data/inputs.json').read_text())
assert sha(a.rebuild)==inputs['candidate']['sha256']
ci=json.loads((report/'data/ci-run.json').read_text());mobile=json.loads((report/'data/mobile-ci-run.json').read_text())
assert ci['headSha']==inputs['candidate']['commit'] and ci['conclusion']=='success'
assert ci['event']=='workflow_dispatch'
assert mobile['headSha']==inputs['mobile_commit'] and mobile['conclusion']=='success'
fixture=json.loads((report/'data/fixture-ci.json').read_text())
assert fixture['headSha']=='9c16a656c4102b150b744f652e1286fe96203cec'
assert fixture['event']=='pull_request'
for name in ['rust','secrets']:
    job=next(j for j in fixture['jobs'] if j['name']==name)
    assert job['conclusion']=='success'
changed=subprocess.check_output(['git','diff','--name-only',inputs['candidate']['commit'],fixture['headSha']],cwd=repo,text=True).splitlines()
assert changed==['crates/xray-ffi/tests/ffi_tests.rs']

result={'archive_files_verified':len(index['file_sha256']),'complete_case_selections_verified':verified_blocks,'strict_and_3pct_summaries_reproduced':True,'control_summary_reproduced':True,'release_rebuild_sha256':sha(a.rebuild),'runtime_commit':ci['headSha'],'mobile_commit':mobile['headSha'],'core_and_sdk_ci_pass':True,'ffi_fixture_commit':fixture['headSha'],'ffi_fixture_rust_and_secrets_ci_pass':True}
(report/'data/verification.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps(result,indent=2))

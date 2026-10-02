#!/usr/bin/env python3
"""Verify all archived bytes and same-connection memory/resume evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import tarfile


def verify(report):
    index=json.loads((report/'evidence-index.json').read_text())
    with tarfile.open(report/'measurements.tar.gz','r:gz') as archive:
        contents={member.name:archive.extractfile(member).read() for member in archive if member.isfile()}
    assert len(contents)==len(index)
    assert set(contents)==set(index)
    for name,blob in contents.items():
        assert hashlib.sha256(blob).hexdigest()==index[name],name
    def read(name):return json.loads(contents[name])
    inputs=json.loads((report/'data/inputs.json').read_text())
    summary={}
    total=0
    for campaign,expected in [('footprint',18),('untouched-controls',8)]:
        manifest=read(campaign+'/manifest.json')
        assert manifest['status']=='pass' and len(manifest['runs'])==expected
        assert not manifest['ambient_cpu']['compiler_load_detected']
        assert not manifest['ambient_cpu']['observer_errors']
        source='held-footprint-source.py' if campaign=='footprint' else 'held-final-source.py'
        collector_digest=next(v for k,v in manifest['file_hashes'].items() if k.endswith('/scripts/run-v08-idle-buffer-controls.py'))
        assert collector_digest==index['investigation/'+source]
        for path,digest in manifest['file_hashes'].items():
            expected=next((v for k,v in inputs['frozen_files'].items() if path.endswith(k)),None)
            if expected is not None:assert digest==expected
        groups={}
        seen=set()
        for run in manifest['runs']:
            key=(run['profile'],run['version'],run['repeat'])
            assert key not in seen;seen.add(key)
            result=read(campaign+'/'+run['output_relative']+'/result.json')
            assert result['status']=='pass' and not result['remaining_engine_processes']
            assert all(result[k]==run[k] for k in ('version','profile','repeat'))
            assert result['connections']==512 and result['warmup_bytes']==1048576
            assert result['checked_bytes_each_direction']==512*(3*1048576+2*1024)
            binary=dict(item.split('=',1) for item in manifest['arguments']['binary'])[run['version']]
            digest=next(v for k,v in manifest['file_hashes'].items() if k.endswith(binary))
            assert result['engine_sha256']==digest
            phases={p['phase']:p for p in result['phases']}
            assert len(phases)==8
            for cycle in range(2):
                assert len(phases[f'first-request-{cycle}']['latency_us'])==512
                assert len(phases[f'idle-{cycle}']['samples'])==4
                assert phases[f'idle-{cycle}']['unix']-phases['warm' if cycle==0 else 'resumed-bulk-0']['unix']>=10.9
            groups.setdefault((run['profile'],run['version']),[]).append(phases)
            total+=1
        for (profile,version),rows in groups.items():
            assert len(rows)==manifest['repeats']
            values={}
            for phase in ['warm','idle-0','resumed-bulk-0','idle-1','resumed-bulk-1']:
                values[phase+'_footprint_mib']=statistics.median(r[phase]['footprint_kib']/1024 for r in rows)
            for cycle in range(2):
                before='warm' if cycle==0 else 'resumed-bulk-0'
                values[f'idle-{cycle}_cpu_ms']=statistics.median(r[f'idle-{cycle}']['cpu_ms']-r[before]['cpu_ms'] for r in rows)
            summary[campaign+'/'+profile+'/'+version]=values
    pilot=read('held/manifest.json')
    assert pilot['status']=='fail' and len(pilot['runs'])==8
    published=json.loads((report/'data/verified-summary.json').read_text())
    assert summary==published
    inputs=json.loads((report/'data/inputs.json').read_text())
    for variant in ('trim','shrink','untouched'):
        path='investigation/'+variant+'.patch'
        assert index[path]==inputs['frozen_files']['target/v08-idle-buffer-investigation/'+variant+'.patch']
    return {'status':'pass','members':len(contents),'complete_clients':total,'pilot_clients_excluded':8,
            'verified_bytes_each_direction':total*512*(3*1048576+2*1024),'summary_reconstructed':True}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--repo',type=Path)
    parser.add_argument('--binary',type=Path)
    args=parser.parse_args()
    result=verify(args.report)
    inputs=json.loads((args.report/'data/inputs.json').read_text())
    if args.repo:
        subprocess.run(['git','-C',str(args.repo),'diff','--exit-code',inputs['baseline_runtime'],
                        '--','crates','Cargo.toml','Cargo.lock'],check=True,capture_output=True)
        result['runtime_source_unchanged']=True
    if args.binary:
        digest=hashlib.sha256(args.binary.read_bytes()).hexdigest()
        assert digest==inputs['frozen_files']['target/v08-idle-buffer-investigation/baseline']
        result['restored_release_matches_baseline']=True
        result['restored_sha256']=digest
    print(json.dumps(result,indent=2))

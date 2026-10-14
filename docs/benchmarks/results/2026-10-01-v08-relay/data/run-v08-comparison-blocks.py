#!/usr/bin/env python3
"""Collect complete case blocks, retrying only observed compiler contamination.

Every rejected attempt is kept. Protocol errors, leaks and observation errors
are never retried. Selection is by environment/completeness, never performance.
"""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('comparison', ROOT / 'scripts/run-v08-protocol-comparison.py')
c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)


def quality(runs):
    """Error has priority over contamination; never hide a real failed trial."""
    for r in runs:
        if (r['returncode'] or not r['process_group_empty_after_run'] or r['remaining_engine_processes']
                or r['surviving_process_group'] or r['ambient_cpu']['observer_errors']):
            return 'error'
    return 'contaminated' if any(r['ambient_cpu']['compiler_load_detected'] for r in runs) else 'clean'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mode', choices=['controls', 'full'], required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--inputs', type=Path)
    p.add_argument('--binary', action='append', default=[])
    p.add_argument('--reference', type=Path); p.add_argument('--harness', type=Path)
    p.add_argument('--reuse', type=Path, help='retain only complete, clean case blocks from this control campaign')
    a = p.parse_args(); out = a.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    full = a.mode == 'full'
    if full:
        assert a.inputs and not a.binary and not a.reuse
        base_args = ['--inputs', str(a.inputs.resolve())]
        available = c.cases(c.PROFILES); versions = ['candidate', 'xray', 'singbox']
        identities = json.loads(a.inputs.read_text())
        binaries = {v: Path(identities[v]['path']).resolve() for v in versions + ['harness']}
    else:
        assert a.binary and a.reference and a.harness
        binaries = {name: Path(path).resolve() for name, path in (b.split('=', 1) for b in a.binary)}
        versions = list(binaries)
        assert len(versions) == len(a.binary)
        base_args = [arg for name, path in binaries.items() for arg in ['--binary', name+'='+str(path)]]
        base_args += ['--reference', str(a.reference.resolve()), '--harness', str(a.harness.resolve())]
        binaries.update(reference=a.reference.resolve(), harness=a.harness.resolve())
        available = [case for case in c.cases(['ss2022-aes128','ss2022-chacha20','vmess-aes128','vmess-chacha20'])
                     if case['traffic'] in ['upload','download','full-duplex']]
    hashes = {str(path): c.bench.sha(path) for path in binaries.values()}
    executable = ROOT / 'scripts' / ('run-v08-protocol-comparison.py' if full else 'run-v08-cpu-controls.py')
    selection = {'policy': __doc__, 'started_unix': time.time(), 'blocks': [], 'reused_from': str(a.reuse) if a.reuse else None}
    aggregate = None; accepted = []
    reuse = json.loads((a.reuse/'manifest.json').read_text()) if a.reuse else None
    if reuse:
        assert reuse['repeats'] == 3 and quality(reuse['runs']) != 'error'
        assert all(reuse['file_hashes'].get(path) == digest for path,digest in hashes.items())
    patch = c.bench.command(['git','diff','--binary','HEAD'], ROOT) + '\n'
    (out/'source.patch').write_text(patch)

    def accept(folder, m, runs, case):
        nonlocal aggregate
        assert {(r['version'],r['repeat']) for r in runs} == {(v,i) for v in versions for i in range(1,4)}
        assert len(runs) == len(versions)*3
        assert all(m['file_hashes'].get(path)==digest for path,digest in hashes.items())
        if aggregate is None: aggregate = copy.deepcopy(m)
        for r in runs:
            r = copy.deepcopy(r)
            origin = r['output_relative']; target = 'selected/'+origin
            result = folder/origin/'result.json'
            destination = out/target; destination.mkdir(parents=True,exist_ok=False)
            if result.exists(): shutil.copyfile(result, destination/'result.json')
            for name in ['stdout.log','stderr.log']:
                if r['returncode'] and (folder/origin/name).exists(): shutil.copyfile(folder/origin/name,destination/name)
            r.update(output_relative=target, origin_manifest=str(folder/'manifest.json'), origin_output_relative=origin)
            accepted.append(r)
        aggregate.update(cases=available, runs=accepted, repeats=3, status='running',
                         block_collection=True, file_hashes={**aggregate['file_hashes'], **hashes},
                         source_patch_sha256=c.bench.sha(out/'source.patch'))
        aggregate['file_hashes'][str(Path(__file__).resolve())] = c.bench.sha(Path(__file__).resolve())
        c.bench.save(out/'manifest.json',aggregate)
        selection['blocks'].append({'case':case['id'],'selected_manifest':str(folder/'manifest.json'),'accepted_runs':len(runs)})
        c.bench.save(out/'selection.json',selection)

    try:
        for case in available:
            prior = [r for r in reuse['runs'] if r['case']==case['id']] if reuse else []
            if len(prior)==len(versions)*3 and quality(prior)=='clean':
                accept(a.reuse,reuse,prior,case); print('reused',case['id'],flush=True); continue
            for attempt in range(1,4):
                quiet_deadline=time.monotonic()+300
                while c.ambient()['compiler_load_detected']:
                    if time.monotonic()>quiet_deadline: raise RuntimeError('compiler did not become idle; accepted blocks retained')
                    time.sleep(5)
                assert not c.followup.inventory(binaries.values()), 'engine already running'
                folder=out/'attempts'/f"{case['id']}-{attempt}";folder.parent.mkdir(exist_ok=True)
                log=folder.with_suffix('.log')
                with log.open('w') as stream:
                    status=subprocess.run([sys.executable,str(executable),*base_args,'--case-id',case['id'],'--repeats','3','--output',str(folder)],cwd=ROOT,stdout=stream,stderr=subprocess.STDOUT).returncode
                manifest_path=folder/'manifest.json'
                if not manifest_path.exists():
                    raise RuntimeError(f'collector failed before a manifest; see {log}')
                m=json.loads(manifest_path.read_text());q=quality(m['runs'])
                selection['blocks'].append({'case':case['id'],'attempt_manifest':str(manifest_path),'quality':q,'collector_returncode':status})
                c.bench.save(out/'selection.json',selection)
                if q=='contaminated':
                    print('retry complete block after compiler overlap:',case['id'],attempt,flush=True); continue
                if q=='clean' and (status or m.get('status')!='pass'):
                    raise RuntimeError(f'collector validation failed: {manifest_path}')
                if q=='error' and any(r['ambient_cpu']['compiler_load_detected'] for r in m['runs']):
                    raise RuntimeError(f'failure overlaps compilation; retained without retry: {manifest_path}')
                # Full comparison keeps genuine completed failures; controls stop
                # on their first error. Neither path silently retries errors.
                if q=='error' and (not full or len(m['runs'])!=len(versions)*3):
                    raise RuntimeError(f'failed trial retained at {manifest_path}')
                if len(m['runs'])!=len(versions)*3:
                    raise RuntimeError(f'incomplete block without compiler overlap: {manifest_path}')
                accept(folder,m,m['runs'],case)
                print('accepted',case['id'],q,flush=True); break
            else: raise RuntimeError('three contaminated attempts; evidence retained')
        assert all(c.bench.sha(Path(path))==digest for path,digest in hashes.items())
        aggregate.update(status='pass' if all(not r['returncode'] for r in accepted) else 'fail', finished_unix=time.time())
        c.bench.save(out/'manifest.json',aggregate)
    finally:
        selection['finished_unix']=time.time();c.bench.save(out/'selection.json',selection)
    if aggregate['status']!='pass':raise SystemExit(1)


if __name__=='__main__':main()

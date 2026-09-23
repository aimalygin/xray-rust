#!/usr/bin/env python3
"""Compare both protocols through a common frozen SOCKS workload driver.

References use exec-only config launchers, so RSS/CPU sample the real client PID.
Never overlap this collector with compilation, tests, or another benchmark.
"""
import argparse
import contextlib
import copy
import importlib.util
import json
import os
from pathlib import Path
import platform
import time

SPEC = importlib.util.spec_from_file_location('delayed', Path(__file__).with_name('run-v07-delayed-protocol.py'))
delayed = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(delayed)
bench = delayed.bench
followup = delayed.followup


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--harness', type=Path)
    p.add_argument('--candidate-workers', type=int, choices=[1,2,4,6,8,12])
    p.add_argument('--reference-go-workers', type=int, choices=[1,2,4,6,8,12], help='explicit GOMAXPROCS control for prepared Go reference clients')
    p.add_argument('--engine', action='append', help='label=/absolute/binary; overrides defaults')
    p.add_argument('--protocol', choices=['hysteria2','wireguard'], action='append')
    p.add_argument('--traffic', choices=['upload','download','full-duplex','tcp-latency','udp'], action='append')
    p.add_argument('--connections', type=int, choices=[1,8,16], action='append')
    p.add_argument('--repeats', type=int, default=5)
    p.add_argument('--bulk-mib', type=int, default=32)
    p.add_argument('--echo-iterations', type=int, default=1000)
    p.add_argument('--one-way-ms', type=float, default=0)
    p.add_argument('--rate-mbps', type=float, default=100)
    p.add_argument('--smoke', action='store_true')
    a = p.parse_args()
    if not 1 <= a.repeats <= 20 or not 1 <= a.bulk_mib <= 512 or not 1 <= a.echo_iterations <= 10000 or not 0 <= a.one_way_ms <= 500 or not 1 <= a.rate_mbps <= 1000:
        raise ValueError('invalid bounded workload')
    for variable in ['TOKIO_WORKER_THREADS','GOMAXPROCS']:
        os.environ.pop(variable,None)
    root=a.root.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    engines=dict(x.split('=',1) for x in a.engine) if a.engine else {
        'candidate':str((root/'bin/rust-before').resolve()),'xray':str(root/'bin/xray-client'),
        'singbox':str(root/'bin/singbox-client'),'native':str(root/'bin/native-client')}
    if a.engine and len(engines)!=len(a.engine):raise ValueError('duplicate engine labels')
    # Use the same canonical argv path for process cleanup and result identity,
    # including caller-supplied symlinks to a frozen executable.
    engines={name:str(Path(path).resolve(strict=True)) for name,path in engines.items()}
    harness=(a.harness or root/'bin/protocol-bench').resolve();reference=(root/'bin/xray-core').resolve()
    files=[harness,reference,Path(__file__),Path(delayed.__file__),Path(followup.__file__),Path(bench.__file__),bench.ROOT/'scripts/run-v07-apple-protocol-fixture.py']
    real_binaries=[harness,reference]
    binary_builds={}
    for name,path in engines.items():
        exe=Path(path).resolve(strict=True);files.append(exe);real_binaries.append(exe)
        build=exe.parent/'build.json'
        if build.exists():
            files.append(build)
            binary_builds[name]={'path':str(build),'sha256':bench.sha(build),'metadata':json.loads(build.read_text())}
            patch=exe.parent/'source.patch'
            if patch.exists():
                files.append(patch)
                binary_builds[name]['source_patch']={'path':str(patch),'sha256':bench.sha(patch)}
        spec=Path(path+'.json')
        if spec.exists():
            files.append(spec)
            for binary in json.loads(spec.read_text())['binaries'].values():
                binary=Path(binary).resolve(strict=True);files.append(binary);real_binaries.append(binary)
    if followup.inventory(real_binaries):raise RuntimeError('benchmark processes already running')
    cases=[]
    for template in bench.protocol_cases('new',a.smoke):
        if template['path']!='socks' or template['connections']!=1 or template['protocol'] not in (a.protocol or ['hysteria2','wireguard']) or template['traffic'] not in (a.traffic or ['upload','download','full-duplex','tcp-latency','udp']):continue
        for count in a.connections or [1,8]:
            case=copy.deepcopy(template);case.update(connections=count,id=template['id'].rsplit('-',1)[0]+f'-{count}')
            case['iterations']=(10 if a.smoke else a.echo_iterations) if case['traffic'] in ('udp','tcp-latency') else (4 if a.smoke else a.bulk_mib*16)
            cases.append(case)
    hashes={str(f):bench.sha(f) for f in files}
    (out/'source.patch').write_text(bench.command(['git','diff','--binary','HEAD'],bench.ROOT)+'\n')
    manifest=dict(schema_version=1,suite='new',smoke=a.smoke,repeats=1 if a.smoke else a.repeats,cases=cases,
        platform=platform.platform(),source_commit=bench.command(['git','rev-parse','HEAD'],bench.ROOT),source_patch_sha256=bench.sha(out/'source.patch'),
        file_hashes=hashes,reference_commit=bench.REFERENCE,versions={k:{'binary':v,'engine_sha256':bench.sha(v)} for k,v in engines.items()},
        binary_builds=binary_builds,
        source_provenance_note='source_commit/source.patch describe the collector workspace; each frozen executable is identified by SHA256 and its adjacent binary_builds metadata when available',
        one_way_delay_ms=a.one_way_ms,link_mbps_per_direction=a.rate_mbps if a.one_way_ms else None,
        process_accounting='prepared real binary launched directly; one verified TCP echo before steady measurements; startup and lifetime CPU retained separately',
        warmup=True,candidate_workers=a.candidate_workers,reference_go_workers=a.reference_go_workers,
        target='strictly lower RSS; no lower throughput, higher latency/CPU or additional failures; uncertainty is reported separately, never converted into a pass',
        started_unix=time.time(),runs=[])
    bench.save(out/'manifest.json',manifest)
    for case in cases:
        for repeat in range(1,manifest['repeats']+1):
            labels=list(engines);offset=(repeat-1)%len(labels);labels=labels[offset:]+labels[:offset]
            if repeat%2==0:labels.reverse()
            for version in labels:
                ident=f"{case['id']}-{version}-{repeat}"
                with bench.fixture(reference,out/(ident+'-server')) as configs:
                    config=copy.deepcopy(configs[case['protocol']]);settings=config['outbounds'][0]['settings']
                    os.environ['BENCH_REFERENCE_CERT']=str(out/(ident+'-server')/'fixture/tls.crt')
                    if case['protocol']=='wireguard':
                        address,port=settings['peers'][0]['endpoint'].rsplit(':',1);settings['noKernelTun']=True
                    else:address,port=settings['address'],settings['port']
                    relay_context=delayed.Relay((address,int(port)),a.one_way_ms/1000,a.rate_mbps) if a.one_way_ms else contextlib.nullcontext()
                    with relay_context as relay:
                        if relay:
                            if case['protocol']=='wireguard':settings['peers'][0]['endpoint']=f'127.0.0.1:{relay.port}'
                            else:settings.update(address='127.0.0.1',port=relay.port)
                        request={k:case[k] for k in ['path','traffic','connections','iterations','payload_size']}
                        prepared=Path(engines[version]+'.json').exists()
                        client_env={'GOMAXPROCS':str(a.reference_go_workers)} if prepared and a.reference_go_workers else {}
                        if version=='candidate' and a.candidate_workers:client_env['TOKIO_WORKER_THREADS']=str(a.candidate_workers)
                        request.update(binary=engines[version],config=config,output=str(out/ident), warmup=True, prepare_client=prepared, client_env=client_env);req=out/(ident+'.json');bench.save(req,request)
                        result=bench.execute([str(harness),'protocol-run',str(req)],out/(ident+'.log'),bench.ROOT)
                    if relay:result['relay']=dict(relay.stats)
                result.update(case=case['id'],version=version,repeat=repeat,output_relative=ident,remaining_engine_processes=followup.inventory(real_binaries))
                manifest['runs'].append(result);bench.save(out/'manifest.json',manifest)
                print(ident,result['returncode'],round(result['seconds'],2),flush=True)
                if result['remaining_engine_processes'] or result['surviving_process_group'] or (relay and (relay.stats['error'] or relay.stats['dropped'])):raise RuntimeError('invalid collection: leaked process or delay relay error/drop')
                if a.smoke and result['returncode']:raise RuntimeError('smoke failed; fix fixture before measuring')
    if any(bench.sha(path)!=digest for path,digest in hashes.items()):raise RuntimeError('input changed during collection')
    manifest.update(finished_unix=time.time(),status='pass' if all(x['returncode']==0 for x in manifest['runs']) else 'fail');bench.save(out/'manifest.json',manifest)
    if manifest['status']!='pass':raise SystemExit(1)


if __name__=='__main__':main()

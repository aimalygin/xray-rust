#!/usr/bin/env python3
"""Use the pinned Go client to isolate eight-flow WireGuard upload/full-duplex failures.

Same generic driver, fresh pinned reference server, same payload and repetitions.
The control uses a userspace stack and never creates host TUN interfaces/routes.
"""
import argparse
import importlib.util
import json
import platform
from pathlib import Path
import time

SOURCE=Path(__file__).resolve().with_name('run-v07-performance.py')
spec=importlib.util.spec_from_file_location('performance',SOURCE)
bench=importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--harness',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    root=args.root.resolve();harness=args.harness.resolve();output=args.output.resolve()
    if bench.campaign_processes(root):raise RuntimeError('campaign processes already running')
    output.mkdir(parents=True,exist_ok=False)
    binary=root/'bin/xray-core'
    cases=[c for c in bench.protocol_cases('new',False) if c['id'] in ('wireguard-socks-upload-8','wireguard-socks-full-duplex-8')]
    manifest={'schema_version':1,'suite':'new','smoke':False,'diagnostic':True,'repeats':5,
        'purpose':'Reference client isolation control for the same eight-flow upload and full-duplex workloads',
        'cases':cases,'started_unix':time.time(),'platform':platform.platform(),
        'harness_sha256':bench.sha(harness),'collector_sha256':bench.sha(__file__),
        'shared_collector_sha256':bench.sha(SOURCE),'reference_sha256':bench.sha(binary),
        'reference_commit':bench.REFERENCE,'fixture_policy':'fresh reference and client per run; userspace only',
        'cleanup_policy':'RAII kill/wait and process-group/global inventory verification',
        'preflight_campaign_processes':[],
        'versions':{'reference-client':{'commit':bench.REFERENCE,'engine_sha256':bench.sha(binary)}},'runs':[]}
    bench.save(output/'manifest.json',manifest)
    for case in cases:
        for repeat in range(1,6):
            identifier=f"{case['id']}-reference-client-{repeat}"
            target=output/identifier
            with bench.fixture(binary,output/f'{identifier}-server') as configs:
                config=configs['wireguard']
                config['outbounds'][0]['settings']['noKernelTun']=True
                request={k:case[k] for k in ['path','traffic','connections','iterations','payload_size']}
                request.update(binary=str(binary),config=config,output=str(target))
                request_path=output/f'{identifier}.json';bench.save(request_path,request)
                result=bench.execute([str(harness),'protocol-run',str(request_path)],output/f'{identifier}.log',root/'candidate')
            remaining=bench.campaign_processes(root)
            result.update(case=case['id'],version='reference-client',repeat=repeat,output=str(target),
                          output_relative=identifier,remaining_engine_processes=remaining)
            manifest['runs'].append(result);bench.save(output/'manifest.json',manifest)
            print(identifier,result['returncode'],f"{result['seconds']:.1f}s",flush=True)
            if remaining or result['surviving_process_group']:raise RuntimeError('control process cleanup failed')
    assert bench.sha(harness)==manifest['harness_sha256']
    assert bench.sha(binary)==manifest['reference_sha256']
    assert bench.sha(SOURCE)==manifest['shared_collector_sha256']
    assert bench.sha(__file__)==manifest['collector_sha256']
    manifest['finished_unix']=time.time()
    manifest['status']='pass' if all(r['returncode']==0 for r in manifest['runs']) else 'fail'
    bench.save(output/'manifest.json',manifest)
    if manifest['status']!='pass':raise SystemExit(1)


if __name__=='__main__':main()

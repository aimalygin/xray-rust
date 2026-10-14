#!/usr/bin/env python3
"""Bounded VMess census; instrumented observations never counted as speed gains."""
import argparse,copy,hashlib,importlib.util,json,os,shutil,time
from pathlib import Path
ROOT=Path('/Users/antonmalygin/xray-rust');BASE=ROOT/'target/v08-census-investigation'
spec=importlib.util.spec_from_file_location('comparison',ROOT/'scripts/run-v08-protocol-comparison.py');c=importlib.util.module_from_spec(spec);spec.loader.exec_module(c)
def main():
    p=argparse.ArgumentParser();p.add_argument('--campaign',choices=['kernel','libc','internal'],required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--repeats',type=int,default=3);p.add_argument('--smoke',action='store_true');a=p.parse_args()
    for v in ['GOMAXPROCS','GOGC','GOMEMLIMIT','TOKIO_WORKER_THREADS','DYLD_INSERT_LIBRARIES','XRAY_CENSUS_MAP']:os.environ.pop(v,None)
    os.umask(0o077)
    frozen=json.loads((ROOT/'docs/benchmarks/results/2026-10-01-v08-batch/data/inputs.json').read_text())
    paths={k:Path(frozen[k]['path']) for k in ['candidate','xray','singbox']}
    for k,v in paths.items():assert c.bench.sha(v)==frozen[k]['sha256'],k
    harness=BASE/'census-harness'
    out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    launchers={}
    for k in ['xray','singbox']:
        path=out/(k+'-client');shutil.copyfile(ROOT/'scripts/v08-reference-client.py',path);path.chmod(0o700);c.bench.save(Path(str(path)+'.json'),{'mode':k,'binaries':{n:str(paths[n]) for n in ['xray','singbox']}});launchers[k]=path
    if a.campaign=='internal':paths['candidate']=BASE/'internal-client'
    versions=['candidate'] if a.campaign=='internal' else ['candidate','xray','singbox']
    cases=[x for x in c.cases(['vmess-aes128']) if x['traffic'] in ['upload','download']]
    if a.smoke:
        cases=[cases[0]]
        for x in cases:x['iterations']=64
    active=[*paths.values(),harness]
    if c.ambient()['compiler_load_detected'] or c.followup.inventory(active):raise RuntimeError('busy before census')
    manifest={'campaign':a.campaign,'diagnostic_only':True,'smoke':a.smoke,'repeats':a.repeats,'cases':cases,'versions':versions,'started_unix':time.time(),'scope':'OS snapshots exclude warmup; include setup and cleanup/settle. Internal drop counters include warmup. libc entry counts are not an exhaustive syscall trace. No instrumented timing claim.','file_hashes':{str(v):c.bench.sha(v) for v in [*active,BASE/'libcensus.dylib',Path(__file__),ROOT/'scripts/v08-reference-client.py']},'runs':[]}
    try:
        for index,case in enumerate(cases):
            for repeat in range(1,a.repeats+1):
                order=versions[(index+repeat-1)%len(versions):]+versions[:(index+repeat-1)%len(versions)]
                if repeat%2==0:order.reverse()
                with c.fixture(paths['xray'],out/f"{case['id']}-server-{repeat}",case['profile']) as (config,pid):
                    for version in order:
                        name=f"{case['id']}-{version}-{repeat}";dest=out/name
                        request={k:case[k] for k in ['path','traffic','connections','iterations','payload_size']}
                        request.update(binary=str(launchers.get(version,paths[version])),config=copy.deepcopy(config),output=str(dest),warmup=True,prepare_client=version!='candidate',client_preface=True)
                        if a.campaign=='libc':request['client_env']={'DYLD_INSERT_LIBRARIES':str(BASE/'libcensus.dylib'),'XRAY_CENSUS_MAP':str(dest/'calls.map')}
                        req=out/(name+'.json');c.bench.save(req,request)
                        result=c.measured_execute([str(harness),'protocol-run',str(req)],out/(name+'.log'))
                        remaining=[s for s in c.followup.inventory(active) if int(s.split(None,1)[0])!=pid]
                        result.update(case=case['id'],version=version,repeat=repeat,output_relative=name,remaining_engine_processes=remaining,client_order=order)
                        manifest['runs'].append(result);c.bench.save(out/'manifest.json',manifest)
                        print(a.campaign,name,result['returncode'],round(result['seconds'],2),flush=True)
                        if result['returncode'] or remaining or result['surviving_process_group'] or result['ambient_cpu']['compiler_load_detected']:raise RuntimeError('failed or contaminated census; retained')
                        report=json.loads((dest/'result.json').read_text());assert report['status']=='pass' and report['diagnostic_only']
                        for snapshot in report['process_census'].values():
                            assert 'error' not in snapshot['os'],snapshot
                            if a.campaign=='libc':assert snapshot['interpose'] and snapshot['interpose'][0]==0x58524159434e5331,snapshot
                if c.followup.inventory(active):raise RuntimeError('surviving process')
        for file,digest in manifest['file_hashes'].items():assert c.bench.sha(Path(file))==digest,file
        manifest['status']='pass'
    except BaseException:
        manifest['status']='fail';raise
    finally:
        manifest['finished_unix']=time.time();c.bench.save(out/'manifest.json',manifest)
if __name__=='__main__':main()

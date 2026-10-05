#!/usr/bin/env python3
import json,time
import drive as d
import importlib.util
sp=importlib.util.spec_from_file_location('resource',__import__('pathlib').Path(__file__).with_name('resources-all.py'));r=importlib.util.module_from_spec(sp);sp.loader.exec_module(r)
def thread_sample():
    pid=d.shell('pidof',d.HOST).strip()
    assert pid.isdigit()
    cmd=f'for f in /proc/{pid}/task/*/stat; do cat "$f"; done'
    out={}
    for line in d.shell('run-as',d.HOST,'sh','-c',cmd).splitlines():
        if ') ' not in line:continue
        prefix,fields=line.rsplit(')',1);fields=fields.split()
        tid,name=prefix.split(' (',1)
        out[tid]={'name':name,'ticks':int(fields[11])+int(fields[12])}
    return out
try:
    env=json.loads((d.ROOT/'fixture3/v07-probe.json').read_text())
    for backend in ('packet-pump','file-descriptor'):
        d.host_stop();d.install_profile(env['cases'][0])
        d.command(d.HOST,'connect',('--es','tun-backend',backend,'--ez','probe-only','true'))
        s=d.wait_status(d.HOST,lambda s:s.get('state') in ('running','failed','fatal'));assert s['state']=='running'
        time.sleep(3)
        a=r.sample();ta=thread_sample();time.sleep(10);tb=thread_sample();b=r.sample()
        busy=[{'name':v['name'],'cpuSeconds':(v['ticks']-ta[k]['ticks'])/100} for k,v in tb.items() if k in ta]
        d.emit('idle-cpu-control',backend=backend,before=a,after=b,threads=sorted(busy,key=lambda x:-x['cpuSeconds']))
        d.host_stop()
finally:
    d.host_stop();d.log_snapshot('idle-logcat.log')


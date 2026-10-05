#!/usr/bin/env python3
import json
import os
import re
import statistics
import time
import drive as d

LIMITS={'rssGrowthBytes':8*1024*1024,'rssGrowthFraction':0.25,'threadGrowth':4,
        'cycles':2,'httpAttempts':240,'udpAttempts':480,'workers':32,'settleSeconds':20}

def sample():
    pid=d.shell('pidof',d.HOST).strip()
    if not pid.isdigit(): raise RuntimeError('missing unique host process')
    raw=d.shell('run-as',d.HOST,'sh','-c',f'cat /proc/{pid}/stat /proc/{pid}/status')
    lines=raw.splitlines();stat=lines[0].rsplit(')',1)[1].split()
    fields=dict(x.split(':',1) for x in lines[1:] if ':' in x)
    return {'time':time.time(),'pid':int(pid),'cpuTicks':int(stat[11])+int(stat[12]),
            'startTicks':int(stat[19]),'rssBytes':int(fields['VmRSS'].split()[0])*1024,
            'threads':int(fields['Threads'].strip())}

def settled():
    samples=[]
    time.sleep(LIMITS['settleSeconds']-5)
    for _ in range(5):
        samples.append(sample());time.sleep(1)
    return samples

def run():
    d.emit('resources-start',limits=LIMITS,scope='probe-only',interpretation='bounded request stress, not throughput or energy benchmark')
    (d.ROOT/'resource-limits.json').write_text(json.dumps(LIMITS,indent=2)+'\n')
    hz=int(d.shell('getconf','CLK_TCK').strip())
    env=json.loads((d.ROOT/'fixture3/v07-probe.json').read_text())
    cycle_id=400
    for case in env['cases']:
        if case['caseId']=='vmess-auto': continue
        for backend in ('file-descriptor','packet-pump'):
            identity={'case':case['caseId'],'backend':backend,'runId':'all-cipher-diagnostic'}
            d.emit('resource-case-start',**identity)
            cycles=[]
            traffic_ok=True
            try:
                d.host_stop();d.install_profile(case)
                d.command(d.HOST,'connect',('--es','tun-backend',backend,'--ez','probe-only','true'))
                started=d.wait_status(d.HOST,lambda s:s.get('state') in ('running','failed','fatal'))
                assert started['state']=='running' and started.get('detail')=='probe-only',started
                d.emit('resource-warmup',**identity,status=d.traffic(env,'ipv4',2))
                baseline=sample()
                for cycle in (1,2):
                    cycle_id+=1
                    extra=('--es','http-url',f'http://198.51.100.7:{env["tcpPort"]}/v08-probe',
                           '--es','udp-host','198.51.100.7','--ei','udp-port',str(env['udpPort']),
                           '--el','interval-seconds','60')
                    d.command(d.PROBE,'reset');d.command(d.PROBE,'start',extra)
                    d.wait_status(d.PROBE,lambda s:int(s.get('udp-passed',0))>=1)
                    before=sample()
                    probe_pid=d.shell('pidof',d.PROBE).strip()
                    if not probe_pid.isdigit(): raise RuntimeError('missing unique probe process')
                    d.command(d.PROBE,'stress',('--ei','stress-cycle',str(cycle_id),
                        '--ei','stress-http-attempts','240','--ei','stress-udp-attempts','480',
                        '--ei','stress-concurrency','32'))
                    samples=[];deadline=time.monotonic()+90;completion=None
                    while time.monotonic()<deadline:
                        samples.append(sample())
                        log=d.adb('logcat','-d','-v','epoch','--pid='+probe_pid,'-s','XrayDeviceProbe:I','*:S')
                        log='\n'.join(line for line in log.splitlines()
                            if line.split() and line.split()[0].replace('.','',1).isdigit()
                            and float(line.split()[0])>=before['time'])
                        matches=re.findall(r'XRAY_ANDROID_STRESS state=completed cycle='+str(cycle_id)+r' (.+)',log)
                        if matches:
                            completion={k:int(v) for k,v in re.findall(r'(\w+)=(\d+)',matches[-1])};break
                        time.sleep(0.5)
                    after=sample()
                    d.emit('resource-burst',**identity,cycle=cycle,id=cycle_id,before=before,
                           load=samples,after=after,completion=completion)
                    if completion is None: raise RuntimeError('stress completion deadline')
                    if any(completion[k]!=v for k,v in {'httpPassed':240,'udpPassed':480,'httpFailed':0,'udpFailed':0}.items()):
                        traffic_ok=False
                    d.probe_stop()
                    ordinary=d.status(d.PROBE)
                    if int(ordinary.get('http-failed',0)) or int(ordinary.get('udp-failed',0)):
                        traffic_ok=False
                    d.command(d.HOST,'close-connections')
                    recovered=settled()
                    if before['pid']!=after['pid'] or before['startTicks']!=after['startTicks']:
                        raise RuntimeError('process restarted during CPU sample')
                    cpu=(after['cpuTicks']-before['cpuTicks'])/hz
                    rec={'cycle':cycle,'id':cycle_id,'before':before,'load':samples,'after':after,
                         'recovered':recovered,'cpuSeconds':cpu,'wallSeconds':after['time']-before['time'],
                         'completion':completion,'ordinaryProbes':ordinary}
                    cycles.append(rec)
                    name=f'{case["caseId"]}-{backend}-cycle{cycle}-meminfo.txt'
                    (d.ROOT/name).write_text(d.shell('dumpsys','meminfo',d.HOST))
                    d.emit('resource-cycle',**identity,**rec)
                rss=[statistics.median(s['rssBytes'] for s in c['recovered']) for c in cycles]
                threads=[statistics.median(s['threads'] for s in c['recovered']) for c in cycles]
                ok=rss[1]-rss[0]<=max(LIMITS['rssGrowthBytes'],rss[0]*LIMITS['rssGrowthFraction']) and threads[1]-threads[0]<=LIMITS['threadGrowth']
                d.emit('resource-recovery',**identity,passed=ok,rss=rss,threads=threads,
                       rssGrowthBytes=rss[1]-rss[0],threadGrowth=threads[1]-threads[0])
                # Keep both resource and traffic verdicts, including failed trials.
                d.emit('resource-post-traffic',**identity,status=d.traffic(env,'ipv4',2))
                d.host_stop();d.emit('resource-case-complete',**identity,resourcePassed=ok,trafficPassed=traffic_ok)
            except Exception as e:
                d.emit('resource-case-fail',**identity,error=str(e));raise
            finally:
                d.probe_stop();d.host_stop();d.log_snapshot('resource-logcat.log')
    d.emit('resources-complete',runId='all-cipher-diagnostic')

if __name__=='__main__':
    os.umask(0o077);run()

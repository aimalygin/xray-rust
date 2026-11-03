# v0.9 copy of docs/device-results/2026-10-18-v081-candidate/android-cancellation/local-cancel.py;
# only the fixture paths and the case selection differ.
import json,re,time
import drive as d
from device_clock import calibrate
clock=None

import os
from pathlib import Path
# v0.9: the three new client protocols, both HTTP carriers.
env=json.loads((Path(os.environ['FIXTURE_DIR'])/'v07-probe.json').read_text())
cases=[c for c in env['cases'] if c['caseId'] in ('socks-password','http-plain','http-tls','shadowsocks-aead-aes-256-gcm')]
log=Path(os.environ['FIXTURE_LOG'])
def rows(run):
    out=[]
    for l in log.read_text().splitlines():
        try:r=json.loads(l)
        except ValueError:continue
        if r.get('id')==run:out.append(r)
    return out

def wait_backend(run,kind,timeout):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        found=[r for r in rows(run) if r['backend']==kind]
        if found:return found[0]
        time.sleep(.03)
    raise RuntimeError('backend deadline '+kind)

def device_lines(since):
    result=[]
    for line in d.adb('logcat','-d','-v','epoch','-s','XrayDeviceGate:I','XrayDeviceProbe:I','*:S').splitlines():
        line=line.strip()
        if re.match(r'^\d+\.\d+',line) and float(line.split()[0])>=since+clock['offsetSeconds']:result.append(line)
    return result

def start(backend):
    d.command(d.HOST,'connect',('--es','tun-backend',backend,'--ez','probe-only','true'))
    s=d.wait_status(d.HOST,lambda s:s.get('state') in ('running','failed','fatal'))
    assert s['state']=='running',s

run=6000
try:
    for case,backend in [(c,b) for c in cases for b in ('file-descriptor','packet-pump')]:
        for mode in ('close-connections','disconnect'):
            run+=1
            d.probe_stop();d.host_stop();d.command(d.HOST,'reset');d.install_profile(case);start(backend)
            clock=calibrate()
            d.command(d.PROBE,'reset');d.wait_status(d.PROBE,lambda s:s.get('http-passed')=='0' and s.get('http-failed')=='0')
            d.command(d.PROBE,'start',('--es','http-url',f'http://198.51.100.7:{env["tcpPort"]}/v08-hold/{run}',
                '--es','udp-host','198.51.100.7','--ei','udp-port',str(env['udpPort']),'--el','interval-seconds','60'))
            opened=wait_backend(run,'hold-open',6)
            issued=time.time();assert issued-opened['time']<1
            d.emit('local-active-cancel-request',case=case['caseId'],backend=backend,mode=mode,id=run,opened=opened,closeRequestTime=issued,clock=clock)
            d.command(d.HOST,mode)
            stopped=d.wait_status(d.HOST,lambda s:s.get('state')==('running' if mode=='close-connections' else 'stopped'))
            deadline=time.monotonic()+3
            while True:
                lines=device_lines(issued-.1)
                errors=[l for l in lines if 'kind=http result=failed' in l]
                if errors or time.monotonic()>=deadline:break
                time.sleep(.05)
            assert errors and 'SocketTimeoutException' not in errors[-1],errors
            error_at=float(errors[-1].split()[0])-clock['offsetSeconds'];assert -clock['uncertaintySeconds']<=error_at-issued<3
            if mode=='disconnect':assert any('runtimeRunning":false' in l and 'activeConnections":0' in l for l in lines),lines
            else:assert any('connections-close-requested accepted=' in l and 'accepted=0' not in l for l in lines),lines
            d.probe_stop();time.sleep(5.2)
            if mode=='disconnect':start(backend)
            recovered=d.traffic(env,'ipv4',2);d.host_stop()
            closed=wait_backend(run,'hold-close',22)
            d.emit('local-active-cancellation',case=case['caseId'],backend=backend,mode=mode,id=run,
                   opened=opened,closed=closed,closeRequestTime=issued,
                   localHttpError=errors[-1],localErrorAfterRequestSeconds=error_at-issued,
                   status=stopped,lifecycle=lines,recovery=recovered,
                   clock=clock,localCancellationPassed=True,remoteCloseBoundPassed=closed['reason']=='eof' and closed['time']-issued<3)
            d.log_snapshot(f'local-control-{case["caseId"]}-{backend}-{mode}-logcat.log')
finally:
    d.probe_stop();d.host_stop();d.log_snapshot('local-final-logcat.log')

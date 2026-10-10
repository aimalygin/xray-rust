#!/usr/bin/env python3
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET

ROOT = Path(os.environ["XRAY_DEVICE_WORK_DIR"]).resolve()
ADB = os.environ.get("ADB", "adb")
SERIAL = os.environ["ANDROID_SERIAL"]
HOST = 'org.xrayrust.devicehost.v08'
PROBE = 'org.xrayrust.deviceprobe.v08'
COMP = {HOST: 'org.xrayrust.devicehost.MainActivity', PROBE: 'org.xrayrust.deviceprobe.ProbeActivity'}

def adb(*args, data=None, check=True):
    p = subprocess.run([ADB, '-s', SERIAL, *args], input=data, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, timeout=30)
    if check and p.returncode:
        raise RuntimeError('adb command failed: ' + p.stderr.decode(errors='replace')[-500:])
    return p.stdout.decode(errors='replace')

def shell(*args, **kwargs):
    return adb('shell', shlex.join(args), **kwargs)

def command(pkg, name, extras=()):
    return shell('am', 'start', '-W', '-n', pkg+'/'+COMP[pkg], '--es', 'command', name, *extras)

def status(pkg):
    name = 'device-gate-status' if pkg == HOST else 'device-probe-status'
    raw = shell('run-as', pkg, 'cat', 'shared_prefs/'+name+'.xml', check=False)
    if not raw.strip():
        return {}
    result = {}
    for c in ET.fromstring(raw):
        result[c.attrib['name']] = c.text if c.tag == 'string' else c.attrib['value']
    return result

def wait_status(pkg, predicate, timeout=15):
    deadline = time.monotonic()+timeout
    while time.monotonic()<deadline:
        s = status(pkg)
        if predicate(s):
            return s
        time.sleep(0.5)
    raise RuntimeError('status deadline: '+json.dumps(status(pkg)))

def emit(kind, **kwargs):
    value = {'hostTime':time.time(), 'kind':kind, **kwargs}
    with (ROOT/'events.jsonl').open('a') as f:
        f.write(json.dumps(value)+'\n')
    print(json.dumps(value), flush=True)

def install_profile(case, link=False):
    name = 'profile-import.pending' if link else 'profile-config-import.pending'
    shell('run-as', HOST, 'mkdir', '-p', 'no_backup')
    payload = case['text'] if link else case['configJSON']
    shell('run-as', HOST, 'sh', '-c', 'cat > no_backup/'+name, data=payload.encode())
    command(HOST, 'import-pending' if link else 'import-pending-config')
    s = wait_status(HOST, lambda s:s.get('detail') in ('profile-ready','config-profile-ready') or s.get('state')=='failed')
    if s.get('state')=='failed':
        raise RuntimeError('profile rejected: '+json.dumps(s))
    assert not shell('run-as', HOST, 'ls', 'no_backup/'+name, check=False).strip()
    return s

def host_start(backend, timeout=15):
    command(HOST, 'connect', ('--es','tun-backend',backend))
    return wait_status(HOST, lambda s:s.get('state') in ('running','failed','fatal'),timeout)

def host_stop():
    command(HOST,'disconnect')
    wait_status(HOST,lambda s:s.get('state')=='stopped')

def probe_stop():
    command(PROBE,'stop')
    wait_status(PROBE,lambda s:s.get('running')=='false')
    time.sleep(1)

def traffic(env, target, count=3):
    command(PROBE,'reset')
    wait_status(PROBE,lambda s:s.get('http-passed')=='0' and s.get('udp-passed')=='0')
    host = {'ipv4':'198.51.100.7','ipv6':'2001:db8::7','domain':env['probeHost']}[target]
    urlhost = '['+host+']' if ':' in host else host
    extra=('--es','http-url',f'http://{urlhost}:{env["tcpPort"]}/v08-probe',
           '--es','udp-host',host,'--ei','udp-port',str(env['udpPort']),
           '--el','interval-seconds','1')
    command(PROBE,'start',extra)
    try:
        s=wait_status(PROBE,lambda s:(int(s.get('http-passed',0))>=count and int(s.get('udp-passed',0))>=count)
                      or int(s.get('http-failed',0))>0 or int(s.get('udp-failed',0))>0,25)
    finally:
        probe_stop()
    s=status(PROBE)
    if int(s.get('http-failed',0)) or int(s.get('udp-failed',0)):
        raise RuntimeError('traffic failure: '+target+' '+json.dumps(s))
    return s

def log_snapshot(name):
    value=adb('logcat','-d','-v','epoch','-s','XrayDeviceGate:I','XrayDeviceProbe:I','*:S')
    (ROOT/name).write_text(value)

def matrix():
    env=json.loads((ROOT/'fixture/v07-probe.json').read_text())
    emit('matrix-start',caseCount=len(env['cases']),backends=['file-descriptor','packet-pump'])
    for case in env['cases']:
        for backend in ('file-descriptor','packet-pump'):
            identity={'case':case['caseId'],'backend':backend}
            emit('case-start',**identity)
            try:
                host_stop()
                command(HOST,'reset')
                install_profile(case,link=True)
                emit('share-link-import',**identity,passed=True)
                install_profile(case)
                s=host_start(backend)
                assert s['state']=='running',s
                emit('running',**identity,status=s)
                for target in ('ipv4','ipv6','domain'):
                    emit('traffic',**identity,target=target,status=traffic(env,target))
                command(HOST,'close-connections')
                emit('close-recovery',**identity,status=traffic(env,'ipv4',2))
                host_stop()
                command(HOST,'rapid-stop',('--es','tun-backend',backend))
                wait_status(HOST,lambda s:s.get('state')=='stopped')
                time.sleep(1)
                assert status(HOST)['state']=='stopped'
                s=host_start(backend)
                assert s['state']=='running',s
                emit('cancel-start-recovery',**identity,status=traffic(env,'ipv4',2))
                host_stop()
                emit('case-pass',**identity)
            except Exception as e:
                emit('case-fail',**identity,error=str(e))
                raise
            finally:
                probe_stop()
                host_stop()
                log_snapshot('device-logcat.log')
    emit('matrix-pass')

if __name__=='__main__':
    os.umask(0o077)
    p=argparse.ArgumentParser();p.add_argument('mode',choices=['prepare','matrix']);args=p.parse_args()
    if args.mode=='prepare':
        env=json.loads((ROOT/'fixture/v07-probe.json').read_text())
        install_profile(env['cases'][0])
        command(HOST,'connect',('--es','tun-backend','file-descriptor'))
        emit('consent-requested',status=status(HOST))
    else:
        matrix()

#!/usr/bin/env python3
import base64,json,os,time
import drive as d

def run():
    d.host_stop()
    marker='NONSECRET-DEVICE-REDACTION-CHECK'
    inputs={
        'trojan':f'trojan://{marker}@[]:443',
        'shadowsocks2022':f'ss://2022-blake3-aes-128-gcm:{marker}@127.0.0.1:443',
        'vmess':'vmess://'+base64.b64encode(json.dumps({'v':'2','add':'127.0.0.1','port':'443','id':marker,'aid':'0','net':'tcp','scy':'auto'}).encode()).decode(),
    }
    for fmt,raw in inputs.items():
        before=d.shell('run-as',d.HOST,'sha256sum','no_backup/device-gate-profile.bin').split()[0]
        d.shell('run-as',d.HOST,'sh','-c','cat > no_backup/profile-import.pending',data=raw.encode())
        d.command(d.HOST,'import-pending')
        time.sleep(.5)
        state=d.status(d.HOST)
        d.shell('run-as',d.HOST,'test','!','-e','no_backup/profile-import.pending')
        after=d.shell('run-as',d.HOST,'sha256sum','no_backup/device-gate-profile.bin').split()[0]
        pid=d.shell('pidof',d.HOST).strip()
        log=d.adb('logcat','-d','-v','epoch','--pid='+pid)
        passed=state.get('state')=='failed' and before==after and marker not in log
        d.emit('invalid-import-control',format=fmt,passed=passed,status=state,
               profileCiphertextUnchanged=before==after,pendingRemoved=True,markerAbsentFromHostLog=marker not in log)
        if not passed:raise RuntimeError('invalid import/redaction control failed')
    env=json.loads((d.ROOT/'fixture3/v07-probe.json').read_text())
    d.host_stop();d.command(d.PROBE,'reset')
    d.command(d.PROBE,'start',('--es','http-url',f'http://198.51.100.7:{env["tcpPort"]}/v08-probe',
        '--es','udp-host','198.51.100.7','--ei','udp-port',str(env['udpPort']),'--el','interval-seconds','60'))
    try:
        state=d.wait_status(d.PROBE,lambda s:int(s.get('http-failed',0))>=1 and int(s.get('udp-failed',0))>=1,20)
        passed=state.get('http-passed')=='0' and state.get('udp-passed')=='0'
        d.emit('vpn-off-negative-control',passed=passed,status=state,expectedTrafficFailure=True)
        if not passed:raise RuntimeError('synthetic target unexpectedly accessible without VPN')
    finally:
        d.probe_stop();d.host_stop();d.log_snapshot('controls-logcat.log')
    d.emit('controls-complete')

if __name__=='__main__':
    os.umask(0o077);run()

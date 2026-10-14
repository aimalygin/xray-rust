import argparse,json,os,re,time
import drive as d

parser=argparse.ArgumentParser();parser.add_argument('--only-backend');args=parser.parse_args()
fixture_name=os.environ.get('XRAY_WG_FIXTURE_NAME','wireguard-stop')
env=json.loads((d.ROOT/('fixture-'+fixture_name)/'v07-probe.json').read_text())
case=next(c for c in env['cases'] if c['caseId']=='wireguard')
log=d.ROOT/('fixture-'+fixture_name+'.log')
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
        if re.match(r'^\d+\.\d+',line) and float(line.split()[0])>=since:result.append(line)
    return result

def start(backend):
    d.command(d.HOST,'connect',('--es','tun-backend',backend,'--ez','probe-only','true'))
    s=d.wait_status(d.HOST,lambda s:s.get('state') in ('running','failed','fatal'))
    assert s['state']=='running',s

run=int(os.environ.get('XRAY_WG_RUN_START','4000'))
try:
    for backend in ('file-descriptor','packet-pump'):
        if args.only_backend and args.only_backend!=backend:continue
        for mode in ('disconnect','close-before-disconnect'):
            run+=1
            d.probe_stop();d.host_stop();d.command(d.HOST,'reset');d.install_profile(case);start(backend)
            d.command(d.PROBE,'reset');d.wait_status(d.PROBE,lambda s:s.get('http-passed')=='0' and s.get('http-failed')=='0')
            d.command(d.PROBE,'start',('--es','http-url',f'http://198.51.100.7:{env["tcpPort"]}/v08-hold/{run}',
                '--es','udp-host','198.51.100.7','--ei','udp-port',str(env['udpPort']),'--el','interval-seconds','60'))
            opened=wait_backend(run,'hold-open',6)
            issued=time.time();assert issued-opened['time']<1
            if mode=='close-before-disconnect':
                d.command(d.HOST,'close-connections')
                closed=wait_backend(run,'hold-close',3)
                assert closed['reason']=='eof' and closed['time']-issued<3
            stop_time=time.time();d.command(d.HOST,'disconnect')
            stopped=d.wait_status(d.HOST,lambda s:s.get('state')=='stopped')
            lines=device_lines(issued-.1)
            errors=[l for l in lines if 'kind=http result=failed' in l]
            assert errors and 'SocketTimeoutException' not in errors[-1],errors
            error_at=float(errors[-1].split()[0]);assert 0<=error_at-issued<3
            assert any('runtimeRunning":false' in l and 'activeConnections":0' in l for l in lines),lines
            d.probe_stop();time.sleep(5.2)
            start(backend);recovered=d.traffic(env,'ipv4',2);d.host_stop()
            closed=wait_backend(run,'hold-close',22)
            d.emit('wireguard-stop-control',case='wireguard',backend=backend,mode=mode,id=run,
                   opened=opened,closed=closed,closeRequestTime=issued,stopRequestTime=stop_time,
                   localHttpError=errors[-1],localErrorAfterRequestSeconds=error_at-issued,
                   status=stopped,lifecycle=lines,recovery=recovered,
                   localStopPassed=True,remoteCloseBoundPassed=closed['reason']=='eof' and 0<=closed['time']-issued<3)
            d.log_snapshot(f'{fixture_name}-{backend}-{mode}-logcat.log')
finally:
    d.probe_stop();d.host_stop()

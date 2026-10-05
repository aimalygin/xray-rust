import argparse,json,re,time
import drive as d

p=argparse.ArgumentParser();p.add_argument('--suite',choices=['legacy','v07','v08'],required=True)
p.add_argument('--skip-passed',action='store_true');p.add_argument('--only-case');p.add_argument('--only-backend');args=p.parse_args()
suite=args.suite;name=suite+'-udp'
env=json.loads((d.ROOT/('fixture-'+name)/'v07-probe.json').read_text())
log=d.ROOT/('fixture-'+name+'.log')

def rows():
    out=[]
    for line in log.read_text().splitlines():
        try:out.append(json.loads(line))
        except ValueError:pass
    return out

def pending(after):
    end=time.monotonic()+8
    while time.monotonic()<end:
        new=[r for r in rows() if r.get('backend')=='udp-pending' and r['time']>=after]
        if new:return new[0]
        time.sleep(.03)
    raise RuntimeError('no held UDP request at backend')

def start(backend):
    d.command(d.HOST,'connect',('--es','tun-backend',backend,'--ez','probe-only','true'))
    s=d.wait_status(d.HOST,lambda s:s.get('state') in ('running','failed','fatal'))
    assert s['state']=='running',s

def probe():
    d.probe_stop();d.command(d.PROBE,'reset')
    d.wait_status(d.PROBE,lambda s:s.get('udp-passed')=='0' and s.get('udp-failed')=='0')
    before=time.time()
    d.command(d.PROBE,'start',('--es','http-url',f'http://198.51.100.7:{env["tcpPort"]}/v08-probe',
        '--es','udp-host','198.51.100.7','--ei','udp-port',str(env['udpPort']),'--el','interval-seconds','60'))
    return pending(before)

def lifecycle_events(since):
    raw=d.adb('logcat','-d','-v','epoch','-s','XrayDeviceGate:I','*:S')
    return [line.strip() for line in raw.splitlines() if line.split() and re.match(r'^\s*\d+\.\d+',line) and float(line.split()[0])>=since]

failed=[]
try:
    d.emit('udp-campaign-start',suite=suite,delaySeconds=3,clientDeadlineSeconds=5)
    for case in env['cases']:
        if args.only_case and case['caseId']!=args.only_case:continue
        for backend in ('file-descriptor','packet-pump'):
            if args.only_backend and backend!=args.only_backend:continue
            identity={'suite':suite,'case':case['caseId'],'backend':backend}
            if args.skip_passed and (d.ROOT/'events.jsonl').exists():
                previous=[json.loads(line) for line in (d.ROOT/'events.jsonl').read_text().splitlines()]
                if any(e['kind']=='udp-case-pass' and all(e.get(k)==v for k,v in identity.items()) for e in previous):continue
            d.emit('udp-case-start',**identity)
            try:
                d.probe_stop();d.host_stop();d.command(d.HOST,'reset')
                d.install_profile(case);start(backend)
                opened=probe()
                s=d.wait_status(d.PROBE,lambda s:int(s.get('udp-passed',0))+int(s.get('udp-failed',0))>=1,7)
                assert s['udp-passed']=='1' and s['udp-failed']=='0' and s['http-failed']=='0',s
                d.emit('udp-delay-control',**identity,pending=opened,status=s)
                d.probe_stop()
                for operation in ('close-connections','disconnect'):
                    opened=probe()
                    requested=time.time()
                    assert requested-opened['time']<1,'late cancellation could race delayed response'
                    d.emit('udp-cancel-request',**identity,operation=operation,queryTag=opened['queryTag'],requestTime=requested,pending=opened)
                    d.command(d.HOST,operation)
                    s=d.wait_status(d.PROBE,lambda s:int(s.get('udp-passed',0))+int(s.get('udp-failed',0))>=1,7)
                    assert s['udp-passed']=='0' and s['udp-failed']=='1' and s['http-passed']=='1' and s['http-failed']=='0',s
                    response=next(r for r in rows() if r.get('backend')=='udp' and r['queryTag']==opened['queryTag'])
                    assert 2.9<=response['time']-opened['time']<4.5,response
                    assert response['time']>requested
                    first_events=lifecycle_events(requested-.2)
                    if operation=='close-connections':
                        accepted=[int(re.search(r'accepted=(\d+)',line)[1]) for line in first_events if 'state=connections-close-requested' in line]
                        assert accepted and accepted[-1]>=1,first_events
                        assert d.status(d.HOST)['state']=='running'
                        second=time.time();d.command(d.HOST,'close-connections')
                        second_events=lifecycle_events(second-.1)
                        accepted_again=[int(re.search(r'accepted=(\d+)',line)[1]) for line in second_events if 'state=connections-close-requested' in line]
                        assert accepted_again and accepted_again[-1]==0,second_events
                    else:
                        d.wait_status(d.HOST,lambda s:s.get('state')=='stopped')
                        second_events=[]
                    d.emit('udp-active-cancelled',**identity,operation=operation,pending=opened,
                           requestTime=requested,response=response,status=s,
                           lifecycle=first_events,idempotentLifecycle=second_events)
                    d.probe_stop()
                    if operation=='disconnect':start(backend)
                    d.emit('udp-cancel-recovery',**identity,operation=operation,status=d.traffic(env,'ipv4',1))
                d.host_stop();d.emit('udp-case-pass',**identity)
            except Exception as error:
                failed.append(identity);d.emit('udp-case-fail',**identity,error=str(error))
            finally:
                d.probe_stop();d.host_stop();d.log_snapshot(f'{name}-{case["caseId"]}-{backend}-logcat.log')
    d.emit('udp-campaign-complete',suite=suite,failed=failed)
finally:
    d.probe_stop();d.host_stop()
if failed:raise SystemExit(1)

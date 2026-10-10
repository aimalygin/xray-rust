import argparse, json, re, time
from pathlib import Path
import drive as d

parser=argparse.ArgumentParser()
parser.add_argument('--suite',choices=['legacy','v07','v08'],required=True)
parser.add_argument('--only-case')
parser.add_argument('--skip-passed',action='store_true')
parser.add_argument('--only-backend',choices=['file-descriptor','packet-pump'])
args=parser.parse_args()
suite=args.suite
fixture=d.ROOT/('fixture-'+suite)
env=json.loads((fixture/'v07-probe.json').read_text())
log=d.ROOT/('fixture-'+suite+'.log')
run_id={'legacy':1000,'v07':2000,'v08':3000}[suite]

def rows(run):
    result=[]
    for line in log.read_text().splitlines():
        try: row=json.loads(line)
        except ValueError: continue
        if row.get('id')==run: result.append(row)
    return result

def wait_row(run,kind,timeout):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        found=[r for r in rows(run) if r.get('backend')==kind]
        if found:return found[0]
        time.sleep(.03)
    raise RuntimeError(f'backend {kind} deadline id={run}')

def start(backend):
    d.command(d.HOST,'connect',('--es','tun-backend',backend,'--ez','probe-only','true'))
    s=d.wait_status(d.HOST,lambda s:s.get('state') in ('running','failed','fatal'))
    assert s['state']=='running',s
    return s

def active_flow(identity, operation, control=False):
    global run_id
    run_id+=1
    # Distinct IDs even when a partial campaign is explicitly rerun.
    while rows(run_id):run_id+=10000
    d.probe_stop();d.command(d.PROBE,'reset')
    d.wait_status(d.PROBE,lambda s:s.get('http-passed')=='0' and s.get('http-failed')=='0')
    d.command(d.PROBE,'start',('--es','http-url',f'http://198.51.100.7:{env["tcpPort"]}/v08-hold/{run_id}',
        '--es','udp-host','198.51.100.7','--ei','udp-port',str(env['udpPort']),'--el','interval-seconds','60'))
    opened=wait_row(run_id,'hold-open',6)
    if control:
        time.sleep(2)
        assert not any(r['backend']=='hold-close' for r in rows(run_id)),rows(run_id)
        d.emit('hold-no-action-control',**identity,id=run_id,observedOpenSeconds=time.time()-opened['time'])
    request_time=time.time()
    assert request_time-opened['time']<3.5,'probe timeout could confound cancellation'
    d.emit('cancel-request',**identity,id=run_id,operation=operation,backendOpened=opened['time'])
    d.command(d.HOST,operation)
    closed=wait_row(run_id,'hold-close',3)
    assert closed['reason'] in ('eof','ConnectionResetError'),closed
    assert 0<=closed['time']-request_time<3,closed
    assert closed['time']-opened['time']<4.5,'client 5s timeout could confound cancellation'
    if operation=='disconnect':
        d.wait_status(d.HOST,lambda s:s.get('state')=='stopped')
    else:
        assert d.status(d.HOST)['state']=='running'
    d.emit('active-flow-cancelled',**identity,id=run_id,operation=operation,
           requestTime=request_time,opened=opened,closed=closed,
           backendCloseAfterRequestSeconds=closed['time']-request_time)
    # HttpURLConnection may retry a GET after EOF. All retries stay recorded;
    # allow its existing 5s deadline before reusing the probe's counter store.
    d.probe_stop()
    time.sleep(5.2)
    d.emit('cancel-probe-observation',**identity,id=run_id,operation=operation,
           status=d.status(d.PROBE),backendEvents=rows(run_id))
    if operation=='disconnect':start(identity['backend'])
    d.emit('cancel-recovery',**identity,id=run_id,operation=operation,
           status=d.traffic(env,'ipv4',2))

failed=[]
cases=[c for c in env['cases'] if not args.only_case or c['caseId']==args.only_case]
assert cases
try:
    d.emit('campaign-start',suite=suite,caseCount=len(cases),kindOfCancellation='HTTP request in flight; backend EOF before client timeout')
    for case in cases:
        for backend in ('file-descriptor','packet-pump'):
            if args.only_backend and backend!=args.only_backend:continue
            identity={'suite':suite,'case':case['caseId'],'backend':backend}
            if args.skip_passed and (d.ROOT/'events.jsonl').exists():
                previous=[json.loads(line) for line in (d.ROOT/'events.jsonl').read_text().splitlines()]
                if any(e['kind']=='case-pass' and all(e.get(k)==v for k,v in identity.items()) for e in previous):
                    continue
            d.emit('case-start',**identity)
            try:
                d.probe_stop();d.host_stop();d.command(d.HOST,'reset')
                if case['format']!='wireguard':
                    d.install_profile(case,link=True);d.emit('share-link-import',**identity,passed=True)
                d.install_profile(case);d.emit('config-import',**identity,passed=True)
                d.emit('running',**identity,status=start(backend))
                for target in (('ipv4','ipv6','domain') if suite!='v08' else ('ipv4',)):
                    d.emit('traffic',**identity,target=target,status=d.traffic(env,target,2))
                active_flow(identity,'close-connections',control=case==cases[0])
                active_flow(identity,'disconnect')
                d.host_stop();d.emit('case-pass',**identity)
            except Exception as error:
                failed.append(identity)
                d.emit('case-fail',**identity,error=str(error))
            finally:
                d.probe_stop();d.host_stop()
                d.log_snapshot(f'{suite}-{case["caseId"]}-{backend}-logcat.log')
    d.emit('campaign-complete',suite=suite,failed=failed)
finally:
    d.probe_stop();d.host_stop()
if failed:raise SystemExit(1)

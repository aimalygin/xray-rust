#!/usr/bin/env python3
"""Verify preserved Android evidence without treating intentional interruptions as traffic passes."""
import hashlib,json,re
from pathlib import Path

ROOT=Path(__file__).resolve().parent
manifest=json.loads((ROOT/'manifest.json').read_text())
for item in manifest['artifacts']:
    path=(ROOT/item['path']).resolve()
    assert path.is_relative_to(ROOT.resolve()),item['path']
    assert hashlib.sha256(path.read_bytes()).hexdigest()==item['sha256'],item['path']
for item in json.loads((ROOT/'build-identity.json').read_text())['measuredDriverVersions']:
    raw=(ROOT/item['path']).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==item['sha256']
    if 'measuredSha256' in item:
        assert item['path']=='reproduce/drive.py'
        assert hashlib.sha256(raw+b'\n').hexdigest()==item['measuredSha256']
events=[json.loads(l) for l in (ROOT/'events.jsonl').read_text().splitlines()]
backend=[json.loads(l) for l in (ROOT/'backend-events.jsonl').read_text().splitlines()]
def key(e):return (e['suite'],e['case'],e['backend'])
expected=set()
for suite,cases in [('legacy',['vless-reality','xhttp-h1','xhttp-h2','xhttp-h3']),
                    ('v07',['wireguard','hysteria2']),
                    ('v08',['trojan-tls','shadowsocks2022-2022-blake3-chacha20-poly1305',
                            'shadowsocks2022-2022-blake3-aes-128-gcm','shadowsocks2022-2022-blake3-aes-256-gcm',
                            'vmess-auto','vmess-aes-128-gcm','vmess-chacha20-poly1305'])]:
    expected|={(suite,case,path) for case in cases for path in ['file-descriptor','packet-pump']}
assert len(expected)==26
for kind in ['case-pass','udp-case-pass']:
    required=({k for k in expected if k!=('v08','trojan-tls','packet-pump')} if kind=='udp-case-pass'
              else {k for k in expected if k[1]!='wireguard' and not k[1].startswith('shadowsocks2022-')})
    assert {key(e) for e in events if e['kind']==kind}==required,kind
for kind in ['active-flow-cancelled','udp-active-cancelled']:
    records=[e for e in events if e['kind']==kind]
    required={(k,op) for k in expected for op in ['close-connections','disconnect'] if not (kind=='active-flow-cancelled' and (k[1].startswith('shadowsocks2022-') or (k[1]=='wireguard' and op=='disconnect')))}
    assert {(key(e),e['operation']) for e in records}==required,kind
    assert len(records)==len(required),kind
    for e in records:
        if kind=='active-flow-cancelled':
            assert e['closed']['reason'] in ['eof','ConnectionResetError']
            assert 0<=e['closed']['time']-e['requestTime']<3
            assert e['closed']['time']-e['opened']['time']<4.5
            assert abs(e['backendCloseAfterRequestSeconds']-(e['closed']['time']-e['requestTime']))<1e-6
            for field in ['opened','closed']:
                assert any(all(r.get(k)==v for k,v in e[field].items()) for r in backend),field
            recovery='cancel-recovery'
        else:
            assert 0<=e['requestTime']-e['pending']['time']<1
            assert 2.9<=e['response']['time']-e['pending']['time']<4.5
            assert e['response']['time']>e['requestTime']
            assert e['pending']['queryTag']==e['response']['queryTag']
            assert e['status']['udp-passed']=='0' and e['status']['udp-failed']=='1'
            assert e['status']['http-passed']=='1' and e['status']['http-failed']=='0'
            for field in ['pending','response']:
                assert any(all(r.get(k)==v for k,v in e[field].items()) for r in backend),field
            if e['operation']=='close-connections':
                first=[int(re.search(r'accepted=(\d+)',l)[1]) for l in e['lifecycle'] if 'connections-close-requested' in l]
                second=[int(re.search(r'accepted=(\d+)',l)[1]) for l in e['idempotentLifecycle'] if 'connections-close-requested' in l]
                assert first and first[-1]>=1 and second and second[-1]==0
            else:
                assert any('XRAY_ANDROID_LIFECYCLE state=stopped' in l for l in e['lifecycle'])
            recovery='udp-cancel-recovery'
        recovered=any(r['kind']==recovery and key(r)==key(e) and r['operation']==e['operation'] and r['hostTime']>e['hostTime'] for r in events)
        if kind=='udp-active-cancelled' and key(e)==('v08','trojan-tls','packet-pump') and e['operation']=='disconnect':
            assert not recovered  # real failed recovery retained below
        else:assert recovered
controls=[e for e in events if e['kind']=='udp-delay-control']
assert {key(e) for e in controls}==expected
normal=[e for e in events if e['kind'] in ['traffic','cancel-recovery','udp-cancel-recovery','udp-delay-control']] + manifest['ordinaryTrafficFailures']
for name in ['http-passed','http-failed','udp-passed','udp-failed']:
    assert sum(int(e['status'].get(name,0)) for e in normal)==manifest['ordinaryTraffic'][name]
assert manifest['ordinaryTraffic']['http-failed']==0
assert manifest['ordinaryTraffic']['udp-failed']==1
failures=[e for e in events if e['kind'] in ['case-fail','udp-case-fail']]
assert failures==manifest['failures']
# The first pilot's parser defect remains a failed attempt; require its diagnosis
# and original controller rather than hiding it among expected UDP timeouts.
assert len(failures)==10,failures
assert failures[0]['kind']=='udp-case-fail' and failures[0]['error']=='[]'
tcp_failures=[e for e in failures if e['kind']=='case-fail']
assert {key(e) for e in tcp_failures}=={k for k in expected if k[1]=='wireguard' or k[1].startswith('shadowsocks2022-')}
assert len(tcp_failures)==8 and all(e['error'].startswith('backend hold-close deadline') for e in tcp_failures)
ordinary_failures=[e for e in failures if e['error'].startswith('traffic failure: ')]
assert len(ordinary_failures)==1 and key(ordinary_failures[0])==('v08','trojan-tls','packet-pump')
assert len(manifest['ordinaryTrafficFailures'])==1
assert manifest['ordinaryTrafficFailures'][0]['status']['udp-failed']=='1'
assert json.loads((ROOT/'udp-pilot-diagnosis.json').read_text())['classification']=='controller-log-parser-error'
assert (ROOT/'reproduce/udp-cancel-pilot-initial.py').exists()
controls=[e for e in events if e['kind']=='wireguard-stop-control']
assert len(controls)==4
assert {(e['backend'],e['mode']) for e in controls}=={(p,m) for p in ['file-descriptor','packet-pump'] for m in ['disconnect','close-before-disconnect']}
for e in controls:
    assert e['localStopPassed'] and e['status']['state']=='stopped'
    assert 0<=e['localErrorAfterRequestSeconds']<3
    assert e['recovery']['http-failed']==e['recovery']['udp-failed']=='0'
    assert e['recovery']['http-passed']==e['recovery']['udp-passed']=='2'
    assert e['remoteCloseBoundPassed']==(e['closed']['reason']=='eof' and 0<=e['closed']['time']-e['closeRequestTime']<3)
    if e['mode']=='close-before-disconnect':assert e['remoteCloseBoundPassed']
    if e['remoteCloseBoundPassed']:assert e['closed']['reason']=='eof' and e['closed']['time']-e['closeRequestTime']<3
    else:assert e['closed']['reason']=='TimeoutError' and e['closed']['time']-e['opened']['time']>=19.9
assert json.loads((ROOT/'wireguard-control-diagnosis.json').read_text())['classification']=='controller-expected-negative-result-error'
controls=[e for e in events if e['kind']=='ss2022-local-control']
assert len(controls)==12
assert {(e['case'],e['backend'],e['mode']) for e in controls}=={(k[1],k[2],op) for k in expected if k[1].startswith('shadowsocks2022-') for op in ['close-connections','disconnect']}
for e in controls:
    assert e['localCancellationPassed'] and 0<=e['localErrorAfterRequestSeconds']<3
    assert e['status']['state']==('running' if e['mode']=='close-connections' else 'stopped')
    assert e['recovery']['http-passed']==e['recovery']['udp-passed']=='2'
    assert e['recovery']['http-failed']==e['recovery']['udp-failed']=='0'
    assert not e['remoteCloseBoundPassed'] and e['closed']['reason']=='TimeoutError'
    assert e['closed']['time']-e['opened']['time']>=19.9
controls=[e for e in events if e['kind']=='ss2022-go-control']
assert len(controls)==3
assert {e['case'] for e in controls}=={k[1] for k in expected if k[1].startswith('shadowsocks2022-')}
for e in controls:
    assert e['processExitTime']<e['closed']['time']
    assert e['closed']['reason']=='TimeoutError' and e['closed']['time']-e['opened']['time']>=19.9
    assert e['remoteCloseAfterSocksSeconds']>=19
    assert all(r['backend']!='hold-close' for r in e['backendBeforeClientExit'])
repeats=manifest['trojanRepeatResults']
assert len(repeats)==4 and [e['backend'] for e in repeats]==['packet-pump','file-descriptor','packet-pump','file-descriptor']
for trial in repeats:
    folder=ROOT/f"trojan-repeat-{trial['trial']}"
    records=[json.loads(l) for l in (folder/'events.jsonl').read_text().splitlines()]
    rows=[json.loads(l) for l in (folder/'backend-events.jsonl').read_text().splitlines()]
    passed=any(e['kind']=='udp-case-pass' for e in records)
    assert passed==trial['casePassed']==(trial['exitCode']==0)
    assert trial['failures']==[e for e in records if e['kind']=='udp-case-fail']
    if passed:
        assert len([e for e in records if e['kind']=='udp-cancel-recovery'])==2
        assert all(e['status']['udp-failed']=='0' and e['status']['http-failed']=='0' for e in records if e['kind'] in ['udp-cancel-recovery','udp-delay-control'])
    for e in records:
        if e['kind']=='udp-active-cancelled':
            assert 0<=e['requestTime']-e['pending']['time']<1
            assert 2.9<=e['response']['time']-e['pending']['time']<4.5
            assert e['status']['udp-passed']=='0' and e['status']['udp-failed']=='1'
            assert all(e[field] in rows for field in ['pending','response'])
assert 'XRAY_ANDROID_LIFECYCLE state=fatal' not in (ROOT/'device-logcat.log').read_text()
assert manifest['releaseAcceptanceComplete'] is False
assert manifest['androidNetworkAndLock']=='owner-skipped-not-tested'
assert json.loads((ROOT/'cleanup.json').read_text())['complete']
assert all(not x['credentialsRemaining'] for x in json.loads((ROOT/'fixture-cleanup.json').read_text()))
print('Evidence integrity verified: 18/26 primary TCP cases, 25/26 primary UDP cases, retained remote-close and recovery failures, explicit follow-up controls. This is not full release acceptance.')

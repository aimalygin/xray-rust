"""Bounded fresh-fixture repeats; preserve the primary failure and every retry."""
import json,os,subprocess,sys,time
from pathlib import Path
import drive as d
root=Path(os.environ.get('XRAY_CORE_ROOT',Path(__file__).resolve().parents[2])).resolve()
work=d.ROOT
os.umask(0o077)
print('Waiting for SS2022 controls; no concurrent device work',flush=True)
while 'SS2022 peer and local cancellation controls complete' not in (work/'ss-scheduler.log').read_text():time.sleep(2)
for trial,backend in enumerate(['packet-pump','file-descriptor','packet-pump','file-descriptor'],1):
    tag=f'trojan-repeat-{trial}'
    childwork=work/tag;childwork.mkdir(mode=0o700)
    command=[sys.executable,'-u','scripts/run-v08-android-protocol-fixture.py','--suite','v08','--protocol','v08',
        '--bind',os.environ['XRAY_FIXTURE_BIND'],'--reference-binary','target/v08-comparison/bin/xray',
        '--reference-sha256','fcbfcfe586d891ecf556570acd32ce5160e803498e30fe072d151d0056d23b99',
        '--output',str(childwork/'fixture-v08-udp'),'--udp-delay-seconds','3','--seconds','180']
    print('RUN',tag,backend,flush=True)
    with (childwork/'fixture-v08-udp.log').open('w') as output:
        fixture=subprocess.Popen(command,cwd=root,stdout=output,stderr=subprocess.STDOUT)
        try:
            deadline=time.monotonic()+20
            while 'Fixture ready:' not in (childwork/'fixture-v08-udp.log').read_text():
                if fixture.poll() is not None or time.monotonic()>deadline:raise RuntimeError('fixture not ready')
                time.sleep(.2)
            d.emit('trojan-repeat-start',trial=trial,backend=backend)
            env={**os.environ,'XRAY_DEVICE_WORK_DIR':str(childwork)}
            with (childwork/'controller.log').open('w') as log:
                result=subprocess.run([sys.executable,'-u',str(work/'udp-cancel.py'),'--suite','v08','--only-case','trojan-tls','--only-backend',backend],env=env,stdout=log,stderr=subprocess.STDOUT)
            rows=[json.loads(l) for l in (childwork/'events.jsonl').read_text().splitlines()]
            d.emit('trojan-repeat-complete',trial=trial,backend=backend,exitCode=result.returncode,
                casePassed=any(e['kind']=='udp-case-pass' for e in rows),failures=[e for e in rows if e['kind']=='udp-case-fail'])
        finally:
            if fixture.poll() is None:
                fixture.terminate()
                try:fixture.wait(timeout=8)
                except subprocess.TimeoutExpired:fixture.kill();fixture.wait()
            remaining=[p.name for p in (childwork/'fixture-v08-udp').glob('*') if p.name in ['server.json','v07-probe.json','tls.crt','tls.key','server-wg.pem','client-wg.pem']]
            (work/f'cleanup-{tag}.json').write_text(json.dumps({'exitCode':fixture.returncode,'credentialsRemaining':remaining}))
            assert not remaining
print('Trojan four fresh-fixture repeats complete',flush=True)

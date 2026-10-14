"""Remove only this campaign's isolated device profile after all controls finish."""
import json,subprocess
import drive as d
assert 'Trojan four fresh-fixture repeats complete' in (d.ROOT/'trojan-repeat-scheduler.log').read_text()
d.probe_stop();d.host_stop()
state={'host':d.status(d.HOST),'probe':d.status(d.PROBE)}
files=['no_backup/profile-import.pending','no_backup/profile-config-import.pending','no_backup/device-gate-profile.bin']
d.shell('run-as',d.HOST,'rm','-f',*files)
for f in files:d.shell('run-as',d.HOST,'test','!','-e',f)
for package in [d.PROBE,d.HOST]:d.shell('am','force-stop',package)
assert not d.shell('pidof',d.HOST,check=False).strip()
assert not d.shell('pidof',d.PROBE,check=False).strip()
conditions={}
for label,cmd,prefixes in [('battery',['dumpsys','battery'],['USB powered:','level:','temperature:','status:']),('thermal',['dumpsys','thermalservice'],['Thermal Status:'])]:
    conditions[label]=[x.strip() for x in d.shell(*cmd).splitlines() if any(x.strip().startswith(pre) for pre in prefixes)]
remaining=[p for p in d.ROOT.rglob('*') if p.is_file() and (p.name in ['server.json','v07-probe.json','tls.crt','tls.key','server-wg.pem','client-wg.pem'] or p.match('go-client-*.json'))]
assert not remaining,[p.name for p in remaining]
owned=[]
for row in subprocess.check_output(['ps','-axo','pid=,command='],text=True).splitlines():
    parts=row.strip().split()
    if len(parts)<2:continue
    command=parts[1:]
    if str(d.ROOT) in ' '.join(command) and ('scripts/run-v08-android-protocol-fixture.py' in command or (command[0].endswith('/xray') and '-config' in command)):
        owned.append(parts[0])
assert not owned,owned
result={'complete':True,'ownedServicesStopped':True,'ownedAppProcessesStopped':True,'ownedProfileAndPendingImportsRemoved':True,'fixtureCredentialsRemoved':True,'ownedFixtureAndReferenceClientProcessesStopped':True,'previousAppPackagesUntouched':True,'stateBeforeForceStop':state,'finalConditions':conditions}
(d.ROOT/'cleanup.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))

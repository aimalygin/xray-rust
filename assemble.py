"""Assemble reviewed measurements; never execute a device or rewrite raw outcomes."""
import collections, copy, gzip, hashlib, importlib.util, io, json, math, tarfile, zipfile
from pathlib import Path
MOBILE=Path(__file__).resolve().parents[3]
OUT=MOBILE/'Artifacts/v0.7.0-release-evidence'
PARTS=MOBILE/'Artifacts/v0.7.0-rc.1-evidence-parts-3533166'
FINAL=MOBILE/'Artifacts/v0.7.0-rc.1-final-devices'
CORE=MOBILE/'.build/core-v0.7.0-rc.1'
COMMIT='353316687b22c2fabbaf37ab5668dda05a972f46'; TREE='f5aacb1fb5a5bbda9eac83a7330059219ce6b0ce'
spec=importlib.util.spec_from_file_location('evidence', CORE/'scripts/check-v07-release-evidence.py');v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)
def read(p):return json.loads(p.read_text())
def dump(d):return (json.dumps(d,indent=2,ensure_ascii=False)+'\n').encode()
def sha(b):return hashlib.sha256(b).hexdigest()
blobs={}
def artifact(kind,path,data):
 blobs[path]=data
 return {'kind':kind,'path':path,'sha256':sha(data)}
retained=read(FINAL/'android-retained-3533166/report.json')
lock=read(FINAL/'android-wifi-lock-3533166-diagnostic-2/report.json')
imports=read(FINAL/'android-import-3533166.json')
for d in [retained,lock]:assert d['result']=='pass' and d['candidateCommit']==COMMIT and d['candidateTree']==TREE
assert imports['result']=='pass' and imports['coreCommit']==COMMIT
assert all(x['result']=='pass' for x in imports['checks'])
raw={};source_hashes={}
def record(p):
 data=p.read_bytes();name=str(p.relative_to(MOBILE/'Artifacts'));source_hashes[name]=sha(data)
 raw[name]=json.loads(data) if p.suffix=='.json' else data.decode()
# Include successful checks and original failed attempts; their results are untouched.
for dirname in ['android-retained-3533166','android-wifi-lock-3533166-diagnostic-2','android-transitions-3533166-attempt-2','android-wifi-lock-3533166']:
 for p in sorted((FINAL/dirname).rglob('*')):
  if p.is_file() and p.suffix in {'.json','.log','.txt'}:record(p)
for name in ['android-import-3533166.json','android-wifi-timeouts-3533166.json','release-exceptions-20260926.json','release-decision-wireguard-20260927.json']:
 record(FINAL/name)
scenarios=[];legacy={'vless-reality','xhttp-h1','xhttp-h2','xhttp-h3'}
for s in retained['scenarios']:
 assert s['result']==s['trafficResult']=='pass'
 if s['id'] in legacy:continue
 item=copy.deepcopy(s);item['durationSeconds']=math.ceil(s['durationSeconds'])
 if s['id'] in v.ANDROID_PROTOCOLS:
  name=s['id'];wake=next(x for x in lock['scenarios'] if x['id']==name)
  for phase in ['wifi-before','wake','reconnect']:
   p=read(FINAL/'android-wifi-lock-3533166-diagnostic-2'/f'{name}-{phase}-probe.json')
   assert p['result']=='pass' and set(p['checks'])=={'ipv4-tcp-fin','ipv6-tcp-fin','ipv4-udp','ipv6-udp','routed-dns-a','routed-dns-aaaa'}
  probe=read(FINAL/'android-retained-3533166'/f'{name}-probe.json')
  assert probe['closedFlows']==8 and probe['freshRecoveryEchoes']>=1 and probe['freshUdpSuccesses']>0
  recovery=next(x for x in retained['resourceRecovery'] if x['scenario']==name)
  assert recovery['activeConnections']==0 and recovery['seconds']<=15
  recovery=next(x for x in lock['lockRecovery'] if x['stage']==name)
  assert recovery['screenOffSeconds']>=30 and recovery['probeRetries']==0
  assert 'connected' in wake['events'] and 'screen-off-Dozing' in wake['events']
  item['durationSeconds']+=math.ceil(wake['durationSeconds'])
  item['transitions']=sorted(v.PROTOCOL_TRANSITIONS-{'wifi-cellular-wifi'})
 else:item['transitions']=list(dict.fromkeys(item['transitions']))
 scenarios.append(item)
scenarios.append({'id':'legacy-regression','durationSeconds':math.ceil(sum(s['durationSeconds'] for s in retained['scenarios'] if s['id'] in legacy)), 'transitions':sorted(legacy),'trafficResult':'pass','result':'pass'})
scenarios.append({'id':'profile-import','durationSeconds':max(1,math.ceil(imports['durationSeconds'])),'transitions':['hysteria2-link','wireguard-file','invalid-input-redaction'],'trafficResult':'pass','result':'pass'})
assert {s['id'] for s in scenarios}==v.POLICY.scenarios('android')
growth=[];thread_growth=[];resource_detail=[]
for campaign,d in [('retained',retained),('wifi-lock',lock)]:
 assert all(s['fatalTunErrors']==s['unrecoveredTransitions']==0 for s in d['samples'])
 groups=collections.defaultdict(list)
 for row in d['samples']:groups[row['runtimeGeneration']].append(row)
 for gen,rows in groups.items():
  value=max(r['residentMemoryBytes'] for r in rows)-rows[0]['residentMemoryBytes'];growth.append(value)
  resource_detail.append({'campaign':campaign,'source':'host-rss','runtimeGeneration':gen,'samples':len(rows),'rssGrowthBytes':value})
 groups=collections.defaultdict(list)
 for row in d['nativeResourceSamples']:
  name=row['scenario']
  if campaign=='wifi-lock':
   for suffix in ['-wifi-before','-wake','-reconnect']:name=name.removesuffix(suffix)
  groups[name].append(row)
 for name,rows in groups.items():
  rss=max(r['rssBytes'] for r in rows)-rows[0]['rssBytes'];threads=max(r['threads'] for r in rows)-rows[0]['threads']
  growth.append(rss);thread_growth.append(threads)
  resource_detail.append({'campaign':campaign,'source':'proc-status','scenario':name,'samples':len(rows),'rssGrowthBytes':rss,'threadGrowth':threads})
observed={'residentMemoryGrowthBytes':max(growth),'threadGrowth':max(thread_growth),'fatalErrors':0,'unrecoveredTransitions':0}
assert all(observed[k]<=retained['limits'][k] for k in observed)
identity={'revision':COMMIT,'tree':TREE,'dirty':False}
android={'platform':'android','physical':True,'model':retained['model'],'osVersion':retained['osVersion'],'architecture':'arm64-v8a','durationSeconds':math.ceil(retained['durationSeconds']+lock['durationSeconds']+imports['durationSeconds']),'scenarios':scenarios,'limits':retained['limits'],'observed':observed,'artifacts':[],'result':'pass'}
android['artifacts'].append(artifact('resource-profile','android/resource-profile.json',dump({'candidate':identity,'observed':observed,'limits':retained['limits'],'method':'Maximum rise over first sample of each host runtime and native scenario; Wi-Fi wake/reconnect grouped conservatively by protocol/backend. Counts are native /proc thread counts. Raw samples are retained.','groups':resource_detail,'nativeResourceSamples':{'retained':retained['nativeResourceSamples'],'wifi-lock':lock['nativeResourceSamples']},'hostSamples':{'retained':retained['samples'],'wifi-lock':lock['samples']},'resourceRecovery':retained['resourceRecovery'],'lockRecovery':lock['lockRecovery']})))
android['artifacts'].append(artifact('sanitized-log','android/sanitized-log.json',dump({'candidate':identity,'scope':'Passing bounded campaigns; historical failed attempts preserved, not erased by owner acceptance. Diagnostic follow-ups live in protocol-comparisons.tar.gz with their original revisions.','sourceSha256':source_hashes,'reports':raw})))
android['artifacts'].append(artifact('transition-timeline','android/transition-timeline.json',dump({'candidate':identity,'cellular':'not-tested; owner accepted for 0.7 only','retained':retained['timeline'],'wifi-lock':lock['timeline'],'lockRecovery':lock['lockRecovery'],'historicalFailures':'android/sanitized-log.json; performance/protocol-comparisons.tar.gz'})))
apple=read(PARTS/'apple/device.json')
for item in apple['artifacts']:
 data=(PARTS/item['path']).read_bytes();assert sha(data)==item['sha256'];blobs[item['path']]=data
performance=read(PARTS/'performance-v06/performance.json')
for item in performance['artifacts']:
 p=PARTS/'performance-v06'/Path(item['path']).name;data=p.read_bytes();assert sha(data)==item['sha256'];blobs[item['path']]=data
# Deterministic nested comparison archive. Keep original source identities and failures.
comparison_files={}
comparison_files['historical-protocol-comparisons.tar.gz']=(MOBILE/'Artifacts/v0.7.0-rc.1-evidence-parts/protocol-comparisons.tar.gz').read_bytes()
selected_suffixes={'.json','.jsonl','.md','.log','.txt','.csv','.java','.xml'}
for name in ['v0.7.0-rc.1-wireguard-official-20260927','v0.7.0-rc.1-direct-udp-20260927','v0.7.0-rc.1-wireguard-recovery-20260927','v0.7.0-rc.1-wireguard-timeouts-20260927']:
 root=MOBILE/'Artifacts'/name;manifest=read(root/'manifest.json');files=manifest['files']
 hashes=files if isinstance(files,dict) else {x['path']:x['sha256'] for x in files}
 for rel,digest in sorted(hashes.items()):
  p=root/rel
  if p.suffix not in selected_suffixes:continue
  data=p.read_bytes();assert sha(data)==digest,(name,rel,'original manifest differs')
  comparison_files[f'{name}/{rel}']=data
 comparison_files[f'{name}/manifest.json']=(root/'manifest.json').read_bytes()
for dirname in ['performance-v05','performance-v05-attempt-1']:
 for p in sorted((PARTS/dirname).rglob('*')):
  if p.is_file() and p.suffix in {'.json','.csv','.log','.md','.txt'} and p.name!='config.json':comparison_files['candidate-3533166/'+str(p.relative_to(PARTS))]=p.read_bytes()
comparison_files['README.md']=b'''# Retained comparisons and failures\n\nThe historical archive retains its dated source identities. The Android control\nreports retain candidate 3533166 or explicitly diagnostic 684eca5/earlier commits.\nThese are not new stable-version measurements. Original manifest hashes are\nretained; this package selects reports, raw samples, header captures, analyses\nand test descriptions. APKs, native binaries and credential-bearing profiles\nare excluded; their recorded build hashes remain in the reports.\n\nOfficial WireGuard: 3000/3000; xray-rust: 2999/3000; direct UDP: 4999/5000.\nThe investigated case is accepted by the owner for 0.7 only; root cause is not\nproved. No statistical equivalence or new CPU/RSS/throughput parity is claimed.\n'''
comparison_files['selected-files.json']=dump({name:sha(data) for name,data in sorted(comparison_files.items())})
buffer=io.BytesIO()
with gzip.GzipFile(fileobj=buffer,mode='wb',mtime=0,filename='') as gz:
 with tarfile.open(fileobj=gz,mode='w') as tar:
  for name,data in sorted(comparison_files.items()):
   entry=tarfile.TarInfo(name);entry.size=len(data);entry.mode=0o644;entry.mtime=0;tar.addfile(entry,io.BytesIO(data))
performance['artifacts'].append(artifact('protocol-comparisons','performance/protocol-comparisons.tar.gz',buffer.getvalue()))
performance['artifacts'].append(artifact('known-limitations','performance/known-limitations.md',(OUT/'known-limitations.md').read_bytes()))
performance['artifacts'].append(artifact('release-decisions','performance/release-decisions.json',v.OWNER_DECISIONS.read_bytes()))
manifest={'schemaVersion':3,'candidate':identity,'devices':[apple,android],'performance':performance,'acceptance':v.accepted_scope(),'result':'accepted-with-exceptions'}
path=OUT/'v07-release-evidence.zip'
with zipfile.ZipFile(path,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
 for name,data in sorted({'manifest.json':dump(manifest),**blobs}.items()):
  info=zipfile.ZipInfo(name,date_time=(2026,9,27,0,0,0));info.external_attr=0o100644<<16;info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,data)
v.validate_archive(path,COMMIT,TREE)
(OUT/'manifest.json').write_bytes(dump(manifest));(OUT/'SHA256SUMS').write_text(f'{sha(path.read_bytes())}  {path.name}\n')
(OUT/'assembly-report.json').write_bytes(dump({'measuredCandidate':identity,'archiveSha256':sha(path.read_bytes()),'archiveBytes':path.stat().st_size,'files':len(blobs)+1,'comparisonFiles':len(comparison_files),'androidObserved':observed,'result':'accepted-with-exceptions','stableSourceValidation':'pending final clean stable commit','newPhysicalDeviceRun':False}))
print((OUT/'assembly-report.json').read_text())

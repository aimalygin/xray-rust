#!/usr/bin/env python3
"""Rehash exact evidence and independently reconstruct all reported summaries."""
import hashlib,importlib.util,json,tarfile,tempfile
from pathlib import Path
REPORT=Path(__file__).resolve().parents[1]
def read(p):return json.loads(p.read_text())
def sha(data):return hashlib.sha256(data).hexdigest()
index=read(REPORT/'evidence-index.json');inputs=read(REPORT/'data/inputs.json');archive=REPORT/index['archive'];assert sha(archive.read_bytes())==index['archive_sha256']
with tempfile.TemporaryDirectory(prefix='v08-duplex-verify-') as tmp:
 root=Path(tmp)
 with tarfile.open(archive) as tar:
  members=tar.getmembers();assert len(members)==len(index['file_sha256']) and {m.name for m in members}==set(index['file_sha256'])
  for m in members:
   assert m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
   data=tar.extractfile(m).read();assert sha(data)==index['file_sha256'][m.name]
   p=root/m.name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(data)
 for name,n in [('normal-controls',54),('normal-confirmation',18),('kernel',24),('libc',24)]:
  m=read(root/name/'manifest.json');assert len(m['runs'])==n
  for version in ['candidate','xray','singbox']:
   identity=inputs[version];assert m['file_hashes'][identity['path']]==identity['sha256']
 for version in ['rust','xray']:
  for i in range(1,5):
   directory=root/f'{version}-duplex-{i}';meta=read(directory/'capture.json');result=read(directory/'client/result.json')
   assert result['status']=='pass' and result['diagnostic_only'] and result['profile_cycles']==meta['cycles']
   assert result['bytes_sent']==meta['verified_bytes']['sent'] and result['bytes_received']==meta['verified_bytes']['received']
   for path,digest in meta['file_hashes'].items():
    suffix=path.split('/xray-rust/',1)[1]
    if suffix in inputs['files']:assert inputs['files'][suffix]==digest
    elif suffix=='target/v08-io-final/bin/xray':assert inputs['xray']['sha256']==digest
    elif path.endswith('/capture.py'):
     source='capture-v1.py' if (version,i)==('rust',1) else 'capture.py'
     assert sha((root/'investigation'/source).read_bytes())==digest
    else:raise AssertionError(path)
   profile=read(directory/'profile-summary.json');assert profile['last_sample_ns']-profile['first_sample_ns']>5_000_000_000
 assert not read(root/'rust-duplex-3-precheck-rejected/attempt.json')['workload_started']
 spec=importlib.util.spec_from_file_location('summarize',REPORT/'data/summarize.py');module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 assert module.run(root)==read(REPORT/'data/summary.json')
 assert inputs['ordinary_release_restored_byte_identically']
 print(json.dumps({'archive_members_verified':len(members),'ordinary_trials':72,'counter_trials':48,'cpu_captures':8,'repeated_cpu_captures':6,'all_summaries_reconstructed':True},indent=2))

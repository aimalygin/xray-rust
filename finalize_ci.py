"""Freeze successful automated checks separately from the original measurements."""
import datetime, gzip, hashlib, io, json, tarfile, zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
CORE = 'eaad8a9359d6da8956d0e0699a60864ccd4be5e9'
MOBILE = '9d656838822b930ba837ea78f14700818fca8453'
EXPECTED = {36341111142: ('aimalygin/xray-rust', CORE, 'core-push'), 36341113954: ('aimalygin/xray-rust', CORE, 'core-pr'), 36341138442: ('aimalygin/xray-rust-mobile', MOBILE, 'mobile-pr')}
data = json.loads((ROOT/'ci-final-runs.json').read_text())
assert {r['databaseId'] for r in data['runs']} == set(EXPECTED)
for run in data['runs']:
    repo, head, name = EXPECTED[run['databaseId']]
    assert run['repository'] == repo and run['headSha'] == head
    assert run['status'] == 'completed' and run['conclusion'] == 'success', (name, run['status'], run['conclusion'])
    assert all(j['conclusion'] in {'success', 'skipped'} for j in run['jobs'])
    log = ROOT/'ci-logs'/f'{name}-{run["databaseId"]}.zip'
    with zipfile.ZipFile(log) as archive:
        assert archive.testzip() is None
source = json.loads((ROOT/'stable-source-validation.json').read_text())
assert source['stable']['revision'] == CORE and source['runtimeAndDependenciesUnchanged'] and not source['newPhysicalDeviceRun']
assert source['result'] == 'accepted-with-exceptions'
paths = [ROOT/name for name in ['ci-final-runs.json', 'ci-artifacts-metadata.json', 'ci-artifacts-sha256.json', 'stable-source-validation.json']]
paths += list((ROOT/'ci-logs').rglob('*')) + list((ROOT/'ci-artifacts').rglob('*'))
files = {}
for path in sorted(paths):
    assert not path.is_symlink()
    if path.is_file():
        files[str(path.relative_to(ROOT))] = path.read_bytes()
record = {
    'schemaVersion': 1, 'kind': 'v0.7.0-stable-ci-confirmation',
    'core': CORE, 'mobile': MOBILE,
    'measuredEvidenceSha256': source['measuredEvidenceSha256'],
    'measuredCandidate': source['measuredCandidate'],
    'scope': 'Successful pre-tag source/SDK CI plus verified source promotion. Required review, exact-source evidence workflow, canonical SDK artifacts, release-tag gates and publication are still separate steps.',
    'runs': [{'repository': r['repository'], 'id': r['databaseId'], 'url': r['url'], 'headSha': r['headSha'], 'result': r['conclusion'], 'successfulJobs': sum(j['conclusion']=='success' for j in r['jobs'])} for r in data['runs']],
    'files': {name: hashlib.sha256(body).hexdigest() for name, body in files.items()},
    'newPhysicalDeviceRun': False, 'publicationReady': False, 'result': 'pass',
}
manifest = (json.dumps(record, indent=2)+'\n').encode()
(ROOT/'automated-validation.json').write_bytes(manifest)
files['manifest.json'] = manifest
archive_path = ROOT/'v07-automated-validation.tar.gz'
with archive_path.open('wb') as output:
    with gzip.GzipFile(fileobj=output, mode='wb', filename='', mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode='w') as archive:
            for name, body in sorted(files.items()):
                info = tarfile.TarInfo(name); info.size=len(body); info.mode=0o644; info.mtime=0
                archive.addfile(info, io.BytesIO(body))
sha = hashlib.sha256(archive_path.read_bytes()).hexdigest()
(ROOT/'AUTOMATED_SHA256SUMS').write_text(f'{sha}  {archive_path.name}\n')
print(json.dumps({'archive':str(archive_path),'sha256':sha,'bytes':archive_path.stat().st_size,'files':len(files),'runs':record['runs']},indent=2))

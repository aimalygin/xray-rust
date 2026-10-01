#!/usr/bin/env python3
"""Verify archive membership and reproduce strict/3% comparison summaries."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tarfile
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--repo', type=Path, required=True)
p.add_argument('--report', type=Path, required=True)
p.add_argument('--rebuild', type=Path, required=True)
a = p.parse_args()
repo, report = a.repo.resolve(), a.report.resolve()
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
index = json.loads((report/'evidence-index.json').read_text())
archive = report/index['archive']
assert sha(archive) == index['archive_sha256']
spec = importlib.util.spec_from_file_location('parity', repo/'scripts/summarize-v07-protocol-parity.py')
parity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(parity)
with tempfile.TemporaryDirectory(prefix='v08-io-verify-', dir=repo/'target') as temporary:
    extracted = Path(temporary)
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        assert len(members) == len(index['file_sha256'])
        assert {m.name for m in members} == set(index['file_sha256'])
        for m in members:
            assert m.isfile() and not Path(m.name).is_absolute() and '..' not in Path(m.name).parts
            content = tar.extractfile(m).read()
            assert hashlib.sha256(content).hexdigest() == index['file_sha256'][m.name], m.name
            destination = extracted/m.name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
    for allowance, name in ((0,'summary-strict.json'), (3,'summary-mac-3pct.json')):
        recomputed = parity.summarize(extracted/'full', allowance)
        assert recomputed == json.loads((report/'data'/name).read_text()), name
inputs = json.loads((report/'data/inputs.json').read_text())
assert sha(a.rebuild) == inputs['candidate']['sha256']
assert sha(Path(inputs['candidate']['path'])) == inputs['candidate']['sha256']
for name, head in (('ci-run.json', inputs['candidate']['commit']),
                   ('mobile-ci-run.json','a735aae5e7916f18c0125afa28e509a9ddd48c2c')):
    ci = json.loads((report/'data'/name).read_text())
    assert ci['headSha'] == head and ci['conclusion'] == 'success', name
result = {'archive_files_verified':len(index['file_sha256']),
          'strict_summary_recomputed':True,'mac_3pct_summary_recomputed':True,
          'runtime_commit':inputs['candidate']['commit'],
          'release_rebuild_sha256':{str(a.rebuild):sha(a.rebuild)},
          'candidate_sha256':inputs['candidate']['sha256'],
          'exact_runtime_core_and_sdk_ci_pass':True}
(report/'data/verification.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
print(json.dumps(result,indent=2))

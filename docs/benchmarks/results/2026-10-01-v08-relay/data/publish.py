#!/usr/bin/env python3
"""Archive exact numeric evidence; deliberately exclude generated credentials."""
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tarfile

root = Path(sys.argv[1]).resolve()
source = root / 'target/v08-relay-investigation'
report = root / 'docs/benchmarks/results/2026-10-01-v08-relay'
report.mkdir(parents=True, exist_ok=False)
data = report / 'data'; data.mkdir()

def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
def save(path, value): path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value

full = source / 'full'
manifest = json.loads((full / 'manifest.json').read_text())
assert len(manifest['runs']) == 630 and manifest['repeats'] == 3
assert all(not r['ambient_cpu']['compiler_load_detected'] and not r['ambient_cpu']['observer_errors'] and r['process_group_empty_after_run'] and not r['remaining_engine_processes'] and not r['surviving_process_group'] for r in manifest['runs'])
for path, digest in manifest['file_hashes'].items(): assert sha(Path(path)) == digest, path
parity = module('parity', root / 'scripts/summarize-v07-protocol-parity.py')
for allowance, name in [(0, 'summary-strict.json'), (3, 'summary-mac-3pct.json')]:
    save(data / name, parity.summarize(full, allowance))
controls = module('controls', source / 'summarize.py')
save(data / 'control-summary.json', controls.summarize(source))
for name in ['inputs.json', 'host.json', 'builds.json', 'ci-run.json', 'mobile-ci-run.json', 'ci-initial-failure.json', 'ci-attempt-1-final.json', 'fixture-ci.json', 'summarize.py', 'publish.py', 'verify.py']:
    shutil.copyfile(source / name, data / name)
files = {}
with tarfile.open(report / 'measurements.tar.gz', 'w:gz') as archive:
    def add(path, name):
        assert name not in files
        files[name] = sha(path); archive.add(path, arcname=name, recursive=False)
    for group in ['full', 'isolated-controls', 'batched-controls', 'batched-clean-controls', 'aes-upload-confirmation', 'aes-download-confirmation', 'final-controls', 'final-clean-controls', 'held-memory', 'final-held-memory', 'stack-controls', 'stack-held-memory', 'ss-aes-duplex-confirmation', 'profile-baseline']:
        folder = source / group
        m = json.loads((folder / 'manifest.json').read_text())
        add(folder / 'manifest.json', group + '/manifest.json')
        if (folder / 'source.patch').exists(): add(folder / 'source.patch', group + '/source.patch')
        for run in m['runs']:
            trial = folder / run['output_relative']
            if (trial / 'result.json').exists(): add(trial / 'result.json', group + '/' + run['output_relative'] + '/result.json')
            if run.get('returncode'):
                for path in [trial / 'stdout.log', trial / 'stderr.log', folder / (run['output_relative'] + '.log')]:
                    if path.exists(): add(path, group + '/' + str(path.relative_to(folder)))
        if (folder / 'selection.json').exists(): add(folder / 'selection.json', group + '/selection.json')
        for attempt_manifest in sorted((folder / 'attempts').glob('*/manifest.json')):
            attempt = attempt_manifest.parent
            attempted = json.loads(attempt_manifest.read_text())
            paths = [attempt_manifest, attempt / 'source.patch']
            for run in attempted['runs']:
                trial = attempt / run['output_relative']
                paths.append(trial / 'result.json')
                if run['returncode']:
                    paths.extend([trial / 'stdout.log', trial / 'stderr.log', attempt / (run['output_relative'] + '.log')])
            for path in paths:
                if path.exists(): add(path, group + '/' + str(path.relative_to(folder)))
        if group == 'profile-baseline':
            for path in sorted(folder.glob('*.sample.txt')): add(path, group + '/' + path.name)
    for name in ['builds.json', 'padding.patch', 'relay.patch', 'relay-v2.patch', 'batched.patch', 'combined.patch', 'candidate.patch', 'profile.py', 'held-memory.py', 'relay-tests.log', 'proxy-tests.log', 'clippy.log', 'final-tests.log', 'final-core-tests.log', 'final-clippy.log', 'final-build.log', 'committed-rebuild.log', 'stack.patch', 'stack-tests.log', 'stack-clippy.log', 'stack-build.log', 'stack-core-tests.log', 'stack-rebuild.log', 'collector-tests.log', 'ci-rust-failure.log', 'ffi-test.patch', 'ffi-tests.log', 'mobile-verification.log']:
        add(source / name, 'investigation/' + name)
for name in ['run-v08-comparison-blocks.py', 'run-v08-cpu-controls.py', 'run-v08-protocol-comparison.py']:
    shutil.copyfile(root / 'scripts' / name, data / name)
save(report / 'evidence-index.json', dict(archive='measurements.tar.gz', archive_sha256=sha(report / 'measurements.tar.gz'), file_sha256=files,
    excluded_from_performance=['batched-controls (external xcodebuild overlap)', 'profile-baseline (instrumented)', 'contaminated full/attempts case blocks; all attempts and selection retained', 'incomplete or contaminated final-controls case blocks (ANECompilerService); exact selection retained in final-clean-controls/selection.json'],
    scope='Exact numeric results, manifests, variant patches and test logs; generated fixture credentials and binaries remain local.'))
print(f'Archived {len(files)} exact evidence files in {report}')

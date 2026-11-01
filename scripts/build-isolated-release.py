#!/usr/bin/env python3
"""Build one revision's release binary in isolation and record provenance.

Before/after comparisons must never share a Cargo target directory. Cargo's
artifact hash for a workspace crate does not include the checkout's absolute
path, and freshness is decided by file mtimes. A second checkout whose files
look older than the first build's artifacts silently reuses those artifacts.
That is how the 2026-10-27 migration campaign's "before" client got the
migration's `xray-config` and `xray-utls`.

This script exports the exact commit into a fresh temporary directory outside
the repository, builds it with an empty target directory and a sanitized
environment, and fails unless every workspace package in the build was
compiled from that export. It writes the binary and a JSON record whose keys
match the migration collector's `inputs.json` entries.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
# Anything that could change code generation or reuse outputs across builds.
SANITIZED_ENV = ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS', 'RUSTC_WRAPPER',
                 'RUSTC_WORKSPACE_WRAPPER', 'CARGO_BUILD_RUSTC_WRAPPER', 'CARGO_TARGET_DIR',
                 'CARGO_BUILD_TARGET_DIR', 'CARGO_INCREMENTAL')


def sha256(path):
    digest = hashlib.sha256()
    with open(path, 'rb') as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b''):
            digest.update(chunk)
    return digest.hexdigest()


def git(*args):
    return subprocess.run(['git', *args], cwd=ROOT, check=True, capture_output=True).stdout


def export(commit, destination):
    """Extract the committed tree; uncommitted local edits cannot leak in."""
    archive = git('archive', '--format=tar', commit)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        for member in tar.getmembers():
            # git archive output is trusted, but refuse paths escaping the export.
            target = (destination / member.name).resolve()
            if destination.resolve() not in (target, *target.parents):
                raise ValueError(f'unsafe archive path: {member.name}')
        tar.extractall(destination)


def compiled_workspace_packages(messages, source):
    """Return workspace packages built from `source`; reject reused or foreign ones."""
    source = source.resolve()
    compiled, foreign, fresh = set(), set(), set()
    for line in messages.splitlines():
        if not line.startswith('{'):
            continue
        message = json.loads(line)
        if message.get('reason') != 'compiler-artifact':
            continue
        if 'registry+' in message['package_id'] or 'git+' in message['package_id']:
            continue
        manifest = Path(message['manifest_path']).resolve()
        if source not in manifest.parents:
            foreign.add(str(manifest))
            continue
        # Workspace members and vendored path crates, e.g. `crates/xray-config`.
        package = str(manifest.parent.relative_to(source))
        (fresh if message.get('fresh') else compiled).add(package)
    if foreign:
        raise RuntimeError(f'path packages outside the export were built: {sorted(foreign)}')
    if fresh:
        raise RuntimeError(f'workspace packages were reused instead of compiled: {sorted(fresh)}')
    if not compiled:
        raise RuntimeError('no workspace package was compiled')
    return sorted(compiled)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--rev', required=True, help='commit, tag or branch to build')
    parser.add_argument('--name', required=True, help='label, e.g. before, after or harness')
    parser.add_argument('--campaign', type=Path, required=True,
                        help='writes bin/NAME and build/NAME.json here; refuses to overwrite')
    parser.add_argument('--package', action='append', default=None,
                        help='cargo package to build (repeatable; default xray-cli)')
    parser.add_argument('--binary', default='xray-rust', help='binary to freeze from target/release')
    parser.add_argument('--keep', action='store_true', help='keep the temporary export and target directory')
    a = parser.parse_args()
    packages = a.package or ['xray-cli']

    commit = git('rev-parse', '--verify', a.rev + '^{commit}').decode().strip()
    tree = git('rev-parse', commit + '^{tree}').decode().strip()
    binary_out = a.campaign / 'bin' / a.name
    record_out = a.campaign / 'build' / (a.name + '.json')
    for path in (binary_out, record_out):
        if path.exists():
            raise FileExistsError(f'{path} exists; frozen inputs are never overwritten')

    work = Path(tempfile.mkdtemp(prefix=f'xray-isolated-{a.name}-'))
    source, target = work / 'src', work / 'target'
    source.mkdir()
    try:
        export(commit, source)
        env = {k: v for k, v in os.environ.items()
               if k not in SANITIZED_ENV and not k.startswith('CARGO_PROFILE_')}
        env.update(CARGO_TARGET_DIR=str(target), CARGO_INCREMENTAL='0')
        command = ['cargo', 'build', '--locked', '--release']
        for package in packages:
            command += ['-p', package]
        build = subprocess.run([*command, '--message-format=json-render-diagnostics'],
                               cwd=source, env=env, capture_output=True, text=True)
        sys.stderr.write(build.stderr)
        if build.returncode != 0:
            raise RuntimeError(f'cargo build failed with status {build.returncode}')
        compiled = compiled_workspace_packages(build.stdout, source)

        built = target / 'release' / a.binary
        binary_out.parent.mkdir(parents=True, exist_ok=True)
        record_out.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(built, binary_out)
        version = lambda tool: subprocess.run([tool, '-vV' if tool == 'rustc' else '-V'], cwd=source, env=env,
                                              check=True, capture_output=True, text=True).stdout
        record = {
            'commit': commit, 'tree': tree, 'lock_sha256': sha256(source / 'Cargo.lock'),
            'rustc': version('rustc'), 'cargo': version('cargo'), 'command': ' '.join(command),
            'incremental': False, 'rustflags': None,
            'path': str(binary_out.resolve()), 'sha256': sha256(binary_out),
            'isolated_target': True, 'workspace_packages_compiled': compiled,
        }
        record_out.write_text(json.dumps(record, indent=2) + '\n')
        print(json.dumps({'name': a.name, 'commit': commit, 'sha256': record['sha256'],
                          'workspace_packages_compiled': len(compiled)}))
    finally:
        if a.keep:
            print(f'kept {work}', file=sys.stderr)
        else:
            shutil.rmtree(work, ignore_errors=True)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""Prepare an isolated comparison directory from explicitly selected binaries.

This does not download, build, or alter any supplied implementation. Build pinned
references first; the collector retains SHA256s for the real measured binaries.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


def sha256(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    for name in ['rust', 'harness', 'xray', 'singbox', 'hysteria', 'wireguard']:
        p.add_argument('--' + name, type=Path, required=True)
    a = p.parse_args()
    paths = {n: getattr(a, n).resolve(strict=True) for n in ['rust', 'harness', 'xray', 'singbox', 'hysteria', 'wireguard']}
    root = a.root.resolve()
    root.mkdir(exist_ok=False, parents=True)
    binaries = root / 'bin'
    binaries.mkdir()
    for name, key in [('rust-before', 'rust'), ('protocol-bench', 'harness'), ('xray-core', 'xray')]:
        (binaries / name).symlink_to(paths[key])
    for mode in ['xray', 'singbox', 'native']:
        wrapper = binaries / (mode + '-client')
        shutil.copyfile(Path(__file__).with_name('v07-reference-client.py'), wrapper)
        wrapper.chmod(0o755)
        Path(str(wrapper) + '.json').write_text(json.dumps({'mode': mode, 'binaries': {n: str(paths[n]) for n in ['xray', 'singbox', 'hysteria', 'wireguard']}}, indent=2) + '\n')
    (root / 'inputs.json').write_text(json.dumps({n: {'path': str(path), 'sha256': sha256(path)} for n, path in paths.items()}, indent=2) + '\n')
    print(root)


if __name__ == '__main__':
    main()

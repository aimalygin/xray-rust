#!/usr/bin/env python3
"""Normalize the already verified/patched upstream tree into the vendored crate."""
import argparse
import json
from pathlib import Path
import re
import shutil
import tomllib


def literal(value):
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return '[' + ', '.join(literal(x) for x in value) + ']'
    return '{ ' + ', '.join(k + ' = ' + literal(v) for k, v in value.items()) + ' }'


def prepare(source, destination):
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source / 'gotatun/src', destination / 'src', dirs_exist_ok=True)
    for name in ['LICENSE', 'LICENSE-CLOUDFLARE', 'README.md']:
        shutil.copyfile(source / name, destination / name)
    workspace = tomllib.loads((source / 'Cargo.toml').read_text())['workspace']
    manifest = (source / 'gotatun/Cargo.toml').read_text()
    for key, value in workspace['package'].items():
        manifest = manifest.replace(key + '.workspace = true', key + ' = ' + literal(value))
    for key, value in workspace['dependencies'].items():
        replacement = 'version = ' + literal(value) if isinstance(value, str) else ', '.join(k + ' = ' + literal(v) for k, v in value.items())
        pattern = re.compile(r'^' + re.escape(key) + r' = \{ workspace = true(?P<tail>.*)$', re.M)
        def substitute(match):
            fields = replacement
            if 'default-features' in match['tail']:
                fields = re.sub(r',? default-features = (true|false)', '', fields)
            return key + ' = { ' + fields + match['tail']
        manifest = pattern.sub(substitute, manifest)
    manifest = re.sub(r'\[\[bench\]\]\n(?:(?!\[)[^\n]*\n)*', '', manifest)
    assert 'workspace = true' not in manifest
    assert 'device' in tomllib.loads(manifest)['features']
    (destination / 'Cargo.toml').write_text(manifest)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    prepare(args.source, args.destination)

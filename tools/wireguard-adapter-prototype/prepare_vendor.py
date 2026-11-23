#!/usr/bin/env python3
"""Normalize the already verified/patched upstream tree into the vendored crate."""
import argparse
import json
from pathlib import Path
import re
import shutil
import tomllib

# The vendored crate is a fork published under a name of its own. Its version
# is X.Y.PPRR: upstream patch release PP, fork release RR.
PACKAGE = 'xray-gotatun'
FORK_RELEASE = 0
REPOSITORY = 'https://github.com/aimalygin/xray-rust'
DESCRIPTION = (
    'A fork of gotatun {upstream}, a userspace WireGuard implementation, with '
    'opt-in bounded device resources and zeroizing preshared keys.'
)
README_NOTICE = '''\
# xray-gotatun

xray-gotatun is a fork of [GotaTun](https://github.com/mullvad/gotatun)
{upstream}, published for [xray-rust]({repository}). It is not affiliated with
or endorsed by Mullvad or the GotaTun project: please report its bugs
[to xray-rust]({repository}/issues), not upstream.

The library is still named `gotatun`:

```toml
gotatun = {{ package = "xray-gotatun", version = "{version}" }}
```

A version is `X.Y.PPRR`: GotaTun patch release `PP`, fork release `RR`.
`XRAY-PATCH.md` in this package describes the changes and how this source is
reproduced from upstream's commit; the patches are in
[xray-rust]({repository}/tree/main/tools/wireguard-adapter-prototype/patches).

Everything below is upstream's own README.

---

'''


def literal(value):
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, bool):
        return str(value).lower()
    if isinstance(value, list):
        return '[' + ', '.join(literal(x) for x in value) + ']'
    return '{ ' + ', '.join(k + ' = ' + literal(v) for k, v in value.items()) + ' }'


def set_field(manifest, key, value):
    """Replace the manifest's one top-level `key = ...` line."""
    manifest, count = re.subn(
        r'^' + re.escape(key) + r' = .*$', lambda _: key + ' = ' + literal(value), manifest, flags=re.M
    )
    assert count == 1, (key, count)
    return manifest


def prepare(source, destination):
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source / 'gotatun/src', destination / 'src', dirs_exist_ok=True)
    for name in ['LICENSE', 'LICENSE-CLOUDFLARE']:
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

    package = tomllib.loads(manifest)['package']
    upstream = package['version']
    major, minor, patch = (int(part) for part in upstream.split('.'))
    version = f'{major}.{minor}.{patch * 100 + FORK_RELEASE}'
    assert package['name'] == 'gotatun'
    manifest = set_field(manifest, 'name', PACKAGE)
    manifest = set_field(manifest, 'version', version)
    manifest = set_field(manifest, 'description', DESCRIPTION.format(upstream=upstream))
    manifest = set_field(manifest, 'repository', REPOSITORY)
    # Without a name the library would be `xray_gotatun`.
    assert manifest.count('\n[lib]\n') == 1
    manifest = manifest.replace('\n[lib]\n', '\n[lib]\nname = "gotatun"\n')
    renamed = tomllib.loads(manifest)
    assert renamed['package']['name'] == PACKAGE and renamed['package']['version'] == version
    assert renamed['lib']['name'] == 'gotatun'
    (destination / 'Cargo.toml').write_text(manifest)

    notice = README_NOTICE.format(upstream=upstream, version=version, repository=REPOSITORY)
    (destination / 'README.md').write_text(notice + (source / 'README.md').read_text())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    prepare(args.source, args.destination)

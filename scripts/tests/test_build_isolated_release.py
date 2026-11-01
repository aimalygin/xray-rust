import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('isolated', ROOT / 'scripts/build-isolated-release.py')
isolated = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(isolated)


def artifact(package_id, manifest, fresh):
    return json.dumps({'reason': 'compiler-artifact', 'package_id': package_id,
                       'manifest_path': str(manifest), 'fresh': fresh, 'target': {'name': 'x'}})


class IsolatedReleaseBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.source = Path(self.temp.name) / 'src'
        (self.source / 'crates/xray-config').mkdir(parents=True)
        (self.source / 'vendor/quinn').mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def path_artifact(self, relative, fresh=False):
        manifest = self.source / relative / 'Cargo.toml'
        return artifact(f'path+file://{manifest.parent}#0.8.1', manifest, fresh)

    def test_compiled_workspace_and_vendored_packages_are_recorded(self):
        messages = '\n'.join([
            'Compiling text that is not JSON',
            artifact('registry+https://github.com/rust-lang/crates.io-index#libc@0.2.186',
                     '/registry/libc/Cargo.toml', True),
            self.path_artifact('crates/xray-config'),
            self.path_artifact('vendor/quinn'),
            json.dumps({'reason': 'build-finished', 'success': True}),
        ])
        self.assertEqual(isolated.compiled_workspace_packages(messages, self.source),
                         ['crates/xray-config', 'vendor/quinn'])

    def test_reused_workspace_artifact_fails_closed(self):
        # The 2026-10-27 "before" client reused xray-config this way.
        messages = '\n'.join([self.path_artifact('vendor/quinn'),
                              self.path_artifact('crates/xray-config', fresh=True)])
        with self.assertRaisesRegex(RuntimeError, 'reused instead of compiled.*xray-config'):
            isolated.compiled_workspace_packages(messages, self.source)

    def test_path_package_from_another_checkout_fails_closed(self):
        other = Path(self.temp.name) / 'other/crates/xray-utls/Cargo.toml'
        messages = '\n'.join([self.path_artifact('crates/xray-config'),
                              artifact(f'path+file://{other.parent}#0.8.1', other, False)])
        with self.assertRaisesRegex(RuntimeError, 'outside the export'):
            isolated.compiled_workspace_packages(messages, self.source)

    def test_build_without_workspace_packages_fails_closed(self):
        with self.assertRaisesRegex(RuntimeError, 'no workspace package'):
            isolated.compiled_workspace_packages('', self.source)


if __name__ == '__main__':
    unittest.main()

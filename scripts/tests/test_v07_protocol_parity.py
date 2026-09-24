"""A failed or misidentified comparison must never be reported as parity."""
import importlib.util
from pathlib import Path
import unittest
import tempfile
import json


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


launcher = module('parity_client', 'v07-reference-client.py')
summary = module('parity_summary', 'summarize-v07-protocol-parity.py')


class ParityTests(unittest.TestCase):
    def test_uncertainty_does_not_invent_samples(self):
        self.assertIsNone(summary.ratio_interval([1, 1], [1, 1]))
        self.assertIsNone(summary.ratio_interval([1, 1, 1], [0, 0, 0]))
        self.assertEqual(summary.ratio_interval([2, 2, 2], [1, 1, 1]), [2, 2])

    def evidence(self, root, equal_memory=False, fail=False):
        case={'id':'test','path':'socks','traffic':'udp','connections':1,'iterations':10,'payload_size':1200}
        manifest={'cases':[case],'versions':{'candidate':{},'reference':{}},'repeats':3,'suite':'new','smoke':False,'runs':[]}
        for version in manifest['versions']:
            candidate=version=='candidate'
            for repeat in range(1,4):
                name=version+str(repeat);directory=root/name;directory.mkdir()
                data={**case,'status':'pass','bytes_sent':12000,'bytes_received':12000,
                      'samples':[{},{}],'throughput_mib_s':20 if candidate else 10,
                      'peak_rss_kib':4096 if candidate or equal_memory else 8192,
                      'cpu_millis':10 if candidate else 20,'latency_us':{'median':10 if candidate else 20}}
                (directory/'result.json').write_text(json.dumps(data))
                manifest['runs'].append({'case':'test','version':version,'repeat':repeat,'output_relative':name,
                                         'returncode':1 if fail and candidate and repeat==2 else 0})
        (root/'manifest.json').write_text(json.dumps(manifest))

    def test_strict_memory_target_and_failures_are_not_waived(self):
        for equal_memory,fail in [(False,False),(True,False),(False,True)]:
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);self.evidence(root,equal_memory,fail)
                result=summary.summarize(root)
                expected='observed_targets_met' if not equal_memory and not fail else 'not_met'
                self.assertEqual(result['parity']['status'],expected)
                if fail:self.assertEqual(result['rows'][0]['versions']['candidate']['metrics'],{})

    def test_environmental_interference_invalidates_positive_results(self):
        for in_manifest in (False, True):
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);self.evidence(root)
                if in_manifest:
                    path=root/'manifest.json';manifest=json.loads(path.read_text())
                    manifest['runs'][0]['ambient_cpu']={'compiler_load_detected':[{'pid':123,'cpu':100}]}
                    path.write_text(json.dumps(manifest))
                else:
                    (root/'measurement-quality.json').write_text(json.dumps({'compiler_load_detected':True}))
                self.assertEqual(summary.summarize(root)['parity']['status'], 'invalid_measurements')

    def test_internal_control_is_retained_but_does_not_masquerade_as_reference(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.evidence(root, equal_memory=True)
            (root/'measurement-quality.json').write_text(json.dumps({
                'internal_controls':['reference'], 'external_references':[]}))
            result=summary.summarize(root)
            self.assertEqual(result['rows'][0]['comparisons']['reference']['role'], 'internal_control')
            self.assertEqual(result['parity']['reference_comparisons'], 0)
            self.assertEqual(result['parity']['point_deficit_metrics'], 0)
            self.assertEqual(result['parity']['status'], 'not_met')

    def test_explicit_comparison_roles_require_every_engine(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.evidence(root)
            (root/'measurement-quality.json').write_text(json.dumps({'external_references':[]}))
            with self.assertRaisesRegex(ValueError, 'comparison roles missing'):
                summary.summarize(root)

    def test_explicit_three_percent_allowance_preserves_strict_differences(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.evidence(root)
            for path in root.glob('*/result.json'):
                data=json.loads(path.read_text());candidate=path.parent.name.startswith('candidate')
                data.update(throughput_mib_s=97 if candidate else 100,
                            cpu_millis=103 if candidate else 100,
                            latency_us={'median':103 if candidate else 100,'p95':103 if candidate else 100,'p99':103 if candidate else 100})
                path.write_text(json.dumps(data))
            self.assertEqual(summary.summarize(root)['parity']['status'], 'not_met')
            allowed=summary.summarize(root,3)
            self.assertEqual(allowed['parity']['status'], 'observed_targets_met')
            self.assertGreater(allowed['parity']['strict_point_deficit_metrics'],0)
            metric=allowed['rows'][0]['comparisons']['reference']['metrics']['throughput_mib_s']
            self.assertFalse(metric['meets_strict_point_target'])
            self.assertEqual(metric['ratio'],.97)
            # All three repeats must move beyond the boundary; one sample does
            # not change the median and should remain an uncertainty question.
            for path in root.glob('candidate*/result.json'):
                data=json.loads(path.read_text());data['throughput_mib_s']=96.99;path.write_text(json.dumps(data))
            self.assertEqual(summary.summarize(root,3)['parity']['status'],'not_met')

    def test_allowance_boundaries_for_each_metric(self):
        for metric in ['cpu_ms','latency_us','latency_p95_us','latency_p99_us','client_startup_seconds']:
            with self.subTest(metric=metric):
                self.assertTrue(summary.point_target(metric,103,100,3))
                self.assertFalse(summary.point_target(metric,103.01,100,3))
        self.assertTrue(summary.point_target('throughput_mib_s',97,100,3))
        self.assertFalse(summary.point_target('throughput_mib_s',96.99,100,3))
        self.assertFalse(summary.point_target('rss_mib',100,100,3))
        self.assertFalse(summary.point_target('rss_mib',101,100,3))

    def test_allowance_cannot_waive_memory_failure_or_interference(self):
        for equal_memory,fail in [(True,False),(False,True)]:
            with tempfile.TemporaryDirectory() as temp:
                root=Path(temp);self.evidence(root,equal_memory,fail)
                self.assertEqual(summary.summarize(root,3)['parity']['status'],'not_met')
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.evidence(root)
            (root/'measurement-quality.json').write_text(json.dumps({'compiler_load_detected':True}))
            self.assertEqual(summary.summarize(root,3)['parity']['status'],'invalid_measurements')

    def test_allowance_does_not_turn_wide_intervals_into_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.evidence(root)
            for version in ['candidate','reference']:
                for repeat in range(1,4):
                    path=root/(version+str(repeat))/'result.json';data=json.loads(path.read_text())
                    data['throughput_mib_s']=[9,10,11][repeat-1] if version=='candidate' else 10
                    path.write_text(json.dumps(data))
            self.assertEqual(summary.summarize(root,3)['parity']['status'],'unproven')

    def test_invalid_allowance_is_rejected_before_reading_measurements(self):
        for value in [-1,100,float('nan'),float('inf')]:
            with self.assertRaisesRegex(ValueError,'allowance'):
                summary.summarize(Path('/unused'),value)

    def test_reference_requires_loopback_socks(self):
        for inbound in [{'protocol': 'tun'}, {'protocol': 'socks', 'listen': '0.0.0.0'}]:
            with self.assertRaises(ValueError):
                launcher.translate({'inbounds': [inbound], 'outbounds': [{}]}, 'native', '')

    def test_native_hysteria_preserves_auth_and_certificate_pin(self):
        config = {'inbounds': [{'protocol': 'socks', 'listen': '127.0.0.1', 'port': 1234}],
                  'outbounds': [{'protocol': 'hysteria', 'settings': {'address': '127.0.0.1', 'port': 4321},
                                 'streamSettings': {'tlsSettings': {'serverName': 'fixture', 'pinnedPeerCertSha256': 'a' * 64}, 'hysteriaSettings': {'auth': 'fixture-auth'}}}]}
        translated, args, kind = launcher.translate(config, 'native', '')
        self.assertEqual(translated['tls']['pinSHA256'], 'a' * 64)
        self.assertEqual(translated['auth'], 'fixture-auth')
        self.assertEqual(kind, 'hysteria')
        self.assertEqual(args[0], 'client')
        config['outbounds'][0]['settings']['address'] = '192.0.2.1'
        with self.assertRaises(ValueError):
            launcher.translate(config, 'native', '')


if __name__ == '__main__':
    unittest.main()

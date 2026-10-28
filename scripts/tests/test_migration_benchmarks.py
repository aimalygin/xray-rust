"""Pre/post evidence must preserve matched workloads and reject bad trials."""
import copy
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('migration', Path(__file__).resolve().parents[1] / 'run-migration-benchmarks.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class MigrationTests(unittest.TestCase):
    def test_case_coverage_preserves_seven_cipher_axes_and_both_tunnel_paths(self):
        rows = m.cases()
        self.assertEqual(len(rows), 200)
        self.assertEqual(len({r['id'] for r in rows}), len(rows))
        self.assertEqual([r for r in rows if r['profile'] in m.c.PROFILES], m.c.cases(m.c.PROFILES))
        for profile in ('hysteria2', 'wireguard'):
            self.assertEqual({(r['path'], r['traffic'], r['connections']) for r in rows if r['profile'] == profile},
                             {(p, t, n) for p in ('socks', 'tun') for t in (*m.BULK, 'tcp-latency', 'udp') for n in (1, 8)})

    def test_odd_repeat_order_imbalance_cancels_across_adjacent_cases(self):
        for index in range(0, 200, 2):
            orders = [m.order(i, repeat) for i in (index, index + 1) for repeat in range(1, 6)]
            for version in m.VERSIONS:
                self.assertEqual(sum(o[0] == version for o in orders), 5)
            self.assertNotEqual(m.order(index, 1), m.order(index, 2))

    def test_protocol_cleanup_observer_and_contamination_errors_fail_closed(self):
        clean = dict(returncode=0, process_group_empty_after_run=True, surviving_process_group=False,
                     remaining_engine_processes=[], ambient_cpu=dict(observer_errors=[], compiler_load_detected=[], heavy_external_load=False))
        self.assertTrue(m.clean(clean))
        for key, value in [('returncode', 1), ('process_group_empty_after_run', False),
                           ('surviving_process_group', True), ('remaining_engine_processes', ['child'])]:
            bad = copy.deepcopy(clean); bad[key] = value
            self.assertFalse(m.clean(bad))
        for key, value in [('observer_errors', ['ps failed']), ('compiler_load_detected', ['cargo']), ('heavy_external_load', True)]:
            bad = copy.deepcopy(clean); bad['ambient_cpu'][key] = value
            self.assertFalse(m.clean(bad))

    def test_interval_cpu_excludes_own_children_and_detects_unrelated_node_load(self):
        own = os.getpid()
        old = {own: dict(parent=1, seconds=0, name='python'), 999991: dict(parent=own, seconds=0, name='after'),
               999992: dict(parent=1, seconds=0, name='node')}
        new = copy.deepcopy(old)
        new[999991]['seconds'] = 5
        self.assertFalse(m.ambient(old, new, 1)['heavy_external_load'])
        new[999992]['seconds'] = 1.1
        sample = m.ambient(old, new, 1)
        self.assertTrue(sample['heavy_external_load'])
        self.assertAlmostEqual(sample['external_cpu_percent'], 110)
        self.assertEqual(m.cpu_seconds('1-02:03:04.50'), 93784.5)

    def test_reality_requires_local_origin_and_fresh_matched_key(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            with self.assertRaises(ValueError):
                m.configs('reality-vision', path, 'example.com:443')
            client, server = m.configs('reality-vision', path, '127.0.0.1:12345')
            cs, ss = client['outbounds'][0]['streamSettings'], server['inbounds'][0]['streamSettings']
            self.assertEqual(cs['realitySettings']['serverName'], ss['realitySettings']['serverNames'][0])
            self.assertEqual(ss['realitySettings']['dest'], '127.0.0.1:12345')
            first = cs['realitySettings']['publicKey']
            self.assertNotEqual(first, m.configs('reality-vision', path, '127.0.0.1:12345')[0]['outbounds'][0]['streamSettings']['realitySettings']['publicKey'])


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('publisher', Path(__file__).resolve().parents[1] / 'publish-migration-benchmarks.py')
        cls.p = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.p)

    def test_missing_matrix_and_smoke_cannot_be_published(self):
        with self.assertRaisesRegex(ValueError, 'incomplete 200-case'):
            self.p.summarize({}, [])
        import json
        entry = {'smoke/manifest.json': json.dumps(dict(status='pass', smoke=True, repeats=1))}
        with self.assertRaisesRegex(ValueError, 'non-publication'):
            self.p.summarize(entry, ['smoke'])

    def test_runtime_validation_rejects_wrong_binary_axes_bytes_and_overrides(self):
        case = m.cases()[0]
        run = dict(version='before', output_relative='trial', returncode=0,
            process_group_empty_after_run=True, surviving_process_group=False, remaining_engine_processes=[],
            ambient_cpu=dict(samples=[{}], observer_errors=[], compiler_load_detected=[], heavy_external_load=False))
        result = {k: case[k] for k in ('path', 'traffic', 'connections', 'iterations', 'payload_size')}
        count = case['connections'] * case['iterations'] * case['payload_size']
        result.update(status='pass', engine_sha256='abc', idle_connections=0, prepare_client=False, client_env={},
            warmup=True, client_preface=True, bytes_sent=count, bytes_received=0, transfer_seconds=1,
            peak_rss_kib=1024, samples=[{}, {}], throughput_mib_s=count / 2**20, cpu_millis=100,
            client_startup_seconds=.1, latency_us=None, ready_latency_us=None)
        inputs = {'before': {'sha256': 'abc'}}
        self.assertEqual(self.p.validate_trial(case, run, result, inputs)['rss_mib'], 1)
        for key, value in [('engine_sha256', 'wrong'), ('bytes_sent', count - 1), ('connections', 8),
                           ('client_env', {'TOKIO_WORKER_THREADS': '1'}), ('warmup', False),
                           ('throughput_mib_s', 123), ('status', 'fail')]:
            bad = copy.deepcopy(result); bad[key] = value
            with self.assertRaises(ValueError, msg=key):
                self.p.validate_trial(case, run, bad, inputs)

    def test_pairing_is_by_repeat_not_ratio_of_independent_medians(self):
        before, after = [1, 10, 100, 1000, 10000], [2, 10, 50, 2000, 10000]
        r = self.p.paired(before, after)
        self.assertEqual(r['samples'], [2, 1, .5, 2, 1])
        self.assertEqual(r['median'], 1)
        self.assertEqual(r['bootstrap_95_percentile'], [.5, 2])
        self.assertIsNone(self.p.paired([0] * 5, after))

    def test_public_manifest_omits_unrelated_process_identity_without_changing_cpu_evidence(self):
        source = {'runs': [{'ambient_cpu': {'compiler_load_detected': [], 'samples': [dict(compiler_load_detected=[], external_cpu_percent=125, top_external=[dict(name='Private App', pid=123, cpu_percent=80)])]}}]}
        redacted = self.p.public_manifest(source)
        sample = redacted['runs'][0]['ambient_cpu']['samples'][0]
        self.assertNotIn('top_external', sample)
        self.assertEqual(sample['external_cpu_percent'], 125)
        self.assertEqual(sample['peak_external_process_cpu_percent'], 80)
        self.assertIn('top_external', source['runs'][0]['ambient_cpu']['samples'][0])


if __name__ == '__main__':
    unittest.main()

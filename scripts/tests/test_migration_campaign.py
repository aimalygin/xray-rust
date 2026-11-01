"""The campaign controller retries only environment rejections and resumes."""
import importlib.util
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('campaign', Path(__file__).resolve().parents[1] / 'run-migration-campaign.py')
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)

CASES = [{'id': 'a'}, {'id': 'b'}]


def trial(returncode=0, heavy=False):
    return dict(returncode=returncode, remaining_engine_processes=[], surviving_process_group=False,
                process_group_empty_after_run=True,
                ambient_cpu=dict(observer_errors=[], heavy_external_load=heavy, compiler_load_detected=[]))


class FakeCollector:
    """Writes the manifest a collector block would leave; outcomes are queued per block prefix."""

    def __init__(self, campaign, outcomes):
        self.campaign, self.outcomes, self.calls = campaign, outcomes, []

    def __call__(self, name, extra):
        self.calls.append(name)
        prefix = name.rsplit('-', 1)[0]
        outcome = self.outcomes[prefix].pop(0)
        case = [{'id': prefix.removeprefix('case-')}]
        runs = {'pass': [trial()], 'noise': [trial(), trial(heavy=True)], 'broken': [trial(), trial(returncode=1)]}[outcome]
        (self.campaign / name).mkdir()
        (self.campaign / name / 'manifest.json').write_text(json.dumps(
            dict(status='pass' if outcome == 'pass' else 'fail', cases=case, runs=runs)))
        return 0 if outcome == 'pass' else 1


class CampaignControllerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.campaign = Path(self.temp.name)
        self.quiet_calls = 0

    def tearDown(self):
        self.temp.cleanup()

    def quiet(self):
        self.quiet_calls += 1

    def run_campaign(self, collector, limit=10):
        with redirect_stdout(io.StringIO()) as out:
            c.run_campaign(self.campaign, CASES, limit, collector, self.quiet)
        return out.getvalue()

    def accepted(self):
        return json.loads((self.campaign / 'accepted-blocks.json').read_text())

    def test_environment_rejections_are_retried_after_waiting_for_quiet(self):
        collector = FakeCollector(self.campaign, {'smoke': ['noise', 'pass'], 'case-a': ['noise', 'pass'], 'case-b': ['pass']})
        out = self.run_campaign(collector)
        self.assertEqual(collector.calls, ['smoke-1', 'smoke-2', 'case-a-1', 'case-a-2', 'case-b-1'])
        self.assertEqual(self.quiet_calls, len(collector.calls))
        self.assertEqual(self.accepted(), ['case-a-2', 'case-b-1'])
        self.assertIn('REJECTED ENVIRONMENT case-a-1', out)
        self.assertIn('ALL CASES COMPLETE', out)

    def test_a_functional_failure_stops_without_a_retry(self):
        collector = FakeCollector(self.campaign, {'smoke': ['pass'], 'case-a': ['broken']})
        with self.assertRaises(SystemExit):
            self.run_campaign(collector)
        self.assertEqual(collector.calls, ['smoke-1', 'case-a-1'])
        self.assertFalse((self.campaign / 'accepted-blocks.json').exists())

    def test_the_last_allowed_attempt_stops_even_on_environment_load(self):
        collector = FakeCollector(self.campaign, {'smoke': ['pass'], 'case-a': ['noise', 'noise']})
        with self.assertRaises(SystemExit):
            self.run_campaign(collector, limit=2)
        self.assertEqual(collector.calls, ['smoke-1', 'case-a-1', 'case-a-2'])

    def test_a_rerun_resumes_after_existing_attempts_and_keeps_accepted_cases(self):
        first = FakeCollector(self.campaign, {'smoke': ['pass'], 'case-a': ['pass'], 'case-b': ['noise', 'noise']})
        with self.assertRaises(SystemExit):
            self.run_campaign(first, limit=2)
        second = FakeCollector(self.campaign, {'case-b': ['pass']})
        out = self.run_campaign(second, limit=2)
        # The smoke and case a are not repeated; case b continues at attempt 3
        # instead of being skipped because two attempts already exist.
        self.assertEqual(second.calls, ['case-b-3'])
        self.assertEqual(self.accepted(), ['case-a-1', 'case-b-3'])
        self.assertIn('ALL CASES COMPLETE', out)

    def test_zero_padded_smoke_directories_from_older_controllers_count(self):
        (self.campaign / 'smoke-01').mkdir()
        (self.campaign / 'smoke-01' / 'manifest.json').write_text(json.dumps(dict(status='pass', cases=[], runs=[trial()])))
        collector = FakeCollector(self.campaign, {'case-a': ['pass'], 'case-b': ['pass']})
        self.run_campaign(collector)
        self.assertEqual(collector.calls, ['case-a-1', 'case-b-1'])

    def test_only_clean_trials_with_external_load_count_as_environment(self):
        for runs, expected in (([trial(), trial(heavy=True)], True), ([trial(heavy=True), trial(returncode=1)], False),
                               ([trial()], False), ([], False)):
            attempt = self.campaign / f'attempt-{len(list(self.campaign.iterdir()))}'
            attempt.mkdir()
            (attempt / 'manifest.json').write_text(json.dumps(dict(status='fail', runs=runs)))
            self.assertEqual(c.environment_only(attempt), expected, runs)
        self.assertFalse(c.environment_only(self.campaign / 'missing'))


if __name__ == '__main__':
    unittest.main()

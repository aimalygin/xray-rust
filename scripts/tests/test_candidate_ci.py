import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "candidate_ci", Path(__file__).resolve().parents[1] / "verify-candidate-ci.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class CandidateCIGates(unittest.TestCase):
    def setUp(self):
        self.run = {"id": 1, "created_at": "2026-11-02T12:00:00Z", "head_sha": "a" * 40,
                    "event": "workflow_dispatch", "path": ".github/workflows/ci.yml",
                    "status": "completed"}
        self.jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                     for name in sorted(MODULE.REQUIRED)]
        self.jobs += [{"name": "release-evidence", "status": "completed", "conclusion": "skipped"},
                      {"name": "publish-prerelease", "status": "completed", "conclusion": "skipped"}]

    def check(self, run=None, jobs=None):
        return MODULE.validate(run or self.run, jobs or self.jobs, "a" * 40)

    def with_conclusion(self, name, conclusion):
        jobs = copy.deepcopy(self.jobs)
        match = [job for job in jobs if job["name"] == name]
        if match:
            match[0]["conclusion"] = conclusion
        else:
            jobs.append({"name": name, "status": "completed", "conclusion": conclusion})
        return jobs

    def test_passing_run_binds(self):
        conclusions = self.check()
        self.assertEqual(conclusions["apple"], "success")
        self.assertEqual(conclusions["release-evidence"], "skipped")

    def test_no_required_gate_can_be_waived(self):
        for name in MODULE.REQUIRED:
            for outcome in ("failure", "skipped", "cancelled", "timed_out"):
                with self.subTest(name=name, outcome=outcome), self.assertRaises(ValueError):
                    self.check(jobs=self.with_conclusion(name, outcome))

    def test_only_the_upstream_main_smoke_may_fail(self):
        self.check(jobs=self.with_conclusion("xray-core-main-smoke", "failure"))
        for outcome in ("failure", "cancelled"):
            with self.subTest(outcome=outcome), self.assertRaises(ValueError):
                self.check(jobs=self.with_conclusion("extra", outcome))

    def test_unrelated_or_incomplete_runs_rejected(self):
        for key, value in (("head_sha", "b" * 40), ("event", "push"), ("event", "schedule"),
                           ("path", "other.yml"), ("status", "in_progress")):
            run = dict(self.run, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.check(run=run)
        for jobs in (self.jobs[1:], self.jobs + [self.jobs[0]],
                     [dict(job, status="in_progress") for job in self.jobs]):
            with self.assertRaises(ValueError):
                self.check(jobs=jobs)

    def test_newest_passing_run_is_selected(self):
        older = dict(self.run, id=1, created_at="2026-11-02T10:00:00Z")
        failed = dict(self.run, id=2, created_at="2026-11-02T11:00:00Z")
        newest = dict(self.run, id=3, created_at="2026-11-02T12:00:00Z")
        jobs = {1: self.jobs, 2: self.with_conclusion("apple", "failure"), 3: self.jobs}
        run, _ = MODULE.select([older, failed, newest], jobs.__getitem__, "a" * 40)
        self.assertEqual(run["id"], 3)
        run, _ = MODULE.select([older, failed], jobs.__getitem__, "a" * 40)
        self.assertEqual(run["id"], 1)
        with self.assertRaisesRegex(ValueError, "run 2: required CI gate did not pass: apple"):
            MODULE.select([failed], jobs.__getitem__, "a" * 40)
        with self.assertRaisesRegex(ValueError, "no passing manual CI run"):
            MODULE.select([], jobs.__getitem__, "a" * 40)


if __name__ == "__main__":
    unittest.main()

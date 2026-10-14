import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "source_tag_ci", Path(__file__).resolve().parents[1] / "verify-source-tag-ci.py")
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SourceTagCIGates(unittest.TestCase):
    def setUp(self):
        self.run = {"head_sha": "a" * 40, "head_branch": "v0.8.0", "event": "push",
                    "path": ".github/workflows/ci.yml", "status": "completed"}
        self.jobs = [{"name": name, "status": "completed", "conclusion": "success"}
                     for name in sorted(MODULE.REQUIRED)]

    def check(self, run=None, jobs=None):
        return MODULE.validate(run or self.run, jobs or self.jobs, "v0.8.0", "a" * 40)

    def test_pass_and_only_completed_secret_scan_can_be_revalidated(self):
        self.check()
        for job in self.jobs:
            if job["name"] == "secrets":
                job["conclusion"] = "failure"
        self.assertEqual(self.check()["secrets"], "failure")
        for outcome in ("skipped", "cancelled", "timed_out"):
            with self.subTest(outcome=outcome):
                jobs = copy.deepcopy(self.jobs)
                next(job for job in jobs if job["name"] == "secrets")["conclusion"] = outcome
                with self.assertRaises(ValueError):
                    self.check(jobs=jobs)

    def test_other_gates_cannot_be_waived(self):
        for name in MODULE.REQUIRED - {"secrets"}:
            for outcome in ("failure", "skipped", "cancelled"):
                jobs = copy.deepcopy(self.jobs)
                next(job for job in jobs if job["name"] == name)["conclusion"] = outcome
                with self.subTest(name=name, outcome=outcome), self.assertRaises(ValueError):
                    self.check(jobs=jobs)

    def test_unrelated_or_incomplete_runs_rejected(self):
        for key, value in (("head_sha", "b" * 40), ("head_branch", "main"),
                           ("event", "workflow_dispatch"), ("path", "other.yml"),
                           ("status", "in_progress")):
            run = dict(self.run, **{key: value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check(run=run)
        for jobs in (self.jobs[:-1], self.jobs + [self.jobs[0]],
                     self.jobs + [{"name": "extra", "status": "completed", "conclusion": "failure"}]):
            with self.assertRaises(ValueError):
                self.check(jobs=jobs)


if __name__ == "__main__":
    unittest.main()

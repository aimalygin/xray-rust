#!/usr/bin/env python3
"""Run the migration collector's xhttp-h3-* cases with the campaign runner's policy.

collector_h3.py DIR REFERENCE_SHA256

DIR holds inputs.json. The smoke block covers only the xhttp-h3 profile; each
case is then one five-pair AB/BA block, retried only when external load alone
rejected it, exactly as scripts/run-migration-campaign.py does for all cases.
"""
import importlib.util
from pathlib import Path
import sys

# The checkout these scripts live in: docs/benchmarks/results/<report>/scripts/.
WORKTREE = Path(__file__).resolve().parents[5]
spec = importlib.util.spec_from_file_location('campaign', WORKTREE / 'scripts/run-migration-campaign.py')
campaign = importlib.util.module_from_spec(spec)
spec.loader.exec_module(campaign)

root = Path(sys.argv[1]).resolve()
reference = sys.argv[2]
run = lambda name, extra: campaign.collect(root, name, extra, reference)
if not any(campaign.passed(path) for path in campaign.existing(root, 'smoke').values()):
    campaign.until_accepted(root, 'smoke', ['--smoke', '--profile', 'xhttp-h3'], 10, run, campaign.wait_for_quiet)
cases = [case for case in campaign.m.cases() if case['id'].startswith('xhttp-h3-')]
campaign.say('CASES', len(cases), ' '.join(case['id'] for case in cases))
campaign.run_campaign(root, cases, 10, run=run, quiet=campaign.wait_for_quiet)

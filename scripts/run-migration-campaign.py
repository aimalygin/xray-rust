#!/usr/bin/env python3
"""Run a before/after campaign: one smoke run, then one collector block per case.

run-migration-campaign.py --campaign DIR [--reference-sha256 HEX] [--attempts N]

DIR holds the inputs.json made from scripts/build-isolated-release.py records,
and every attempt gets a new directory in it. The collector rejects a whole
block when another process uses a CPU core, all of them two, or a compiler
runs. On a desktop Mac that load can last minutes: Spotlight indexing, media
analysis, an App Store install. The controller therefore

- waits before every attempt, the smoke run included, until the collector's
  own rule has passed 30 seconds in a row;
- retries a block that only that load rejected, up to --attempts times per
  case in one invocation, and stops on any other failure;
- records accepted blocks in DIR/accepted-blocks.json, so running it again
  resumes with the next attempt number.

Progress lines: START, WAITED, PASS, REJECTED ENVIRONMENT, FAILED, ALL CASES
COMPLETE. End DIR's name in `.noindex` so that Spotlight leaves its thousands
of trial files alone; Spotlight indexing them rejected blocks on 2026-10-30.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / 'scripts/run-migration-benchmarks.py'
spec = importlib.util.spec_from_file_location('migration', COLLECTOR)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def say(*words):
    print(*words, flush=True)


def collect(campaign, name, extra, reference_sha256):
    """One collector invocation; its output goes to DIR/NAME.log."""
    say('START', name, time.strftime('%Y-%m-%d %H:%M:%S'))
    pin = ['--reference-sha256', reference_sha256] if reference_sha256 else []
    with (campaign / (name + '.log')).open('w') as log:
        return subprocess.run(
            [sys.executable, str(COLLECTOR), '--inputs', str(campaign / 'inputs.json'),
             '--output', str(campaign / name), *pin, *extra],
            cwd=ROOT, stdout=log, stderr=subprocess.STDOUT).returncode


def manifest(attempt):
    try:
        return json.loads((attempt / 'manifest.json').read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def passed(attempt):
    record = manifest(attempt)
    return record is not None and record.get('status') == 'pass'


def environment_only(attempt):
    """True when every trial ran cleanly and external load alone rejected it."""
    runs = (manifest(attempt) or {}).get('runs')
    return bool(runs) and all(
        r['returncode'] == 0 and not r['remaining_engine_processes'] and not r['surviving_process_group']
        and r['process_group_empty_after_run'] and not r['ambient_cpu']['observer_errors'] for r in runs
    ) and any(r['ambient_cpu']['heavy_external_load'] or r['ambient_cpu']['compiler_load_detected'] for r in runs)


def wait_for_quiet(window=5, needed=6, sleep=time.sleep):
    """Return once `needed` windows in a row pass the collector's load rule."""
    quiet, waited, previous = 0, 0, m.processes()
    while quiet < needed:
        sleep(window)
        current = m.processes()
        sample = m.ambient(previous, current, window)
        previous = current
        quiet = 0 if sample['heavy_external_load'] or sample['compiler_load_detected'] else quiet + 1
        waited += window
    if waited > window * needed:
        say('WAITED', waited, 's for a quiet machine', time.strftime('%H:%M:%S'))


def existing(campaign, prefix):
    """Attempt directories PREFIX-N as {N: path}, whatever N's zero padding."""
    found = {}
    for path in campaign.glob(prefix + '-*'):
        suffix = path.name[len(prefix) + 1:]
        if path.is_dir() and suffix.isdigit():
            found[int(suffix)] = path
    return found


def until_accepted(campaign, prefix, extra, limit, run, quiet):
    """Attempt PREFIX-N after the existing ones; return the accepted name."""
    first = max(existing(campaign, prefix), default=0) + 1
    last = first + limit - 1
    for number in range(first, last + 1):
        name = f'{prefix}-{number}'
        quiet()
        if not run(name, extra):
            say('PASS', name)
            return name
        if environment_only(campaign / name) and number < last:
            say('REJECTED ENVIRONMENT', name)
            continue
        say('FAILED', name)
        log = campaign / (name + '.log')
        if log.exists():
            say(log.read_text()[-1500:])
        raise SystemExit(1)


def run_campaign(campaign, cases, limit, run, quiet):
    accepted_path = campaign / 'accepted-blocks.json'
    accepted = json.loads(accepted_path.read_text()) if accepted_path.exists() else []
    if not all(passed(campaign / block) for block in accepted):
        raise SystemExit('accepted-blocks.json lists a block that did not pass')
    if not any(passed(path) for path in existing(campaign, 'smoke').values()):
        until_accepted(campaign, 'smoke', ['--smoke'], limit, run, quiet)
    finished = {case['id'] for block in accepted for case in manifest(campaign / block)['cases']}
    for case in cases:
        if case['id'] in finished:
            continue
        accepted.append(until_accepted(campaign, f"case-{case['id']}", ['--case-id', case['id']], limit, run, quiet))
        accepted_path.write_text(json.dumps(accepted, indent=2) + '\n')
    say('ALL CASES COMPLETE')


def main():
    parser = argparse.ArgumentParser(description='Run a before/after campaign: smoke, then one block per case.')
    parser.add_argument('--campaign', type=Path, required=True, help='directory with inputs.json')
    parser.add_argument('--reference-sha256', help='passed to the collector')
    parser.add_argument('--attempts', type=int, default=10, help='per case and invocation (default 10)')
    args = parser.parse_args()
    campaign = args.campaign.resolve()
    if not campaign.name.endswith('.noindex'):
        say('WARNING: Spotlight indexes', campaign, '- a .noindex suffix keeps it out')
    run_campaign(campaign, m.cases(), args.attempts,
                 run=lambda name, extra: collect(campaign, name, extra, args.reference_sha256),
                 quiet=wait_for_quiet)


if __name__ == '__main__':
    main()

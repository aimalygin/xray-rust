#!/usr/bin/env python3
"""Repeat all original failed cases without changing or replacing primary samples.

Usage: confirm-failures.py REPO PRIMARY_MANIFEST [canonical collector arguments]
The normal collector still rotates all three clients and verifies frozen inputs.
Only its case selection is narrowed to cases with a failed primary run.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

repo = Path(sys.argv.pop(1)).resolve()
primary_path = Path(sys.argv.pop(1)).resolve()
primary_bytes = primary_path.read_bytes()
primary = json.loads(primary_bytes)
failed = sorted({r['case'] for r in primary['runs'] if r['returncode']})
assert primary.get('finished_unix') and failed
spec = importlib.util.spec_from_file_location('comparison', repo/'scripts/run-v08-protocol-comparison.py')
comparison = importlib.util.module_from_spec(spec)
spec.loader.exec_module(comparison)
all_cases = comparison.cases
comparison.cases = lambda profiles, smoke=False: [c for c in all_cases(profiles, smoke) if c['id'] in failed]
output = Path(sys.argv[sys.argv.index('--output')+1]).resolve()
try:
    comparison.main()
finally:
    if output.exists():
        (output/'selection.json').write_text(json.dumps({
            'primary_manifest_sha256':hashlib.sha256(primary_bytes).hexdigest(),
            'failed_primary_cases':failed,
            'confirmation_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'purpose':'separate confirmation, never replacement of failed primary samples'
        },indent=2)+'\n')

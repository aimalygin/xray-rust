"""make_collector_inputs.py BENCH_DIR VARIANT: writes BENCH_DIR/2026-10-31-h3-receive-budget-collector-VARIANT.noindex/inputs.json
with this campaign's isolated `before` and VARIANT builds and the frozen harness, reference and origin of the
2026-10-31 merged collector campaign."""
import json, sys
from pathlib import Path

bench, variant = Path(sys.argv[1]), sys.argv[2]
builds = bench / '2026-10-31-h3-receive-budget.noindex/build'
inputs = json.loads((bench / '2026-10-31-h3-merged-collector.noindex/inputs.json').read_text())
inputs['before'] = json.loads((builds / 'before.json').read_text())
inputs['after'] = json.loads((builds / f'{variant}.json').read_text())
assert inputs['before']['commit'].startswith('591216c5')
assert inputs['after']['commit'].startswith({'cap': 'aad7eb39', 'behind': 'bb4e4dd2', 'timed': 'e970cae1', 'floor': '95280e73'}[variant])
out = bench / f'2026-10-31-h3-receive-budget-collector-{variant}.noindex'
out.mkdir(exist_ok=True)
(out / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
print(out, 'before', inputs['before']['sha256'][:12], variant, inputs['after']['sha256'][:12])

#!/bin/bash
# macOS A/B of bae0ed5b against the merged head 57b5a655: stream pairs, then the collector's xhttp-h3 cases.
set -u
S=/private/tmp/claude-501/-Users-antonmalygin-xray-rust/0435abb7-c55c-4543-a178-493045d19568/scratchpad
export CARGO_HOME=/private/tmp/xray-migration-tools/cargo RUSTUP_HOME=/private/tmp/xray-migration-tools/rustup
export PATH=$S/py312bin:/private/tmp/xray-migration-tools/cargo/bin:$PATH
R=/Users/antonmalygin/xray-rust
SCR=$R/docs/benchmarks/results/2026-10-30-xhttp-h3-send-budget/scripts
B=$R/target/benchmarks
STREAM=$B/2026-10-31-h3-merged.noindex
COLL=$B/2026-10-31-h3-merged-collector.noindex
REF=b8c58f14180eb0cad5665fa2cefb7d10897eec945d007212a053fc1de2257ee8
if [[ ! -f $COLL/inputs.json ]]; then
  mkdir -p $COLL
  python3 - "$B" "$STREAM" "$COLL" <<'PY'
import json, sys
from pathlib import Path
b, stream, coll = map(Path, sys.argv[1:])
inputs = json.loads((b / '2026-10-31-h3-arena-collector.noindex/inputs.json').read_text())
inputs['after'] = json.loads((stream / 'build/after.json').read_text())
assert inputs['before']['commit'].startswith('bae0ed5b') and inputs['after']['commit'].startswith('57b5a655')
(coll / 'inputs.json').write_text(json.dumps(inputs, indent=2) + '\n')
print('inputs: before', inputs['before']['sha256'][:12], 'after', inputs['after']['sha256'][:12])
PY
fi
echo "stream start $(date +%H:%M:%S)"
python3 $SCR/stream_ab.py --campaign $STREAM --rounds 5 >>$STREAM/stream-ab.log 2>&1
echo "stream exit=$? $(date +%H:%M:%S)"
echo "collector start $(date +%H:%M:%S)"
python3 $SCR/collector_h3.py $COLL $REF >>$COLL/campaign.log 2>&1
echo "collector exit=$? $(date +%H:%M:%S)"

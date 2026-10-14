#!/usr/bin/env python3
"""Use the existing whole-case collector for all three VMess profiles only.

Child collectors retain their original seven-profile case indexes and rotation.
The source wrapper is archived alongside the original collector; no workload,
repeat count, failure handling or quality selection rule is changed.
"""
import importlib.util
from pathlib import Path
import sys

root=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('blocks',root/'scripts/run-v08-comparison-blocks.py')
blocks=importlib.util.module_from_spec(spec);spec.loader.exec_module(blocks)
blocks.c.PROFILES={k:v for k,v in blocks.c.PROFILES.items() if k.startswith('vmess-')}
assert set(blocks.c.PROFILES)=={'vmess-aes128','vmess-chacha20','vmess-auto'}
sys.argv=[__file__,'--mode','full','--inputs',str(root/'target/v08-batch-investigation/inputs.json'),'--output',str(root/'target/v08-batch-investigation/comparison')]
blocks.main()

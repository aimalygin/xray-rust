#!/usr/bin/env python3
"""Holds a broad interop gate to the helpers its tests cannot run without.

`check-rc-interop.sh` and `check-scheduled-pinned-interop.sh` run every
ignored test of `local_xray_interop_tests`, and neither runs on a pull
request. A test module that reads a helper binary from the environment with
no fallback of its own fails there, at release time, unless the gate exports
that variable or skips the module by name.

What counts as required is a variable named by a literal and read with
`.expect(..)` or `.unwrap()`; a name held in a constant is not seen.

Usage: interop-gate-helpers.py <gate script> [<tests directory>]
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

# `env::var_os("NAME").expect(..)` or `.unwrap()`, on one line or wrapped.
REQUIRED = re.compile(
    r'env::var(?:_os)?\(\s*"([A-Z][A-Z0-9_]*)"\s*\)\s*\.\s*(?:expect|unwrap)\('
)


def required_helpers(tests: Path) -> list[tuple[str | None, str]]:
    """Each (module, variable) a test reads with no fallback; the suite's
    root file has no module to skip."""
    sources = [(None, tests / "local_xray_interop_tests.rs")]
    sources += [
        (source.stem, source)
        for source in sorted((tests / "local_xray_interop_tests").glob("*.rs"))
    ]
    return [
        (module, variable)
        for module, source in sources
        for variable in sorted(set(REQUIRED.findall(source.read_text())))
    ]


def uncovered(gate: str, helpers: list[tuple[str | None, str]]) -> list[str]:
    problems = []
    for module, variable in helpers:
        exported = re.search(rf"^\s*export {variable}=", gate, re.MULTILINE)
        skipped = module is not None and f"--skip {module}::" in gate
        if not exported and not skipped:
            problems.append(
                f"{module or 'the suite root'} requires {variable}: "
                "export it, skip the module, or let the test build its helper"
            )
    return problems


def main() -> int:
    gate = Path(sys.argv[1])
    tests = (
        Path(sys.argv[2])
        if len(sys.argv) > 2
        else Path(__file__).resolve().parents[2] / "crates/xray-core-rs/tests"
    )
    helpers = required_helpers(tests)
    if not helpers:
        print(f"no required helper found under {tests}", file=sys.stderr)
        return 1
    problems = uncovered(gate.read_text(), helpers)
    for problem in problems:
        print(f"{gate.name}: {problem}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

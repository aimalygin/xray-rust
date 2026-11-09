#!/usr/bin/env python3
"""Recheck the Xray-core verdicts recorded in a config-verdicts.json corpus,
such as tests/fixtures/masque/config-verdicts.json.

Each case is a one-outbound configuration that `xray run -test` either
accepts ("Configuration OK.") or refuses with an error whose text holds the
recorded substring. With --record the verdicts are written back instead.
"""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def verdict(xray: Path, config: dict, workdir: Path) -> str:
    path = workdir / "case.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    result = subprocess.run(
        [str(xray), "run", "-test", "-config", str(path)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    output = result.stdout + result.stderr
    if result.returncode == 0 and "Configuration OK." in output:
        return "ok"
    failures = [line for line in output.splitlines() if "Failed to start:" in line]
    if result.returncode == 0 or not failures:
        raise SystemExit(f"unexpected xray output for {config}:\n{output}")
    # The innermost cause, after the last " > ".
    return failures[-1].rsplit(" > ", 1)[-1].strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("xray", type=Path)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--record", action="store_true")
    args = parser.parse_args()

    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    failures = []
    with tempfile.TemporaryDirectory() as tmp:
        for case in fixture["cases"]:
            config = {"outbounds": [case["outbound"], *case.get("extraOutbounds", [])]}
            got = verdict(args.xray, config, Path(tmp))
            if args.record:
                case["xray"] = got
            elif case["xray"] == "ok" and got != "ok" or case["xray"] != "ok" and (
                got == "ok" or case["xray"] not in got
            ):
                failures.append(f"{case['name']}: recorded {case['xray']!r}, Xray says {got!r}")
    if args.record:
        args.fixture.write_text(
            json.dumps(fixture, ensure_ascii=False, indent=1) + "\n", encoding="utf-8"
        )
        return 0
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"{len(fixture['cases']) - len(failures)} of {len(fixture['cases'])} Xray verdicts match")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

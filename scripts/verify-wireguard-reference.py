#!/usr/bin/env python3
"""Verify the independent wireguard-go/gVisor module identities before a live run."""

import json
from pathlib import Path
import subprocess
import sys

MODULE = Path(__file__).resolve().parents[1] / "tools/wireguard-reference"
WIREGUARD_COMMIT = "f333402bd9cbe0f3eeb02507bd14e23d7d639280"
PINS = {
    "golang.zx2c4.com/wireguard": (
        "v0.0.0-20250521234502-f333402bd9cb",
        "h1:whnFRlWMcXI9d+ZbWg+4sHnLp52d5yiIPUxMBSt4X9A=",
        "h1:rpwXGsirqLqN2L0JDJQlwOboGHmptD5ZD6T2VmcqhTw=",
    ),
    "gvisor.dev/gvisor": (
        "v0.0.0-20260122175437-89a5d21be8f0",
        "h1:Lk6hARj5UPY47dBep70OD/TIMwikJ5fGUGX0Rm3Xigk=",
        "h1:QkHjoMIBaYtpVufgwv3keYAbln78mBoCuShZrPrer1Q=",
    ),
}


def verify_modules(modules: list[dict]) -> None:
    found = set()
    for module in modules:
        path = module.get("Path", "")
        if module.get("Replace") is not None:
            raise SystemExit(f"reference module replacement: {path}")
        if "xray" in path.lower() and not module.get("Main"):
            raise SystemExit("independent reference must not import Xray")
        if path in PINS:
            actual = tuple(module.get(key) for key in ("Version", "Sum", "GoModSum"))
            if actual != PINS[path] or path in found:
                raise SystemExit(f"incorrect reference identity: {path}")
            found.add(path)
    if found != PINS.keys():
        raise SystemExit("missing reference module identity")


def read_modules(text: str) -> list[dict]:
    decoder = json.JSONDecoder()
    modules = []
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        modules.append(value)
        text = text.lstrip()[end:]
    return modules


if __name__ == "__main__":
    result = subprocess.run(
        ["go", "-C", str(MODULE), "list", "-mod=readonly", "-m", "-json", "all"],
        capture_output=True, text=True, check=True,
    )
    verify_modules(read_modules(result.stdout))
    print(f"verified official wireguard-go 0.0.20250522 ({WIREGUARD_COMMIT}) and pinned gVisor")

"""0.8.1 collector API (docs/device-results/2026-10-18-v081-candidate/android/drive.py)
over the promoted v0.9 driver's Device (scripts/run-v09-android-device-matrix.py).

ROOT is the run directory (events.jsonl and logcat snapshots). The only change in
behaviour: traffic() expects UDP to be refused for cases with ``udp: false``
(HTTP CONNECT), exactly as the v0.9 matrix does.
"""
import importlib.util
import os
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "v09_matrix", "<repo>/scripts/run-v09-android-device-matrix.py")
_m = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m)

ROOT = Path(os.environ["RUN_DIR"])
ROOT.mkdir(parents=True, exist_ok=True)
_device = _m.Device(os.environ.get("ANDROID_SERIAL", "<samsung-serial>"),
                    os.environ.get("ADB", "adb"), os.environ.get("PACKAGE_SUFFIX", ".v09"),
                    ROOT / "events.jsonl")
HOST, PROBE = _device.host, _device.probe
_udp_expected = True


def adb(*args):
    return _device.run(*args)


def shell(*args, **kwargs):
    return _device.shell(*args, **kwargs)


def command(package, name, extras=()):
    return _device.command(package, name, extras)


def status(package):
    return _device.status(package)


def wait_status(package, ready, timeout=15):
    return _device.wait(package, ready, timeout)


def emit(kind, **values):
    _device.emit(kind, **values)


def install_profile(case, link=False):
    global _udp_expected
    _udp_expected = case.get("udp", True)
    _device.install(case, link)


def host_stop():
    _device.stop()


def probe_stop():
    _device.probe_stop()


def traffic(env, target, count=3):
    return _device.traffic(env, target, _udp_expected, count)


def udp_expected():
    return _udp_expected


def log_snapshot(name):
    value = adb("logcat", "-d", "-v", "epoch", "-s", "XrayDeviceGate:I", "XrayDeviceProbe:I", "*:S")
    (ROOT / name).write_text(value)


def host_start(backend):
    return _device.start(backend)


def run_case(env, case, backend):
    """The v0.9 matrix's run_case: link + config import, traffic, close, restart."""
    return _m.run_case(_device, env, case, backend)

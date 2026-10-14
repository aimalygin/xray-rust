#!/usr/bin/env python3
"""Apply a per-service IPv4 UDP fragmentation policy after Xray starts.

Linux x86_64, cgroup v2, Python 3.9+, and pidfd_getfd permission are required.
This is a server deployment helper, not part of the client runtime. It accepts
only one SS2022 listener in an explicitly named service, config and binary.
"""
import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import socket
import subprocess
import sys
import time

IP_MTU_DISCOVER = 10
IP_PMTUDISC_DONT = 0


def validate_config(config, port):
    candidates = [item for item in config.get("inbounds", []) if item.get("port") == port]
    if len(candidates) != 1:
        raise ValueError("expected exactly one configured inbound on the selected port")
    inbound = candidates[0]
    settings = inbound.get("settings", {})
    if (inbound.get("protocol") != "shadowsocks" or
            settings.get("method") not in (
                "2022-blake3-chacha20-poly1305", "2022-blake3-aes-128-gcm",
                "2022-blake3-aes-256-gcm") or
            "udp" not in settings.get("network", "tcp").split(",")):
        raise ValueError("selected inbound must explicitly enable native SS2022 UDP")


def command_matches(arguments, config):
    """Accept the explicit single-config invocation used by the service recipe."""
    return len(arguments) == 4 and arguments[1:] == [b"run", b"-config", os.fsencode(config)]


def service_pids(unit):
    group = subprocess.check_output(
        ["systemctl", "show", unit, "--property=ControlGroup", "--value"], text=True
    ).strip()
    if not group.startswith("/") or ".." in Path(group).parts or group == "/":
        raise ValueError("service has no bounded cgroup")
    # Only this cgroup's members are eligible; never scan all host processes.
    return [int(value) for value in
            (Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.procs").read_text().split()]


def listener_fds(pid, port):
    proc = Path("/proc") / str(pid)
    inodes = set()
    for line in (proc / "net/udp").read_text().splitlines()[1:]:
        fields = line.split()
        if int(fields[1].split(":")[1], 16) == port:
            inodes.add(fields[9])
    result = []
    for entry in (proc / "fd").iterdir():
        try:
            match = re.fullmatch(r"socket:\[(\d+)\]", os.readlink(entry))
        except FileNotFoundError:
            continue
        if match and match[1] in inodes:
            result.append(int(entry.name))
    return result


def apply(args):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("this helper is validated only on Linux x86_64")
    # Derive the syscall identifier from the installed architecture header.
    header = Path("/usr/include/x86_64-linux-gnu/asm/unistd_64.h").read_text()
    match = re.search(r"^#define __NR_pidfd_getfd (\d+)$", header, re.MULTILINE)
    if not match:
        raise ValueError("pidfd_getfd syscall definition is unavailable")
    syscall_number = int(match[1])
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        try:
            eligible = []
            for pid in service_pids(args.unit):
                proc = Path("/proc") / str(pid)
                try:
                    command = (proc / "cmdline").read_bytes().rstrip(b"\0").split(b"\0")
                    if os.readlink(proc / "exe") == str(args.executable) and command_matches(command, args.config):
                        eligible.append(pid)
                except FileNotFoundError:
                    continue
            if len(eligible) > 1:
                raise ValueError("multiple matching service processes; refusing partial configuration")
            if not eligible:
                time.sleep(0.1)
                continue
            pid = eligible[0]
            validate_config(json.loads(args.config.read_text()), args.port)
            pidfd = os.pidfd_open(pid)
            try:
                with (Path("/proc") / str(pid) / "exe").open("rb") as binary:
                    digest = hashlib.sha256()
                    for chunk in iter(lambda: binary.read(1024 * 1024), b""):
                        digest.update(chunk)
                if digest.hexdigest() != args.sha256:
                    raise ValueError("running executable SHA-256 differs from the required pin")
                fds = listener_fds(pid, args.port)
                if len(fds) > 1:
                    raise ValueError("multiple UDP descriptors; refusing partial configuration")
                if not fds:
                    time.sleep(0.1)
                    continue
                libc = ctypes.CDLL(None, use_errno=True)
                libc.syscall.restype = ctypes.c_long
                duplicate = libc.syscall(syscall_number, pidfd, fds[0], 0)
                if duplicate < 0:
                    raise OSError(ctypes.get_errno(), "cannot duplicate the selected service socket")
                with socket.socket(fileno=duplicate) as listener:
                    if (listener.family != socket.AF_INET or
                            listener.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_DGRAM or
                            listener.getsockname()[1] != args.port):
                        raise ValueError("selected descriptor is not the expected IPv4 UDP socket")
                    try:
                        listener.getpeername()
                    except OSError as error:
                        if error.errno != errno.ENOTCONN:
                            raise
                    else:
                        raise ValueError("refusing to configure a connected outbound UDP socket")
                    before = listener.getsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER)
                    if not args.check:
                        listener.setsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_DONT)
                    after = listener.getsockopt(socket.IPPROTO_IP, IP_MTU_DISCOVER)
                    if after != IP_PMTUDISC_DONT:
                        raise ValueError("listener fragmentation policy is not DONT")
                return {"unit": args.unit, "pid": pid, "fd": fds[0], "port": args.port,
                        "before": before, "after": after, "checkOnly": args.check,
                        "executableSha256": args.sha256}
            finally:
                os.close(pidfd)
        except FileNotFoundError:
            # ExecStartPost can run before the fixture/config/listener is ready.
            time.sleep(0.1)
    raise TimeoutError("selected service listener did not become ready within the startup bound")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=10)
    parser.add_argument("--check", action="store_true", help="verify only; never set the option")
    parser.add_argument("--audit", type=Path, help="optional private JSON output, written atomically")
    args = parser.parse_args()
    if (not re.fullmatch(r"[A-Za-z0-9_.@:-]+\.service", args.unit) or
            not re.fullmatch(r"[a-f0-9]{64}", args.sha256) or
            not 1 <= args.port <= 65535 or not 0 < args.timeout <= 30 or
            not args.config.is_absolute() or not args.executable.is_absolute()):
        parser.error("use an explicit service, absolute config/executable, SHA-256, port and 0..30 s bound")
    result = apply(args)
    if args.audit:
        temporary = args.audit.with_name(args.audit.name + ".tmp")
        with temporary.open("x") as handle:
            os.chmod(temporary, 0o600)
            handle.write(json.dumps(result, sort_keys=True) + "\n")
        temporary.replace(args.audit)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        # Do not log parsed configuration or credentials.
        print(f"SS2022 socket setup failed: {type(error).__name__}: {error}", file=sys.stderr)
        raise SystemExit(1)

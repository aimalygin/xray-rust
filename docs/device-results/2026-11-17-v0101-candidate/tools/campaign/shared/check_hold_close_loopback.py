#!/usr/bin/env python3
"""Host-only dry run of the remote-EOF half of the Android cancellation runs.

New for the v0.10 campaign; NOT a 0.9.0 tool and NOT device evidence.

local_cancel_v09.py / local_cancel_v010.py open GET /v08-hold/<id> through the
tunnel to the Android fixture's HTTP oracle, cancel locally, and require the
oracle's hold-close to report reason "eof" less than 3 s after the request
(remoteCloseBoundPassed). Here the device is replaced by the candidate CLI with a
SOCKS ingress (check-v09-fixture-loopback.py's client_config): for every case of
the chosen Android fixture suite, two cancellations:

- socket-close: the SOCKS client closes its socket (the app's flow goes away);
- process-stop: the CLI gets SIGINT, its graceful shutdown signal (the tunnel
  stops, as `disconnect` stops the core; the candidate CLI handles only SIGINT
  gracefully, SIGTERM ends it at once).

A row passes when hold-close says "eof" within 3 s. This checks the carrier and
the server side on the loopback, not the device's close-connections path.
"""
import argparse
import importlib.util
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

CANDIDATE = Path("<stand-clone>")
spec = importlib.util.spec_from_file_location("fixture_loopback", CANDIDATE / "scripts/check-v09-fixture-loopback.py")
loopback = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loopback)
BOUND_SECONDS = 3


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-args", required=True,
                        help="arguments of run-v08-android-protocol-fixture.py, e.g. '--suite v09 --protocol v09'")
    parser.add_argument("--case", action="append", help="limit to these caseIds")
    parser.add_argument("--reference-binary", type=Path, required=True)
    parser.add_argument("--client-binary", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--xray-core-client", action="store_true",
                        help="comparison only: the client is Xray-core, which wants DNS servers as objects")
    args = parser.parse_args()
    os.umask(0o077)
    work = args.work_dir.absolute()
    work.mkdir(mode=0o700, parents=True, exist_ok=False)
    command = [sys.executable, str(CANDIDATE / "scripts/run-v08-android-protocol-fixture.py"),
               *args.fixture_args.split(), "--bind", "127.0.0.1", "--reference-binary",
               str(args.reference_binary), "--output", str(work / "fixture"), "--seconds", "600"]
    fixture = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    lines = queue.Queue()
    log = (work / "fixture-stdout.log").open("w")

    def pump():
        for line in fixture.stdout:
            log.write(line); log.flush(); lines.put(line)
    threading.Thread(target=pump, daemon=True).start()
    rows, failed = [], False

    def wait_row(kind, hold_id, timeout):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            try:
                line = lines.get(timeout=max(0.01, end - time.monotonic()))
            except queue.Empty:
                break
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("backend") == kind and row.get("id") == hold_id:
                return row
        return None

    try:
        first = lines.get(timeout=60)
        if not first.startswith("Fixture ready: "):
            raise loopback.CheckFailure("fixture did not start: " + first.strip())
        envelope = json.loads(Path(first.removeprefix("Fixture ready: ").strip()).read_text())
        hold_id = 7000
        for case in envelope["cases"]:
            if args.case and case["caseId"] not in args.case:
                continue
            for mode in ("socket-close", "process-stop"):
                hold_id += 1
                ingress = loopback.free_port()
                config = work / f"client-{case['caseId']}.json"
                settings = loopback.client_config(case, ingress)
                if args.xray_core_client:
                    servers = settings.get("dns", {}).get("servers", [])
                    settings["dns"]["servers"] = [
                        {"address": s.rsplit(":", 1)[0], "port": int(s.rsplit(":", 1)[1])}
                        if isinstance(s, str) and s.count(":") == 1 else s for s in servers]
                config.write_text(json.dumps(settings, indent=2) + "\n")
                row = {"case": case["caseId"], "mode": mode, "id": hold_id}
                with (work / f"client-{case['caseId']}-{mode}.log").open("wb") as clog:
                    child = subprocess.Popen([str(args.client_binary), "run", "-config", str(config)],
                                             stdout=clog, stderr=clog)
                    sock = None
                    try:
                        loopback.wait_listening(ingress, child)
                        time.sleep(case.get("settleSeconds", 0))
                        sock = __import__("socket").create_connection(("127.0.0.1", ingress), timeout=15)
                        loopback.socks_request(sock, 1, "198.51.100.7", envelope["tcpPort"])
                        sock.sendall(f"GET /v08-hold/{hold_id} HTTP/1.1\r\nHost: 198.51.100.7\r\n\r\n".encode())
                        opened = wait_row("hold-open", hold_id, 15)
                        if opened is None:
                            raise loopback.CheckFailure("no hold-open at the fixture")
                        issued = time.time()
                        if mode == "socket-close":
                            sock.close(); sock = None
                        else:
                            child.send_signal(signal.SIGINT)
                        closed = wait_row("hold-close", hold_id, 25)
                        if closed is None:
                            raise loopback.CheckFailure("no hold-close within 25 s")
                        row.update(openedToRequest=round(issued - opened["time"], 3),
                                   reason=closed["reason"], closeAfterRequest=round(closed["time"] - issued, 3))
                        row["result"] = ("passed" if closed["reason"] == "eof"
                                         and closed["time"] - issued < BOUND_SECONDS else "failed")
                    except (loopback.CheckFailure, OSError) as error:
                        row.update(result="failed", error=f"{type(error).__name__}: {error}")
                    finally:
                        if sock is not None:
                            sock.close()
                        if child.poll() is None:
                            child.terminate()
                        try:
                            child.wait(5)
                        except subprocess.TimeoutExpired:
                            child.kill(); child.wait()
                config.unlink()
                failed |= row["result"] != "passed"
                rows.append(row)
                print(json.dumps(row), flush=True)
    finally:
        fixture.send_signal(signal.SIGTERM)
        try:
            fixture.wait(15)
        except subprocess.TimeoutExpired:
            fixture.kill(); fixture.wait()
        log.close()
    leftovers = sorted(p.name for p in (work / "fixture").iterdir() if p.name != "server.log")
    summary = {"fixtureArgs": args.fixture_args, "rows": len(rows), "failed": sum(r["result"] != "passed" for r in rows),
               "boundSeconds": BOUND_SECONDS, "fixtureSecretsRemoved": not leftovers,
               "scope": "host loopback through SOCKS ingress; not device evidence"}
    (work / "results.json").write_text(json.dumps({"summary": summary, "rows": rows}, indent=2) + "\n")
    print(json.dumps(summary), flush=True)
    return 1 if failed or leftovers else 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Recompute the bounded campaign's published hashes, counts and DF correlation."""
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
manifest = json.loads((ROOT / "manifest.json").read_text())


def rows(name):
    return [json.loads(line) for line in (ROOT / name).read_text().splitlines()]


for name, digest in manifest["files"].items():
    assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest, name

for run in manifest["goRuns"]:
    trials = rows(run["name"] + ".jsonl")
    assert len(trials) == run["attempts"]
    assert sum(row["passed"] for row in trials) == run["passed"]
    assert all(not row["passed"] or row["source_matches"] for row in trials)

for run in manifest["deviceRuns"]:
    events = rows(run["name"] + ".jsonl")
    assert events == json.loads((ROOT / (run["name"] + "-device.json")).read_text())
    assert events[-1]["event"] == "complete"
    assert events[-1]["result"] == run["result"]
    assert len(events) == run["verification"]["rows"]
    for kind, count in run["counts"].items():
        assert sum(row["event"] == kind for row in events) == count
    trials = [row for row in events if row["event"] == "udp-size-result"]
    assert len(trials) == run["udpSweep"]["attempts"]
    assert sum(row["result"] == "passed" for row in trials) == run["udpSweep"]["passed"]
    if run["name"].endswith("transitions"):
        recovered = [row for row in events if row["event"] == "transition-recovered"]
        assert [row["stage"] for row in recovered] == [
            "wifi-baseline", "cellular", "wifi", "after-unlock"
        ]
        assert all(row["retries"] == 0 for row in recovered)
        samples = [row for row in events if row["event"] == "sample"]
        assert len({row["runtime"] for row in samples}) == 1
        assert all(row["droppedPackets"] == row["tunFDReadLoopExits"] ==
                   row["tunFDWriteLoopExits"] == 0 for row in samples)

packets = json.loads((ROOT / "native-packet-metadata.json").read_text())
echoes = json.loads((ROOT / "native-backend-metadata.json").read_text())
correlation = json.loads((ROOT / "boundary-correlation.json").read_text())
for name, expected_passes, expected_flags in [
    ("go-native-boundary", 36, "DF"),
    ("go-native-dont-boundary", 56, "none"),
]:
    trials = rows(name + ".jsonl")
    start = trials[0]["unix_start"] - 0.25
    end = trials[-1]["unix_start"] + trials[-1]["seconds"] + 0.25
    incoming = [p for p in packets if start <= p["unixTime"] <= end and p["direction"] == "In"]
    outgoing = [p for p in packets if start <= p["unixTime"] <= end and p["direction"] == "Out"]
    backend = [p for p in echoes if start <= p["unixTime"] <= end]
    combined = [p for p in correlation if p["control"] == name]
    assert len(trials) == len(incoming) == len(outgoing) == len(backend) == len(combined) == 56
    assert sum(t["passed"] for t in trials) == expected_passes
    for index, (trial, request, reply, echo, combined_row) in enumerate(
            zip(trials, incoming, outgoing, backend, combined)):
        assert request["flow"] == reply["flow"] == combined_row["flow"]
        assert echo["bytes"] == trial["payload_bytes"] == combined_row["payloadBytes"]
        assert request["udpBytes"] == trial["sent_wire_bytes"][0]
        assert reply["udpBytes"] == request["udpBytes"] + 8
        assert combined_row["trial"] == index
        assert combined_row["passed"] == trial["passed"]
        assert reply["flags"] == expected_flags == combined_row["replyFlags"]
        assert reply["ipBytes"] == combined_row["serverReplyIPBytes"]
        if expected_flags == "DF":
            assert trial["passed"] == (reply["ipBytes"] <= 1480)

audit = json.loads((ROOT / "socket-option-audit.json").read_text())
ordered = [audit[k] for k in ["socket-option-before", "socket-option-dont",
                             "socket-option-want-again", "socket-option-dont-again"]]
assert len({(x["testPID"], x["fd"]) for x in ordered}) == 1
assert [(x["before"], x["after"]) for x in ordered] == [(1, 1), (1, 0), (0, 1), (1, 0)]
assert all(json.loads((ROOT / "cleanup.json").read_text()).values())
print("Verified hashes, Go/device verdicts, same-socket controls and 112 correlated boundary trials")

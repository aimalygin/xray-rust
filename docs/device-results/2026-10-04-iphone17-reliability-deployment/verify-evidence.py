#!/usr/bin/env python3
"""Verify this bounded campaign without contacting a device or server."""
import collections
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def read(name):
    return json.loads((ROOT / name).read_text())


def rows(name):
    return [json.loads(line) for line in (ROOT / name).read_text().splitlines()]


manifest = read("manifest.json")
for artifact in manifest["files"] + manifest["sources"]:
    path = ROOT / artifact["path"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == artifact["sha256"], path


def device(run):
    events = rows(run["name"] + "/events.jsonl")
    assert events == read(run["name"] + "/device-events.json")
    assert events[-1]["event"] == "complete" and events[-1]["result"] == run["result"]
    assert len(events) == run["verification"]["rows"]
    assert dict(collections.Counter(x["event"] for x in events)) == run["counts"]
    trials = [x for x in events if x["event"] == "udp-size-result"]
    assert len(trials) == run["udpSweep"]["attempts"]
    assert sum(x["result"] == "passed" for x in trials) == run["udpSweep"]["passed"]
    return events


totals = collections.Counter()
assert len(manifest["step1"]) == 10
for run in manifest["step1"]:
    events = device(run)
    assert run["result"] == "passed"
    totals.update(run["counts"])
    backend = read(run["name"] + "/backend-metadata.json")
    tcp = [x for x in events if x["event"] == "tcp"]
    udp = [x for x in events if x["event"] == "udp"]
    assert all(x["result"] == "passed" and x["bytes"] == 65536 for x in tcp)
    opens = [x["flow"] for x in backend if x["event"] == "tcp-open"]
    assert len(set(opens)) == len(opens) == len(tcp)
    for flow in opens:
        for kind in ("tcp-read", "tcp-write"):
            assert sum(x["bytes"] for x in backend if x["event"] == kind and x["flow"] == flow) == 65536
    assert [x["bytes"] for x in backend if x["event"] == "udp-echo"] == [x["bytes"] for x in udp]
    assert all(x["result"] == "passed" for x in udp)
assert {k: totals[k] for k in ["tcp", "udp", "dns-anchor", "startup-cancelled", "rapid-restart", "connection-close-verified"]} == {
    "tcp": 210, "udp": 140, "dns-anchor": 70, "startup-cancelled": 15,
    "rapid-restart": 25, "connection-close-verified": 15,
}

expected = [(40, 40), (40, 40), (44, 38), (44, 40), (43, 0)]
pids = set()
correlated = 0
for run, (go_passed, phone_passed) in zip(manifest["step2"], expected, strict=True):
    events = device(run)
    label = run["label"]
    go = rows(label + "-go.jsonl")
    assert len(go) == run["go"]["attempts"] == 44
    assert sum(x["passed"] for x in go) == run["go"]["passed"] == go_passed
    assert all(not x["passed"] or x["source_matches"] for x in go)
    assert run["udpSweep"]["passed"] == phone_passed
    assert run["result"] == ("failed" if label == "cap-aes128" else "passed")
    if label == "cap-aes128-smoke":
        assert {k: run["counts"][k] for k in ("tcp", "udp", "dns-anchor", "connection-close-verified")} == {
            "tcp": 18, "udp": 12, "dns-anchor": 6, "connection-close-verified": 3,
        }
    startup = read(label + "-startup.json")
    server = read(label + "-server.json")
    setup = startup["setup"]
    assert setup == server["setup"]
    assert setup["before"] == 1 and setup["after"] == 0 and not setup["checkOnly"]
    assert setup["executableSha256"] == manifest["reference"]["vpsBinarySha256"]
    assert startup["state"]["ControlPID"] == "0" and startup["state"]["ActiveState"] == "active"
    assert startup["generation"] == server["generation"]
    assert startup["generation"]["generation"] == run["generation"]
    assert setup["pid"] not in pids
    pids.add(setup["pid"])
    for check in [startup["check"], server["afterCheck"]]:
        assert check["checkOnly"] and check["before"] == check["after"] == 0
        assert (check["pid"], check["fd"]) == (setup["pid"], setup["fd"])
    arrived = [(i, x) for i, x in enumerate(go) if x["passed"] or label == "cap-aes128-smoke"]
    phone = [x for x in events if x["event"] in ("udp", "udp-size-result") and x["result"] == "passed"]
    assert len(server["backend"]) == run["backendEchoes"]
    assert [x["bytes"] for x in server["backend"]] == [x["payload_bytes"] for _, x in arrived] + [x["bytes"] for x in phone]
    if not label.startswith("cap-"):
        continue
    correlation = read(label + "-go-correlation.json")
    packets = read(label + "-ip-metadata.json")
    omitted = correlation["uncapturedSuccessfulTrialIndices"]
    assert omitted == ([] if label == "cap-aes128" else [0])
    assert all(go[i]["passed"] for i in omitted)
    absent = correlation["requestAbsentTrialIndices"]
    assert absent == ([i for i, x in enumerate(go) if not x["passed"]] if label == "cap-chacha" else [])
    expected_indices = [i for i, _ in arrived if i not in omitted]
    assert [x["trial"] for x in correlation["captured"]] == expected_indices
    used = set()
    for pair in correlation["captured"]:
        trial = go[pair["trial"]]
        assert pair["passed"] == trial["passed"] and pair["payloadBytes"] == trial["payload_bytes"]
        for key, direction, extra in [("request", "In", 28), ("reply", "Out", 36)]:
            group = pair[key]
            members = [packets[i] for i in group["rows"]]
            assert not used.intersection(group["rows"])
            used.update(group["rows"])
            assert members[0]["offset"] == 0 and not members[-1]["MF"]
            assert all(x["direction"] == direction for x in members)
            if len(members) > 1:
                assert len({x["id"] for x in members}) == 1
                for first, second in zip(members, members[1:]):
                    assert first["MF"] and second["offset"] == first["offset"] + first["bytes"] - 20
            ip_bytes = members[-1]["offset"] + members[-1]["bytes"]
            assert ip_bytes == group["ipBytes"] == trial["sent_wire_bytes"][0] + extra
            if direction == "Out":
                assert all(not x["DF"] for x in members)
        if not trial["passed"]:
            assert label == "cap-aes128-smoke" and trial["payload_bytes"] == 1300
            assert trial["received_wire_bytes"] == [0] and pair["reply"]["ipBytes"] == 1398
        correlated += 1
assert len(pids) == 5 and correlated == 169
assert sum(x["action"] == "restart" for x in manifest["step2"]) == 2
negative = read("negative-control.json")
assert all(negative[k] for k in ("startRejected", "mainProcessStopped", "credentialsRemoved", "reservedPortServicesRestored"))
before, after = read("vps-before.json"), read("vps-cleanup.json")
assert before["ipNoPmtuDisc"] == after["ipNoPmtuDisc"] == "0"
for name in ["x-ui.service", "xray-xhttp-memory-probe.service"]:
    assert before["services"][name] == after["services"][name]
assert all(x["ActiveState"] == "active" for x in after["services"].values())
assert all(read("cleanup.json").values())
print("Verified 10 legacy invocations, 350 backend exchanges, 5 starts/2 restarts, all failed controls and 169 captured Go pairs")

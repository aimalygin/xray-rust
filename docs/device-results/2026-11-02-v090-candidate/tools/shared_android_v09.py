"""Android shared scenarios for v0.9, as in the 0.8.1 campaign (android-shared):
the v0.9 matrix's run_case over the shared fixture (vless-encryption,
ip-on-demand, xhttp-download-session), then the IP controls and host-adapter
projection of docs/device-results/2026-10-18-v081-candidate/android/projection-controls.py.
Projection uses the v0.9 protocol cases instead of the 0.8 ones."""
import copy, json, os, time
from pathlib import Path
import drive as d

env = json.loads((Path(os.environ["FIXTURE_DIR"]) / "v07-probe.json").read_text())
protocols = json.loads((Path(os.environ["PROTOCOL_FIXTURE_DIR"]) / "v07-probe.json").read_text())
try:
    d.emit("matrix-start", caseCount=len(env["cases"]), backends=["file-descriptor", "packet-pump"])
    for case in env["cases"]:
        for backend in ("file-descriptor", "packet-pump"):
            try:
                d.run_case(env, case, backend)
            except Exception as error:
                d.emit("case-fail", case=case["caseId"], backend=backend, error=str(error))
                raise
    d.emit("matrix-pass")
    positive = next(c for c in env["cases"] if c["caseId"] == "ip-on-demand")
    negative = copy.deepcopy(positive)
    config = json.loads(negative["configJSON"]); config["routing"]["domainStrategy"] = "AsIs"
    negative["configJSON"] = json.dumps(config)
    for backend in ["file-descriptor", "packet-pump"]:
        d.emit("ip-asis-negative-plan", backend=backend, expected="domain traffic rejected; literal IP still works")
        d.host_stop(); d.install_profile(negative); assert d.host_start(backend)["state"] == "running"
        d.emit("ip-asis-literal-control", backend=backend, status=d.traffic(env, "ipv4", 1))
        try:
            result = d.traffic(env, "domain", 1)
            d.emit("ip-asis-negative-control", backend=backend, passed=False, unexpectedTraffic=result)
        except RuntimeError:
            state = d.status(d.PROBE)
            ok = int(state.get("http-failed", 0)) + int(state.get("udp-failed", 0)) > 0
            d.emit("ip-asis-negative-control", backend=backend, passed=ok, status=state)
        d.host_stop(); d.install_profile(positive); assert d.host_start(backend)["state"] == "running"
        d.emit("ip-on-demand-recovery-control", backend=backend, status=d.traffic(env, "domain", 2)); d.host_stop()
    cases = [c for c in protocols["cases"] if c["caseId"] in ("socks-password", "http-plain", "shadowsocks-aead-aes-256-gcm")]
    for case in cases:
        for backend in ["file-descriptor", "packet-pump"]:
            d.host_stop(); d.install_profile(case); started = time.time()
            d.command(d.HOST, "connect", ("--es", "tun-backend", backend, "--ez", "probe-only", "true", "--ez", "tun-admission", "true"))
            state = d.wait_status(d.HOST, lambda s: s.get("state") in ("running", "failed", "fatal")); assert state["state"] == "running", state
            status = d.traffic(protocols, "ipv4", 2); d.command(d.HOST, "close-connections")
            raw = d.adb("logcat", "-d", "-v", "epoch", "-s", "XrayDeviceGate:I", "*:S")
            samples = []
            for line in raw.splitlines():
                if "XRAY_ANDROID_SAMPLE " in line and float(line.split()[0]) >= started:
                    samples.append(json.loads(line.split("XRAY_ANDROID_SAMPLE ", 1)[1]))
            sample = samples[-1]; passed = sample["admissionEnabled"] and sample["admissionAllowed"] > 0 and sample["fatalTunErrors"] == 0
            d.emit("host-adapter-projection", case=case["caseId"], backend=backend, passed=passed, traffic=status, sample=sample)
            assert passed; d.host_stop()
    d.emit("projection-controls-complete")
finally:
    d.probe_stop(); d.host_stop(); d.log_snapshot("projection-logcat.log")

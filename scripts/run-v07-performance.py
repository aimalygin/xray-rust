#!/usr/bin/env python3
"""Paired local v0.6.1/v0.7 benchmarks. Fresh processes; failures are retained.

Run the original v0.5/v0.6 gates separately. This collector adds old transport
coverage and same-driver SOCKS/TUN measurements for Hysteria2 and WireGuard.
It never changes host routes or invokes production VPNs.
"""
from __future__ import annotations

import argparse
import contextlib
import copy
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import signal
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = "5ca6f4b7d4dc20a881d4330e498892697627ec0c"
UUID = "00010203-0405-0607-0809-0a0b0c0d0e0f"


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def command(args, cwd=None):
    return subprocess.check_output([str(a) for a in args], cwd=cwd, text=True).strip()


def env():
    result = {k: v for k, v in os.environ.items() if not k.startswith(("XRAY_", "CARGO_PROFILE_"))}
    result.update(GOTOOLCHAIN="go1.26.5", GOENV="off", GOWORK="off")
    return result


def port(exclude=()):
    # XHTTP/3 uses both TCP and UDP. A free TCP port can already belong to
    # another UDP fixture, including an inbound not started yet in this config.
    for _ in range(64):
        with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            number = tcp.getsockname()[1]
            if number in exclude:
                continue
            try:
                udp.bind(("127.0.0.1", number))
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    continue
                raise
            return number
    raise RuntimeError("could not allocate a free TCP/UDP fixture port")


def load_module(path):
    spec = importlib.util.spec_from_file_location("fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@contextlib.contextmanager
def fixture(reference, output, reality=False):
    root = output / "fixture"
    root.mkdir(mode=0o700, parents=True)
    device = load_module(ROOT / "scripts/run-v07-apple-protocol-fixture.py")
    device.verify_reference(reference)
    device.write_fixtures(root, "127.0.0.1", 1, 2, 3)
    server = json.loads((root / "server.json").read_text())
    # The driver binds its synthetic origin to this host's own IPv4 interface.
    # No production credentials, DNS names or remote application targets.
    server.pop("routing")
    server["outbounds"] = [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}]
    configs = {}
    for case in json.loads((root / "v07-probe.json").read_text())["cases"]:
        config = json.loads(case["configJSON"])
        config.pop("inbounds")
        config.pop("dns")
        config.pop("routing")
        if case["format"] == "wireguard":
            config["outbounds"][0]["settings"]["peers"][0]["allowedIPs"] = ["0.0.0.0/0"]
        configs[case["format"]] = config
    cert = str(root / "tls.crt")
    key = str(root / "tls.key")
    pin = configs["hysteria2"]["outbounds"][0]["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"]
    configs["freedom"] = {"outbounds": [{"protocol": "freedom"}]}
    for name, network, alpn, mode in [("vless-tls", "raw", "http/1.1", None),
            ("xhttp-h1", "xhttp", "http/1.1", "packet-up"),
            ("xhttp-h2", "xhttp", "h2", "stream-up"),
            ("xhttp-h3", "xhttp", "h3", "stream-one")]:
        listen = port({int(inbound["port"]) for inbound in server["inbounds"]})
        stream = {"network": network, "security": "tls", "tlsSettings": {
            "alpn": [alpn], "certificates": [{"certificateFile": cert, "keyFile": key}]}}
        if network == "xhttp":
            stream["xhttpSettings"] = {"path": "/bench", "mode": "auto"}
        server["inbounds"].append({"protocol": "vless", "listen": "127.0.0.1", "port": listen,
            "settings": {"clients": [{"id": UUID}], "decryption": "none"}, "streamSettings": stream})
        client_stream = copy.deepcopy(stream)
        client_stream["tlsSettings"] = {"serverName": "v07-probe.test", "alpn": [alpn], "pinnedPeerCertSha256": pin}
        if mode:
            client_stream["xhttpSettings"]["mode"] = mode
        if alpn == "h3":
            client_stream["finalmask"] = {"quicParams": {}}
        configs[name] = {"outbounds": [{"protocol": "vless", "settings": {"vnext": [{
            "address": "127.0.0.1", "port": listen,"users": [{"id": UUID,"encryption": "none"}]}]},
            "streamSettings": client_stream}]}
    if reality:
        listen=port({int(inbound["port"]) for inbound in server["inbounds"]})
        settings={"serverName":"www.google.com","fingerprint":"chrome",
            "publicKey":"E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
            "shortId":"0123456789abcdef","spiderX":"/"}
        configs["reality-vision"]={"outbounds":[{"protocol":"vless","settings":{
            "vnext":[{"address":"127.0.0.1","port":listen,"users":[{
                "id":UUID,"encryption":"none","flow":"xtls-rprx-vision"}]}]},
            "streamSettings":{"network":"tcp","security":"reality","realitySettings":settings}}]}
        server["inbounds"].append({"protocol":"vless","listen":"127.0.0.1","port":listen,
            "settings":{"clients":[{"id":UUID,"flow":"xtls-rprx-vision"}],"decryption":"none"},
            "streamSettings":{"network":"tcp","security":"reality","realitySettings":{
                "dest":"www.google.com:443","serverNames":["www.google.com"],
                "privateKey":"aGSYystUbf59_9_6LKRxD27rmSW_-2_nyd9YG_Gwbks",
                "shortIds":["0123456789abcdef"],"type":"tcp"}}})
    save(root / "server.json", server)
    with (root / "server.log").open("w") as log:
        child = subprocess.Popen([str(reference), "run", "-config", str(root / "server.json")],
                                 stdout=log, stderr=log, env=env())
        try:
            time.sleep(8 if reality else 1)
            if child.poll() is not None:
                raise RuntimeError("reference failed to start; see fixture/server.log")
            yield configs
        finally:
            child.terminate()
            try:
                child.wait(5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()


def protocol_cases(suite, smoke):
    protocols = ["hysteria2", "wireguard"] if suite == "new" else ["freedom", "vless-tls", "xhttp-h1", "xhttp-h2", "xhttp-h3"]
    if suite == "reality": protocols = ["reality-vision"]
    paths = ["socks", "tun"] if suite in ("new", "reality") else ["tun"]
    cases = []
    for protocol in protocols:
        for path in paths:
            for connections in [1, 8]:
                traffic_types = ["upload", "download", "full-duplex", "tcp-latency", "udp"] if suite == "new" else ["upload", "download", "full-duplex"]
                for traffic in traffic_types:
                    latency = traffic in ("tcp-latency", "udp")
                    cases.append({"id": f"{protocol}-{path}-{traffic}-{connections}",
                        "protocol": protocol,"path": path,"traffic": traffic,"connections": connections,
                        "payload_size": 1200 if traffic == "udp" else 1024 if latency else 65536,
                        "iterations": (10 if latency else 4) if smoke else (1000 if latency else 64 if path == "tun" else 512)})
    return cases


def legacy_cases(smoke):
    iterations = "8" if smoke else "1024"
    cases = [{"id": "reality-vision-bulk-1", "args": ["--workload", "reality-vision-bulk-throughput", "--connections", "1", "--iterations", "4" if smoke else "256", "--payload-size", "4194304"]}]
    for transport in ["ws", "httpupgrade", "grpc", "xhttp-h1", "xhttp-h2", "xhttp-h3"]:
        for connections in [1, 8]:
            for traffic in ["upload", "download", "full-duplex"]:
                args = ["--workload", "stream-transport", "--stream-transport", transport,
                    "--traffic", traffic,"--connections",str(connections),"--iterations","512" if transport=="xhttp-h1" and not smoke else iterations,"--payload-size","65536"]
                if transport.startswith("xhttp"):
                    args += ["--xhttp-mode", {"xhttp-h1":"packet-up","xhttp-h2":"stream-up","xhttp-h3":"stream-one"}[transport]]
                cases.append({"id": f"{transport}-{traffic}-{connections}", "args": args})
    return cases


def campaign_processes(root, engines_only=False):
    prefixes=[str(root/"bin"/version/"xray-rust")+" " for version in ("baseline","candidate")]
    if not engines_only:
        prefixes += [str(root/"bin"/name)+" " for name in ("protocol-bench","xray-core")]
    found=[]
    output=command(["ps","-axo","pid=,command="])
    for line in output.splitlines():
        fields=line.strip().split(None,1)
        if len(fields)==2 and any(fields[1].startswith(prefix) for prefix in prefixes):
            found.append({"pid":int(fields[0]),"command":fields[1]})
    return found


def group_exists(pid):
    try:
        os.killpg(pid,0)
        return True
    except ProcessLookupError:
        return False


def kill_group(child):
    try:os.killpg(child.pid,signal.SIGKILL)
    except ProcessLookupError:pass
    child.wait()
    for _ in range(20):
        if not group_exists(child.pid):return
        time.sleep(0.05)
    raise RuntimeError("benchmark process group survived cleanup")


def execute(args, log, cwd=None):
    started = time.time()
    with log.open("w") as stream:
        child = subprocess.Popen(args, cwd=cwd, env=env(), stdout=stream,
                                 stderr=subprocess.STDOUT, start_new_session=True)
        try:
            code = child.wait(timeout=180)
            result={"returncode":code,"seconds":time.time()-started,"command":args}
        except subprocess.TimeoutExpired:
            kill_group(child)
            result={"returncode":124,"seconds":time.time()-started,"command":args,"error":"collector timeout"}
        except BaseException:
            kill_group(child)
            raise
        result["surviving_process_group"]=group_exists(child.pid)
        if result["surviving_process_group"]:
            kill_group(child)
            result.update(returncode=125,error="benchmark left live descendants")
        result["process_group_empty_after_run"]=not group_exists(child.pid)
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,required=True,help="campaign directory with bin/{baseline,candidate} and clean source checkouts")
    parser.add_argument("--harness",type=Path,required=True)
    parser.add_argument("--suite",choices=["legacy","tun","new","reality"],required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--smoke",action="store_true")
    parser.add_argument("--case",help="optional exact case ID for diagnosis; never replaces original evidence")
    parser.add_argument("--iterations",type=int,help="diagnostic work-size override; preserves original full campaign")
    args = parser.parse_args()
    args.root=args.root.resolve(); args.harness=args.harness.resolve(); args.output=args.output.resolve()
    existing=campaign_processes(args.root)
    if existing:raise RuntimeError(f"campaign processes already running: {existing}")
    args.output.mkdir(parents=True,exist_ok=False)
    repeats = 1 if args.smoke else 5
    cases = legacy_cases(args.smoke) if args.suite == "legacy" else protocol_cases(args.suite,args.smoke)
    if args.case:
        cases=[c for c in cases if c["id"]==args.case]
        if not cases: raise ValueError("unknown case")
    if args.iterations is not None:
        if args.suite=="legacy" or not 1<=args.iterations<=16384:raise ValueError("iterations override requires a generic suite and 1..16384")
        for case in cases:case["iterations"]=args.iterations
    versions = ["candidate"] if args.suite == "new" else ["baseline","candidate"]
    manifest={"schema_version":1,"suite":args.suite,"smoke":args.smoke,"diagnostic":bool(args.case or args.iterations is not None),
        "repeats":repeats,"cases":cases,"started_unix":time.time(),"platform":platform.platform(),
        "harness_sha256":sha(args.harness),"collector_sha256":sha(__file__),
        "fixture_policy":"shared suite reference after 8 second warmup; fresh client processes" if args.suite=="reality" else "fresh reference server and keys per run",
        "harness_source_sha256":{str(p.relative_to(ROOT)):sha(p) for p in sorted((ROOT/"crates/xray-bench/src").glob("*.rs"))},
        "cleanup_policy":"RAII kill/wait; per-run process-group and engine inventory verification",
        "preflight_campaign_processes":existing,
        "reference_sha256":sha(args.root/"bin/xray-core"),"reference_commit":REFERENCE,
        "review_thresholds":{"throughput_ratio_min":0.85,"latency_cpu_rss_ratio_max":1.15},
        "versions":{},"runs":[]}
    for version in versions:
        source=args.root/version
        if command(["git","status","--porcelain"],source):raise ValueError("source is dirty")
        manifest["versions"][version]={"commit":command(["git","rev-parse","HEAD"],source),
            "tree":command(["git","rev-parse","HEAD^{tree}"],source),"dirty":False,
            "engine_sha256":sha(args.root/"bin"/version/"xray-rust"),
            "original_harness_sha256":sha(args.root/"bin"/version/"xray-bench"),
            "cargo_lock_sha256":sha(source/"Cargo.lock")}
    save(args.output/"manifest.json",manifest)
    with contextlib.ExitStack() as fixtures:
        shared = fixtures.enter_context(fixture(args.root/"bin/xray-core",args.output,True)) if args.suite=="reality" else None
        for case in cases:
            for repeat in range(repeats):
                # Alternate first/second engine to reduce systematic thermal/order bias.
                order=versions if repeat%2==0 else list(reversed(versions))
                for version in order:
                    identifier=f"{case['id']}-{version}-{repeat+1}"
                    output=args.output/identifier
                    print(identifier,flush=True)
                    context=contextlib.nullcontext(shared) if shared is not None else contextlib.nullcontext({}) if args.suite=="legacy" else fixture(args.root/"bin/xray-core",args.output/f"{identifier}-server")
                    with context as configs:
                        if args.suite=="legacy":
                            invocation=[str(args.root/"bin"/version/"xray-bench"),"run","--engine","xray-rust",
                                "--xray-rust-bin",str(args.root/"bin"/version/"xray-rust"),
                                "--xray-core-bin",str(args.root/"bin/xray-core"),"--no-auto-build","--runs","1",
                                "--run-timeout-ms","150000","--out-dir",str(output),*case["args"]]
                        else:
                            request={k:case[k] for k in ["path","traffic","connections","iterations","payload_size"]}
                            request.update(binary=str(args.root/"bin"/version/"xray-rust"),
                                config=configs[case["protocol"]],output=str(output))
                            request_path=args.output/f"{identifier}.json"
                            save(request_path,request)
                            invocation=[str(args.harness),"protocol-run",str(request_path)]
                        result=execute(invocation,args.output/f"{identifier}.log",args.root/version)
                    result["remaining_engine_processes"]=campaign_processes(args.root,True)
                    if result["remaining_engine_processes"]:raise RuntimeError("engine process survived benchmark cleanup")
                    result.update(case=case["id"],version=version,repeat=repeat+1,output=str(output),output_relative=identifier)
                    manifest["runs"].append(result)
                    save(args.output/"manifest.json",manifest)
                    print(f"  rc={result['returncode']} elapsed={result['seconds']:.1f}s",flush=True)
                    if result["surviving_process_group"]:raise RuntimeError("stopping after benchmark child leak")
    manifest["finished_unix"]=time.time()
    if sha(__file__)!=manifest["collector_sha256"]:
        raise RuntimeError("collector changed during measurement")
    for relative,digest in manifest["harness_source_sha256"].items():
        if sha(ROOT/relative)!=digest:raise RuntimeError("harness source changed during measurement")
    if sha(args.harness)!=manifest["harness_sha256"]:
        raise RuntimeError("harness changed during measurement")
    for version in versions:
        if sha(args.root/"bin"/version/"xray-rust")!=manifest["versions"][version]["engine_sha256"]:
            raise RuntimeError("engine changed during measurement")
    manifest["status"]="pass" if all(r["returncode"]==0 for r in manifest["runs"]) else "fail"
    save(args.output/"manifest.json",manifest)
    if manifest["status"]!="pass":raise SystemExit(1)


if __name__=="__main__":
    main()

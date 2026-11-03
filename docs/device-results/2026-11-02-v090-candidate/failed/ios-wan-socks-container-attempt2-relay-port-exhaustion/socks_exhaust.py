import json, socket, struct, sys, ipaddress
env = json.loads(open(sys.argv[1]).read()); n = int(sys.argv[2])
cfg = json.loads(env["cases"][0]["configJSON"]); out = next(o for o in cfg["outbounds"] if o.get("protocol") == "socks")
s = out["settings"]; server = s.get("address") or s["servers"][0]["address"]; port = s.get("port") or s["servers"][0]["port"]
user = s.get("user") or s["servers"][0]["users"][0]["user"]; pw = s.get("pass") or s["servers"][0]["users"][0]["pass"]
def associate():
    c = socket.create_connection((server, port), timeout=5)
    c.sendall(b"\x05\x01\x02"); c.recv(2); u, p = user.encode(), pw.encode()
    c.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p); c.recv(2)
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("0.0.0.0", 0)); udp.settimeout(3)
    c.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00" + struct.pack("!H", udp.getsockname()[1]))
    r = c.recv(10); return c, udp, r[1], struct.unpack("!H", r[8:10])[0]
held = []
for i in range(n):
    c, udp, status, bport = associate(); held.append((c, udp))
    # one echo per association so freedom also opens its own UDP session
    udp.sendto(b"\x00\x00\x00\x01" + socket.inet_aton("198.51.100.7") + struct.pack("!H", env["udpPort"]) + b"x" * 32, (server, bport))
    try: udp.recvfrom(4096); ok = "echo"
    except socket.timeout: ok = "timeout"
    print(i + 1, "status", status, "relay", bport, ok)

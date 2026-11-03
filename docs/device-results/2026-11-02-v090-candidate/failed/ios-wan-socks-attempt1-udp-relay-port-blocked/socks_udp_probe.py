import json, socket, struct, sys, ipaddress
env = json.loads(open(sys.argv[1]).read())
cfg = json.loads(env["cases"][0]["configJSON"])
out = next(o for o in cfg["outbounds"] if o.get("protocol") == "socks")
s = out["settings"]; server = s.get("address") or s["servers"][0]["address"]; port = s.get("port") or s["servers"][0]["port"]
user = s.get("user") or s["servers"][0]["users"][0]["user"]; pw = s.get("pass") or s["servers"][0]["users"][0]["pass"]
c = socket.create_connection((server, port), timeout=5)
c.sendall(b"\x05\x01\x02"); assert c.recv(2) == b"\x05\x02"
u, p = user.encode(), pw.encode(); c.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p); assert c.recv(2)[1] == 0
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.bind(("0.0.0.0", 0)); udp.settimeout(4)
c.sendall(b"\x05\x03\x00\x01" + b"\x00\x00\x00\x00" + struct.pack("!H", udp.getsockname()[1]))
r = c.recv(10); ip = str(ipaddress.ip_address(r[4:8])); bport = struct.unpack("!H", r[8:10])[0]
print("reply", r[:2].hex(), "bnd", "server-ip" if ip == server else ("unspecified" if ip == "0.0.0.0" else "OTHER:" + ip.split(".")[0] + ".x.x.x"), "port", bport)
relay = (server if ip == "0.0.0.0" else ip, bport)
dg = b"\x00\x00\x00\x01" + socket.inet_aton("198.51.100.7") + struct.pack("!H", env["udpPort"]) + b"hello-udp"
udp.sendto(dg, relay)
try:
    data, src = udp.recvfrom(4096); print("udp reply", len(data), "bytes from", "relay" if src[0] == relay[0] else "other")
except socket.timeout:
    print("udp timeout")

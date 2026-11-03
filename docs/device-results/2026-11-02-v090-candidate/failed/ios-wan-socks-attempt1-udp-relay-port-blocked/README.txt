Xray SOCKS UDP ASSOCIATE replied BND=server IP, port 50137 (ephemeral, per association; Xray proxy/socks/protocol.go ListenSystemPacket Port 0).
The VPS provider exposes only 53053: raw UDP to 53053 reached ens6, UDP to 40000 did not; no UDP from the client reached the server during the probe.
Literal IPv4/IPv6 TCP over WAN passed; the domain step failed because DNS goes through the SOCKS UDP association.

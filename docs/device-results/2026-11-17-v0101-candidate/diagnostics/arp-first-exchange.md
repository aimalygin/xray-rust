# First exchange after an iPhone tunnel start: ARP for the fixture host — diagnostic, NOT evidence (2026-11-17)

Why this directory exists: on this stand `ios-v010-resources` a1, `ios-smoke-v010` a1 and a2 and `ios-shared` a1
failed on the first exchange after a tunnel start, on four different carriers (`mkcp:vless`, `vless-reverse:bridge`,
`xdns:mkcp`, `xhttp-download-session`); only the last goes through TLS, which this release changes.

What was found, from the phone capture the 0.10.0 diagnosis kept
(`release-0100/device-706a766c.noindex/results/ios/diagnostics/tunnel-start/loop6-capture/rvi0.pcapng`,
`tcpdump -k INPDF -n -tttt -r`): at every tunnel start the phone asks for the fixture host's hardware address
again (`ARP who-has <Mac> tell <phone>`), 39 times in that loop of 21 starts; the reply comes after a median of
0.2 s, and six times only after 1.2–2.3 s, the request repeated each second. In each of those six the Tunnel
process's first SYN, TCP's retransmits of it and the UDP datagrams queued meanwhile leave en0 within 0.4 ms of the
ARP reply. So the packets the 0.10.0 write-up called «held below TCP» are waiting for ARP. The fixture host is this
Mac on Wi-Fi (en1, AWDL active), and an ARP request is a broadcast frame, which Wi-Fi delivers without
acknowledgement. XNU gives a neighbour up after five unanswered requests (`net.link.ether.inet.maxtries: 5`),
which is what a failed start looks like: a dial that takes about 5 s and then fails at once, or nothing through
for the probe's 10 s.

Consequences: the family belongs to the LAN test bed (a fixture host that answers ARP late), not to the phone's
handling of the extension and not to the core; it does not exist toward a server behind the router (the public-host
runs). The 0.10.0 campaign's counts (154 starts, 3 failed, 15 slow) are the same thing.

Loops here (`loop.sh`, one `shadowsocks-aead` case copied 14 times, three tunnel cycles each):

| loop | test bed | starts | failed | slow (≥2 s) |
|---|---|---|---|---|
| `k1-keepawake` | Mac pings the router at 10 Hz | 0 — the phone had locked itself, the app did not launch | | |
| `k2-keepawake` (02:37–02:41Z, the Android LAN queue running on the same Mac) | Mac pings the router at 10 Hz (2059 sent, 0.2% lost, 2.4/9.5/155 ms) | 42 | 0 | 1 |
| `k3-control` (02:53–02:59Z, the Android LAN queue still running on the same Mac) | no ping | 67 | 0 | 2 |

`k3-control`'s three runs each ended early on a UDP exchange, not on a first exchange: the reference Xray-core
server routed four of that loop's Shadowsocks UDP flows to the fixture's ranges to `[blocked]`, its default
outbound (1477 flows accepted; `k2-keepawake`: 936 accepted, none blocked). That is the reference server's own
behaviour, seen in the 0.10.0 diagnosis too (6 in about 2500 flows), and no counted run of this stand has one.

What the loops show and what they do not. The counted runs made before them, with nothing else using the Mac's
Wi-Fi, have 76 tunnel starts, 3 failed first exchanges and 8 slow ones, and the failed resources attempt beside
them. The two loops, made while the Android queue's traffic kept the Mac's radio busy, have 109 starts, none
failed and 3 slow, with the ping and without it alike. That fits a Mac whose radio is in use
answering the phone's ARP in time more often, on small numbers; whether the ping adds anything to that the loops
cannot tell. The counted iPhone runs
after the first loop were made with the ping running (58 starts, none failed, 3 slow). It changes nothing in the
phone or the candidate, and their notes say so.

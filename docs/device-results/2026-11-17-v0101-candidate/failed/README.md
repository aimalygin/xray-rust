# Failed attempts of the counted runs

Every attempt of a counted run that did not pass is kept here as the device wrote it (the
attempt's own `result.json`; fixture inputs and raw server logs are not published). No run was
given more than three attempts, and no failed attempt was deleted or overwritten.

| File | Run and attempt | What failed |
| --- | --- | --- |
| [ios/ios-v010-resources-attempt-1-result.json](ios/ios-v010-resources-attempt-1-result.json) | `ios-v010-resources`, attempt 1 | `mkcp:vless`, the run's first exchange: the TCP exchange timed out at the probe's 10 s. The reference server accepted the flow 11 s after the probe started it and nothing before. Attempt 2 passed. |
| [ios/ios-smoke-v010-attempt-1-result.json](ios/ios-smoke-v010-attempt-1-result.json) | `ios-smoke-v010`, attempt 1 | Six cases passed all three cycles. `vless-reverse:bridge`, cycle 3: the tunnel took 5.41 s to connect (0.3 s is usual) and the first TCP exchange closed at once (Network code 1); the portal logged no flow of that cycle. 21 starts, 1 failed first exchange, 5 slow. |
| [ios/ios-smoke-v010-attempt-2-result.json](ios/ios-smoke-v010-attempt-2-result.json) | `ios-smoke-v010`, attempt 2 | `xdns:mkcp`, cycle 2: the tunnel connected in 0.25 s and took the probe's whole payload, the first TCP exchange timed out at 10 s, and the reference server accepted the flow 11 s after the probe started it. Attempt 3 passed. |
| [ios/ios-shared-attempt-1-result.json](ios/ios-shared-attempt-1-result.json) | `ios-shared`, attempt 1 | `xhttp-download-session`, cycle 2: the tunnel connected in 0.23 s, the first TCP exchange failed at 10 s (Network code 1) and the reference server logged no flow of that cycle. `vless-encryption` and `ip-on-demand` had passed. Attempt 2 passed. |
| [ios/ios-wan-masque-attempt-1-result.json](ios/ios-wan-masque-attempt-1-result.json) | `ios-wan-masque`, attempt 1 | Operator timeout, not a traffic failure. The Wi-Fi baseline passed (IPv4, IPv6 and domain TCP, both UDP sizes, routed DNS; recovered in 3.25 s). The app then asked for Wi-Fi off, and nothing was done on the phone for the prompt's 180 s (failure code 6). Attempt 2 passed. |

Every Samsung run passed on its first attempt.

## The four LAN failures have one cause, and it is the test bed's

All four are the first exchange after a tunnel start, on four different carriers
(`mkcp:vless`, `vless-reverse:bridge`, `xdns:mkcp`, `xhttp-download-session`). Three of them use
no TLS, REALITY or QUIC, so nothing this release changes is on their path; only the XHTTP
download session goes through TLS. The TUN path and the network stack are those of v0.10.0.
Each attempt that followed passed on the same build.

[diagnostics/arp-first-exchange.md](../diagnostics/arp-first-exchange.md) has what they are. At
every tunnel start the iPhone asks for the hardware address of the fixture host again (ARP). The
fixture host is a Mac on Wi-Fi, and it sometimes answers that broadcast request late or not at
all. The tunnel's first packets wait in the phone for the answer: a second or two is a slow first
exchange, and five unanswered requests make the phone give the neighbour up, which is a failed
one. A server behind the router is not looked up this way, so the public-host runs do not have it.
That reading rests on a phone capture kept from the 0.10.0 campaign, made on the same phone, Mac
and network; no capture was made of these four attempts themselves.

After that was found, the remaining iPhone LAN runs were made with the Mac pinging the router ten
times a second, which changes nothing in the phone or the candidate. The counted attempts made
that way have 58 tunnel starts, none failed and three slow (2 s or more). The attempts before it
have 76 starts by the same count, 3 failed and 8 slow, and the failed resources attempt beside
them. A control loop without the ping did as well as one with it (67 starts and 42, none failed),
both while the Android runs kept the Mac's Wi-Fi busy: the Mac's idle radio is the likelier
difference, and the ping by itself is not shown to matter.

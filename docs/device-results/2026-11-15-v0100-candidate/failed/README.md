# Failed attempts

Every failed attempt of a counted run is kept here with its own device output, plus the
third candidate's two failed WAN MASQUE attempts, whose run was made again on the fourth
candidate. Fixture inputs, launch descriptors and raw server or device logs are not
published.

## Fourth candidate (7eb199bb)

- `android-resources-attempt-1/events.jsonl`: the Android resource collector at its
  original stress of 32 connections at once.
  - mKCP passed on both backends.
  - MASQUE, file-descriptor backend, cycle 1: the probe's stress finished in 0.75 s. 68 of
    240 HTTP requests passed, 172 failed at once, and all 480 UDP passed.
  - Cause: a MASQUE or WireGuard tunnel admits 16 TCP flows at once, idle ones included,
    and refuses the next one at once.
  - The collector also matched the stress completion line by the host's clock while the
    phone's ran 1.54 s behind. It therefore missed that early completion, reported "stress
    completion deadline" and stopped before MASQUE packet-pump.
  - The owner decided (2026-11-15, «Ограничение и перепрогон») to list the bound as a known
    limitation and re-run with 8 connections for MASQUE. Attempt-2
    (`../android/android-resources/`, collector `../tools/campaign/resources_v010_masque8.py`,
    diff `../tools/resources_v010_masque8.diff`) passed every burst on all four scenarios.

## Third candidate (706a766c), iPhone LAN runs carried over

Each failed on the first exchange after a tunnel start, and its second attempt passed
(see the known limitation "ios-slow-first-exchange").

- `ios-706a766c/ios-smoke-v010-attempt-1-result.json`: `realm:mkcp` cycle 2. After the
  tunnel restart the first TCP exchange to the fixture closed after 4 s. The server logged
  no TCP flow for it, while the phone's DNS flows kept arriving. Cycle 1 and `xdns:mkcp`
  had passed; the remaining five cases did not run.
- `ios-706a766c/ios-legacy-v010-attempt-1-result.json`: `shadowsocks-aead` cycle 1. The
  first TCP exchange after the tunnel start timed out after 10 s and never reached the
  server. The other eleven protocols passed three cycles each.
- `ios-706a766c/ios-shared-attempt-1-result.json`: `ip-on-demand` cycle 3. The first step
  after the tunnel start, resolving the synthetic name through the core's FakeDNS, timed
  out after 10 s. `vless-encryption` and the first two `ip-on-demand` cycles had passed.

## Third candidate (706a766c), WAN MASQUE (not counted; made again on 7eb199bb)

- `ios-706a766c/ios-wan-masque-attempt-1-result.json` and
  `ios-706a766c/ios-wan-masque-attempt-2-result.json`: both failed on the return from
  cellular to Wi-Fi.
  - One DNS answer was lost when the tunnel moved to its Wi-Fi socket: the vendored Quinn
    had closed the socket the connection was leaving while the answer was still on its way.
  - The resolver failed the lookup after 4 s, and iOS kept that failure for the name.
  - Fixed by #299, which is in the fourth candidate. The fourth candidate's
    `ios-wan-masque` passed on its first attempt.

# iPhone Hysteria checks and release decision

The production candidate was core `f61eddaf40bcb2144933208438f3f4791cbbabca`
and SDK `ca0ba5480b4764f210cc7d16961ee00abe9dc4e7`. These identities must not be
relabeled as a later stable build. The retained [post-reboot summary](post-reboot-summary.json)
and [diagnostic packet matches](post-reboot-timeout.json) preserve failed outcomes.

The first post-reboot attempt failed CPU preflight before any measurement.
After a separate idle window, the next attempt completed one 512 MiB duplex
transfer, rejected by its declared CPU gate, then received TCP EOF during the
64 KiB initial exchange. The failure window passed its host/thermal gate, with
no swap and no VPN process restart. No complete A/A or A/B pair was obtained.

A separate instrumented/proxied 20-cold-start campaign reproduced one timeout
among 160 flow observations. All 1,253 logged sends and 1,066 receives were
matched. A fixed-clock-offset-independent comparison places about 3 seconds
of initial-packet delay before Mac UDP kernel receipt; it does not identify
the responsible device, driver or network hop. Kernel-to-userspace processing
was at most 2.799 ms. No general Wi-Fi-causality claim is made.

Earlier exact-production functional runs passed 20 limit/admission scenarios,
30 cold runtime starts and 12 selected Trojan/SS2022/VMess cases. Passing
observations do not erase later failures. The original sanitized archives and
full raw attempts remain in the SDK workspace Artifacts directory.

The summary's pending-capture field is historical: the owner subsequently
stopped diagnostics; administrator packet capture was never started. On
2026-10-11 the owner explicitly deferred this Hysteria investigation and the
unconfirmed 5% performance condition for the requested release. See the
[scoped decision](../../releases/v0.8.0-owner-decisions.json). This is release
acceptance of uncertainty, not a product fix or a passing performance result.

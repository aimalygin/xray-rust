# SS2022 server UDP fragmentation policy

For the pinned Linux Xray-core server, an optional startup hook can apply
`IP_MTU_DISCOVER=IP_PMTUDISC_DONT` to a single native SS2022 IPv4 UDP listener.
This preserves the setting across service **start/restart** without a relay,
modified Xray binary, resident helper or host-wide network changes. It addresses
the [measured DF-dependent reply loss](device-results/2026-10-04-iphone17-ss2022-mtu/README.md).
It does **not** guarantee delivery of fragmented UDP or fix packets lost before
they reach the server. The [restart acceptance report](device-results/2026-10-04-iphone17-reliability-deployment/README.md)
retains additional request and reply losses, including an unfragmented reply.
This is an opt-in deployment workaround, not a general production-path fix.

## Validated scope

[set-xray-ss2022-udp-pmtu.py](../scripts/set-xray-ss2022-udp-pmtu.py) requires
Linux x86_64, cgroup v2, Python 3.9 or later with `os.pidfd_open`, the architecture
syscall header `/usr/include/x86_64-linux-gnu/asm/unistd_64.h`, and permission to
use `pidfd_getfd` on the selected process. The test host used Linux 6.8 and
systemd 255. A service's privilege/capability/seccomp/proc restrictions may
prevent this operation; do not weaken unrelated host protections to force it.
The [Linux API](https://man7.org/linux/man-pages/man2/pidfd_getfd.2.html) duplicates
a descriptor referring to the same open file description and uses ptrace access
checks. The helper closes its duplicate before exiting.

The helper accepts only one matching process in the named service's own cgroup,
with the exact executable path, SHA-256 and single-config command line:
`EXE run -config ABSOLUTE_CONFIG`. It verifies an explicitly UDP-enabled native
SS2022 inbound, a unique socket FD on the selected port, IPv4 datagram type and
an unconnected socket. All three SS2022 methods are accepted. Ambiguous matches,
wrong binary pins, missing permissions and other unsupported configurations fail
the hook; the service is not reported successfully started.

The config, executable, helper, service definition and optional audit directory
must be administrator-owned and trusted. This is not an isolation boundary
against a malicious service process. Config mutation, process exec or dynamic
listener replacement during inspection are outside its supported contract.
Keep the config fixed while the service runs. Executable path matching does not
accept a deleted/replaced running binary; restart with a reviewed new pin.

## Service recipe

For an already authorized, separately managed SS2022 service, install the helper
at an administrator-owned absolute path and add an `ExecStartPost` entry. Replace
**all** placeholders below with that service's actual values; compute and review
the binary pin before installation. The helper must see the service's cgroup,
proc files and architecture header. The startup hook needs the required
privileges; this example assumes a service where those are already available.

```ini
[Service]
ExecStart=/ABSOLUTE/XRAY run -config /ABSOLUTE/server.json
ExecStartPost=/usr/bin/python3 /ABSOLUTE/set-xray-ss2022-udp-pmtu.py --unit %n --config /ABSOLUTE/server.json --executable /ABSOLUTE/XRAY --sha256 REPLACE_WITH_REVIEWED_64_HEX_SHA256 --port REPLACE_WITH_UDP_PORT
TimeoutStartSec=20
```

This illustrates the matching invocation; when editing an existing unit, preserve
its intended `ExecStart` and other settings rather than appending a second
`ExecStart`. Use a controlled restart so the hook runs on each new socket.
An optional `--audit /ADMIN_OWNED_DIRECTORY/socket-setup.json` writes private
before/after/PID/FD metadata atomically. `--check` verifies the current policy
without changing it. A nonzero hook result fails startup; retain that failure
and inspect the unit logs. Do not prefix this hook with systemd's failure-ignoring
`-` marker. See [systemd.service](https://www.man7.org/linux/man-pages/man5/systemd.service.5.html).

This hook is not reapplied by arbitrary API/hot-reload listener replacements.
There is also a short bind-to-hook window: systemd startup completion waits for
`ExecStartPost`, but external senders can reach an already-bound listener before
the hook finishes. The validated recipe uses start/restart and starts acceptance
traffic only after the hook succeeds. Recheck `--check` after traffic as well.

Do not substitute inbound `customSockopt` in this pinned Xray version: its
`transport/internet/sockopt_linux.go` applies inbound custom options inside the
TCP branch. This UDP hook does not change TCP or an IPv6 outer listener.
Both IPv4 and IPv6 **logical destinations** in the test use an IPv4 carrier.

## Resource and acceptance limits

The hook runs once and exits; it introduces no persistent proxy process or
extra userspace forwarding buffer. That structural property is not a measured
CPU/memory improvement: kernel fragmentation/reassembly costs, energy, saturated
throughput and long-term memory were not benchmarked in this campaign.
[Linux IP documentation](https://man7.org/linux/man-pages/man7/ip.7.html) describes
the socket fragmentation/PMTU policy. IP fragmentation remains path-dependent.

Five successful test starts, including two actual `systemctl restart` actions,
reapplied 1 → 0 on distinct Xray processes. Read-only checks before/after traffic
confirmed 0; a deliberately wrong hash rejected startup and stopped the fixture.
The temporary service files were removed afterward. **No production service was
modified or enabled**, and the repository adds no automatic deployment. The
client runtime, TUN MTU, SDK pins and authentication remain unchanged.

For a new deployment, retain default-policy controls and test the actual path,
all needed ciphers/sizes, restart, and both request/reply directions. Persistent
application of a socket option is a separate result from full network
reliability. Current remaining losses require client-side packet evidence or
another controlled path to locate the dropping hop; repeated passing trials
alone cannot explain them.

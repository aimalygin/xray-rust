# Replaying physical Android regressions

Use the isolated `.v08` host/probe APKs identified in the report. They require
ordinary Android VPN consent, which this campaign already had. Do not substitute
base/rc07 apps or profiles. Set `ADB`, `ANDROID_SERIAL` and
`XRAY_DEVICE_WORK_DIR` to a fresh private 0700 directory. Copy `drive.py`,
`campaign.py`, `udp-cancel.py` and the supplemental `*-control.py` scripts here.
Set `XRAY_CORE_ROOT` to the repository root for the pinned Go-client control. These controllers contain no server
credentials; each imports a fixture's generated profile into the isolated store.

For each suite `legacy`, `v07`, `v08`, launch the repository's
`scripts/run-v08-android-protocol-fixture.py --suite SUITE --protocol v08
--bind YOUR_LAN_IPV4 --reference-binary PINNED_XRAY --reference-sha256 HASH
--seconds 1800 --output "$XRAY_DEVICE_WORK_DIR/fixture-SUITE"`, capturing stdout
in `fixture-SUITE.log` in the same work directory. Wait for `Fixture ready`, then
run `python3 campaign.py --suite SUITE`. Inspect every verdict; a previous
failed attempt is never overwritten. Gracefully stop that owned fixture.

For UDP cancellation, start a fresh fixture with the same suite and
`--udp-delay-seconds 3`, output directory `fixture-SUITE-udp`, stdout log
`fixture-SUITE-udp.log`. Run `python3 udp-cancel.py --suite SUITE`. All tests and
fixtures are sequential; do not run two device controllers together.
`--only-case`, `--only-backend` permit an explicit pilot;
`--skip-passed` continues the same fixture's matrix after that pilot. Do not use
it across changed fixtures, APKs or campaigns.

The initial TCP fixture and pilot controller snapshots retain their original
bytes/hashes for provenance. `fixture-initial.py` expects the repository script
location when run; it is an archival source snapshot, not an alternative path
to invoke directly from this folder. `udp-cancel-pilot-initial.py` retains the
known leading-whitespace parsing defect and is never the replay entry point.

The finite server lifetime removes keys/configs automatically on graceful
shutdown. Controllers stop probe/VPN in `finally` but leave the encrypted test
profile for diagnostics. Afterwards remove only `.v08` pending imports and
`no_backup/device-gate-profile.bin`, force-stop those two test apps, and record
fixture termination, credential cleanup and device state. Keep original failed
runs. Wi-Fi/cellular and lock/wake are owner-skipped; these scripts do not toggle
network settings or lock the device.

## Supplemental teardown controls

Run these after the primary matrices, with no overlapping phone controller.
`wireguard-stop-control-initial.py` is archival: it incorrectly requires the
direct-stop control to reproduce a timeout. Use `wireguard-stop-control.py`,
which records EOF or timeout. `--only-backend` can select one path;
`XRAY_WG_FIXTURE_NAME` and `XRAY_WG_RUN_START` name a distinct follow-up fixture
and numeric request-ID range without overwriting earlier data.
Start a fresh `--suite v07` fixture in `fixture-wireguard-stop`, capturing
`fixture-wireguard-stop.log`, and run `wireguard-stop-control.py`. It compares
whole-VPN stop against explicit connection close before stop on each path.
Stop that fixture before the next one.

Start a fresh `--suite v08` fixture in `fixture-ss2022-control`, capturing
`fixture-ss2022-control.log`. Run `ss2022-go-control.py`, then
`ss2022-local-control.py`. The Go control uses the pinned binary at
`$XRAY_CORE_ROOT/target/v08-comparison/bin/xray`: it closes the local SOCKS
connection and then terminates its own client process, while observing the
server-side held request. It does not modify the reference checkout. The local
control separates phone cancellation/recovery from the three-second remote-EOF
criterion for all three ciphers and both TUN paths.

The recorded `trojan-udp-repeat.py` is the measured sequential follow-up driver.
It waits for this campaign's SS scheduler completion marker. To replay its four
trials independently, use four fresh private directories/fixtures with the
three-second UDP delay and run `udp-cancel.py --suite v08 --only-case trojan-tls
--only-backend PATH`, in order PacketPump, FileDescriptor, PacketPump,
FileDescriptor. Retain each directory's events and backend log independently;
do not use `--skip-passed` or overwrite the first failed recovery. The measured
scheduler receives the LAN address from `XRAY_FIXTURE_BIND`; no address or
secret is embedded in its published source.

# Replaying the bounded Android campaign

These controllers are the measured scripts with the private serial, local ADB
path and output location replaced by environment variables. Use only the
isolated `.v08` test APKs. They import profiles, start/stop the VPN, drive the
separate probe UID and append events. They do not grant VPN consent, toggle
Wi-Fi, modify other apps, or clean up credentials automatically.

Set `ADB`, `ANDROID_SERIAL` and `XRAY_DEVICE_WORK_DIR` (a fresh private 0700
directory). Launch `scripts/run-v08-android-protocol-fixture.py` from repository
root with the pinned reference binary/hash, `--protocol v08`, `--seconds 1800`,
`--bind YOUR_LAN_IPV4` and `--output "$XRAY_DEVICE_WORK_DIR/fixture"`.
Create a relative `fixture3 -> fixture` symlink inside the work directory.
The fixture rejects an already-existing output directory; do not reuse keys.
Install the identified host/probe APKs with `adb -s "$ANDROID_SERIAL" install
-r -t APK`. Run `python3 reproduce/drive.py prepare`, approve the ordinary
system VPN prompt, then run these **sequentially**, without concurrent builds:

```sh
python3 reproduce/idle-cpu.py
python3 reproduce/drive.py matrix
python3 reproduce/resources-all.py
python3 reproduce/controls.py
```

The matrix stops on the first failure. Resource collection keeps traffic and
RSS/thread verdicts separate, retaining unsuccessful requests. A normal exit
from resource collection only means collection completed: inspect every
`resource-case-complete` verdict. CPU ticks use the device's `CLK_TCK` (100 on
this Samsung); the idle thread diagnostic assumes 100 and must be adjusted on
a device with a different tick frequency. Resource recovery is 15 seconds
followed by five samples with 1-second sleeps plus ADB overhead.

Archive `device-logcat.log` after the matrix and each version of
`resource-logcat.log` during resource collection: Android's ring buffer can
overwrite older lines. Stop the probe and VPN, remove only the `.v08` private
pending imports and `device-gate-profile.bin`, and terminate the owned fixture
gracefully to remove its generated credentials. Keep original failed events
and APK identities when making a corrective change.

`build-native.sh` preserves the measured release flags (warnings denied, both
16-KiB link-page settings, no incremental build and commit-based
`SOURCE_DATE_EPOCH`). Before running it, place a clean detached checkout of
`de33998158e84c03f280f979ba2d4212072e5bc4` at
`$XRAY_DEVICE_WORK_DIR/core-source`, install the recorded Rust/NDK versions
and set `ANDROID_HOME`. Offline Cargo dependencies must already be present.
It writes only the campaign's native build outputs. This is a reconstruction
recipe; building at a different absolute path need not reproduce the same hash.
Use the new adapter source separately and retain each APK/source identity.

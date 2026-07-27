# Geodata for the Apple sample

`geoip.dat` and `geosite.dat` are generated third-party assets and should not
be committed to this repository.

From the repository root, install the pinned, checksum-verified versions with:

```sh
./scripts/fetch-geodata.sh
```

The default destination is this directory. To prepare another bundle or test
directory, use an explicit override:

```sh
./scripts/fetch-geodata.sh --output-dir /absolute/path/to/dat
```

The script downloads immutable V2Fly release assets, verifies hard-coded
SHA-256 digests, and only then replaces the destination files. The upstream
`dlc.dat` asset is installed as `geosite.dat`, which is the name expected by
the runtime and the Xcode sample targets.

Version, provenance, attribution, and license details are recorded in the
repository's [`THIRD_PARTY_NOTICES.md`](../../../../THIRD_PARTY_NOTICES.md).
Retain those notices when redistributing an application that bundles the
data.

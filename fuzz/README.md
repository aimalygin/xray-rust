# Fuzz targets

The fuzz package shares the release workspace and lockfile, while its binary
targets are excluded from ordinary tests. libFuzzer instrumentation still
requires a nightly compiler. The release-candidate CI gate uses the pinned
nightly and `cargo-fuzz` versions recorded in `.github/workflows/ci.yml` and
bounded `-runs` values so the campaign has a deterministic upper bound.

Run one target locally, for example:

```sh
cargo +nightly-2026-05-22 fuzz run config_json -- -runs=1024 -max_len=65536
```

Crashes and minimized reproducers appear under `fuzz/artifacts/`; that
directory is ignored to avoid committing arbitrary crash blobs by accident.
An unresolved finding must still be tracked explicitly and block the release.
Record and regression-test every resolved finding before removing its local
artifact.

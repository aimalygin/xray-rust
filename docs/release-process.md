# Release process

How a stable `vMAJOR.MINOR.PATCH` release moves from candidate to published
packages in this repository and in
[xray-rust-mobile](https://github.com/aimalygin/xray-rust-mobile). Per-release
scope, owner decisions and results go in `docs/vXYZ-release.md`; this page
covers only the steps shared by every release.

A release candidate (`-rc.N`) tag differs in one way: its tag CI reruns every
gate and publishes the GitHub prerelease itself.

## Core

1. **Release commit.** Bump the workspace version, date the changelog section,
   regenerate the configuration contract
   (`cargo run -p xray-config --example config_contract > docs/config-contract.json`)
   and merge. That commit is the candidate; every later step binds to its
   revision and tree.
2. **Candidate CI.** Dispatch **CI** on a branch whose head is the candidate
   (`gh workflow run ci.yml --ref <branch>`). This is the only full run: on top
   of ordinary CI it runs `rc-interop`, `host-hardening`, `fuzz-smoke`,
   `controlled-network` and `scheduled-pinned-interop`. Every job must pass
   except `xray-core-main-smoke`, which follows Xray-core `main` and only
   warns. Rerunning failed jobs, or dispatching again, is fine; the tag binds to
   the newest passing run.
3. **Device evidence.** Collect it on the candidate, then dispatch the
   `vXY-release-evidence.yml` workflow for the minor version on the candidate
   with the archive URL and SHA-256.
4. **Publish the evidence on `main`**: `docs/releases/vX.Y.Z-owner-decisions.json`,
   `vX.Y.Z-device-evidence.json` and `.zip`, and the dated report directory under
   `docs/device-results/`.
5. **Tag.** Push the annotated tag at the candidate. Tag CI verifies the tag and
   changelog, scans the tag's own history with the scanner policy it carries,
   and revalidates the device evidence. Its `candidate-ci` job then binds the tag
   to the passing run from step 2
   ([verify-candidate-ci.py](../scripts/verify-candidate-ci.py)) and keeps the
   `source-tag-validation` artifact. It does not rebuild or retest anything.
   Never move a pushed tag; a fix is a new version.
6. **GitHub release.** Download the record and assemble the assets:

   ```bash
   gh run download <tag-ci-run> --repo aimalygin/xray-rust --name source-tag-validation --dir stv
   python3 scripts/make-release-records.py --tag vX.Y.Z \
     --report-commit <main commit from step 4> \
     --report-dir docs/device-results/<YYYY-MM-DD-name> \
     --sdk-revision <measured SDK commit> --sdk-tree <its tree> \
     --source-tag-validation stv/source-tag-validation.json release-assets
   ```

   Releases are immutable. Create a draft with the notes, upload every file in
   `release-assets`, download them again and check them against `SHA256SUMS`,
   then publish.

## SDK

The [SDK release process](https://github.com/aimalygin/xray-rust-mobile/blob/main/docs/releasing.md)
has the details. In order:

1. Pin the core candidate commit (`XRAY_RUST_REF_KIND=commit`) for SDK CI and
   the device campaign.
2. After the core tag, switch `release/core.env` to the tag, then dispatch
   **Prepare release**. Actions may not open pull requests in that repository,
   so the job pushes the lock branch and prints a link; open the pull request
   from it and check that only `Package.swift` and `release/artifacts.env`
   changed.
3. Merge it and push the SDK tag. The release workflow publishes the GitHub
   release and GitHub Packages, then waits for the owner to approve the
   `maven-central` environment before publishing to Maven Central.
4. Resolve the published SwiftPM and Maven packages from clean consumers.

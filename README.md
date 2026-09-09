# v0.6.1-rc.1 release evidence

Exact measured core commit: `1231add417a4e2e6aa4c9e51c13487d493498a1d`. Tree: `2470643a54fd235425a7ce616ac41f22f32d673c`, clean. Candidate source: `codex/xhttp-h2-window-fix`, frozen as `codex/v0.6.1-rc.1`.

Archive: `v061-release-evidence.zip`; SHA-256 `575aed426aff5e40eaad2f75f0d07bd1127f0edd9e6f9f820dc8807e56b59a4b`. The nine-member archive passed `scripts/check-v06-release-evidence.sh` from the exact candidate. It contains the manifest, three sanitized artifacts for each physical device, and two performance artifacts.

- Full manual CI passed all 11 applicable jobs: https://github.com/aimalygin/xray-rust/actions/runs/34358510554
- Physical iPhone 13 / iOS 18.6.2: all five scenarios passed in 190 seconds; RSS growth 1,966,080 bytes; thread growth 0; fatal errors and unrecovered transitions 0.
- Physical Samsung SM-A145F / Android 15: all five scenarios passed in 260 seconds; 129 samples; RSS growth 4,304,896 bytes; thread growth 0; fatal errors and unrecovered transitions 0. Both FileDescriptor and PacketPump passed.
- Five samples per feature performance measurement passed the original calibrated thresholds. The separate v0.5 regression gate also passed on the same candidate.

The campaigns cover bounded local feature traffic, connect, cancellation and disconnect. They do not establish long soak, WAN throughput, sleep/wake, network switching or process-death behavior. Old v0.6.0 reports are not relabeled. Device profiles, private keys, serial identifiers and private application data are excluded.

This evidence commit is separate from the frozen runtime candidate. It does not itself create a release tag or publish SDK artifacts.

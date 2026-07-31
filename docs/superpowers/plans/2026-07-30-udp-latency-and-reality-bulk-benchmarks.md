# UDP Latency and REALITY Bulk Benchmarks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Chart the plain SOCKS-UDP relay path (`udp-freedom` as a third latency group) and bulk throughput through a full VLESS + REALITY + Vision tunnel (new `reality-vision-bulk-throughput` workload, new `reality-throughput` chart), then rerun all charted benchmarks and refresh the README.

**Architecture:** All code changes live in `crates/xray-bench` (spec: `docs/superpowers/specs/2026-07-30-udp-latency-and-reality-bulk-benchmarks-design.md`). The new workload is the existing `tcp-bulk-throughput` driver dispatched behind a new `WorkloadKind` variant whose engine configs and Xray-core REALITY server fixture are the ones `reality-vision-xudp` already uses. The chart module gains two `CHART_SLOTS` entries and one new chart built with the existing `optional_metric_group` machinery.

**Tech Stack:** Rust (tokio), `cargo test -p xray-bench`, Go toolchain (fixture auto-build from the `Xray-core/` checkout at v26.5.9), sing-box checkout at `/Users/antonmalygin/sing-box` (v1.13.15, auto-built with `with_utls`).

**Environment prerequisites (Tasks 2 and 5):** Go toolchain on PATH, network egress to `www.google.com` (REALITY cover origin), `ulimit -n` raised for the 1000-flow series.

---

### Task 1: Add the `reality-vision-bulk-throughput` workload variant and wire every match

Adding a `WorkloadKind` variant breaks every exhaustive match in `lib.rs`, so the variant and all its arms land in one commit. The workload reuses existing pieces end to end: `reality_vision_xudp_config` / `sing_box_reality_vision_xudp_config` client configs, the `start_xray_core_reality_vision_server` fixture, and the `run_tcp_bulk_throughput_workload` driver.

**Files:**
- Modify: `crates/xray-bench/src/lib.rs` (enum ~:140, `as_str`/`parse` ~:161-204, `supports_sing_box_process_engine` ~:216, `WorkloadFixture::start` ~:695, `xray_rust_config` ~:4085, `sing_box_config` ~:4123, `engine_config` ~:4146, `run_engine_once` dispatch ~:6425, tests module :6740+)

- [ ] **Step 1: Write the failing CLI parse test**

Add to the `mod tests` block in `crates/xray-bench/src/lib.rs`, right after `parses_compare_reality_vision_xudp` (ends ~:7227):

```rust
    #[test]
    fn parses_compare_reality_vision_bulk_throughput() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "reality-vision-bulk-throughput",
            "--connections",
            "1",
            "--iterations",
            "4",
            "--payload-size",
            "65536",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::RealityVisionBulkThroughput);
        assert_eq!(options.connections, 1);
        assert_eq!(options.iterations, 4);
        assert_eq!(options.payload_size, 65536);
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p xray-bench parses_compare_reality_vision_bulk_throughput`
Expected: compile error — `WorkloadKind::RealityVisionBulkThroughput` does not exist. (A compile failure is this step's "red".)

- [ ] **Step 3: Add the variant and name mappings**

In the `WorkloadKind` enum (after `RealityVisionXudp,` ~:157):

```rust
    RealityVisionXudp,
    RealityVisionBulkThroughput,
```

In `as_str` (after the `RealityVisionXudp` arm ~:178):

```rust
            Self::RealityVisionXudp => "reality-vision-xudp",
            Self::RealityVisionBulkThroughput => "reality-vision-bulk-throughput",
```

In `parse` (after the `reality-vision-xudp` arm ~:199):

```rust
            "reality-vision-xudp" => Ok(Self::RealityVisionXudp),
            "reality-vision-bulk-throughput" => Ok(Self::RealityVisionBulkThroughput),
```

In `supports_sing_box_process_engine` (~:216-228), extend the `matches!`:

```rust
            Self::Idle
                | Self::TcpFreedom
                | Self::TcpBulkThroughput
                | Self::ManyIdleFlows
                | Self::ReconnectBurst
                | Self::MixedLongLived
                | Self::UdpFreedom
                | Self::RealityVisionXudp
                | Self::RealityVisionBulkThroughput
```

- [ ] **Step 4: Wire the remaining exhaustive matches**

`cargo build -p xray-bench` now lists every non-exhaustive match. Fix each by joining the new variant to the existing `RealityVisionXudp` arm — same configs, same fixture:

`WorkloadFixture::start` (~:729): change the arm head

```rust
            WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulkThroughput => {
                let (vless_addr, process) =
                    start_xray_core_reality_vision_server(options, run_dir, binary_dir).await?;
```

`xray_rust_config` (~:4093): change the arm head

```rust
        WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulkThroughput => {
            reality_vision_xudp_config(port, SocketAddr::from((Ipv4Addr::LOCALHOST, 443)))
        }
```

`sing_box_config` (~:4129): change the arm head and generalize the error message

```rust
        WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulkThroughput => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "{} workload requires a VLESS Reality server fixture",
                    workload.as_str()
                ))
            })?;
            Ok(sing_box_reality_vision_xudp_config(port, vless_addr))
        }
```

`engine_config` (~:4184): change the arm head and generalize the error message

```rust
        WorkloadKind::RealityVisionXudp | WorkloadKind::RealityVisionBulkThroughput => {
            let vless_addr = fixture.vless_addr.ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "{} workload requires a VLESS Reality server fixture",
                    workload.as_str()
                ))
            })?;
            Ok(reality_vision_xudp_config(port, vless_addr))
        }
```

`run_engine_once` dispatch (~:6464): add after the `RealityVisionXudp` arm

```rust
            WorkloadKind::RealityVisionBulkThroughput => {
                run_tcp_bulk_throughput_workload(engine.socks_addr, options).await
            }
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test -p xray-bench parses_compare_reality_vision_bulk_throughput`
Expected: PASS (1 passed).

- [ ] **Step 6: Run the full crate test suite**

Run: `cargo test -p xray-bench`
Expected: all tests pass, no compile warnings about unreachable arms.

- [ ] **Step 7: Commit**

```bash
git add crates/xray-bench/src/lib.rs
git commit -m "$(cat <<'EOF'
Add reality-vision-bulk-throughput bench workload

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Smoke-run the new workload end to end

Proves the composed path (SOCKS CONNECT → VLESS+REALITY+Vision → Xray-core fixture → freedom → loopback source → validated bulk stream) actually completes before we invest in charts and a full run. Needs Go toolchain and egress to `www.google.com`.

**Files:** none (verification only).

- [ ] **Step 1: Run the workload against xray-rust with a small payload**

```bash
cargo run -p xray-bench -- run --engine xray-rust --workload reality-vision-bulk-throughput --xray-core-dir Xray-core --connections 1 --iterations 4 --payload-size 65536 --run-timeout-ms 60000
```

Expected: the command exits 0 and prints a summary line containing `status=ok` (harness output format), with nonzero `bytes_received`.

- [ ] **Step 2: Verify the summary on disk**

```bash
RUN_ID=$(ls -t target/benchmarks | head -1)
python3 -c "import json;s=json.load(open('target/benchmarks/$RUN_ID/xray-rust/reality-vision-bulk-throughput/summary.json'));print(s['status'],s['throughput_mbps'])"
```

Expected: `ok` and a non-null throughput object. If the run fails with a REALITY handshake error, check network egress to `www.google.com` and rerun; if the fixture fails to build, check the Go toolchain — both are environment issues, not code issues.

---

### Task 3: Chart slots, third latency group, and the `reality-throughput` chart

Test-first on the chart e2e test, then the implementation. Note two corrections to the spec discovered during planning (amended in Step 6): the latency group order is `tcp-freedom, udp-freedom, reality-vision-xudp` (direct paths before the tunneled one; the spec said "after reality-vision-xudp"), and no golden regeneration is needed — goldens only cover `render_bar_chart` via a fixed memory-rss fixture that this change does not touch.

**Files:**
- Modify: `crates/xray-bench/src/chart.rs` (`CHART_SLOTS` :464, `run_chart` charts vec :661-743, tests `write_full_group` :1022, e2e test :1081)
- Modify: `docs/superpowers/specs/2026-07-30-udp-latency-and-reality-bulk-benchmarks-design.md`

- [ ] **Step 1: Update the e2e test to expect the new charts (failing first)**

In `crates/xray-bench/src/chart.rs` tests:

`write_full_group` (:1022): change the slot array to 9 entries and extend the latency condition:

```rust
        let slots: [(&str, Option<u64>); 9] = [
            ("idle", None),
            ("many-idle-flows", Some(100)),
            ("many-idle-flows", Some(1000)),
            ("tcp-freedom", None),
            ("udp-freedom", None),
            ("reality-vision-xudp", None),
            ("tcp-bulk-throughput", None),
            ("reality-vision-bulk-throughput", None),
            ("routed-tcp-freedom", None),
        ];
```

and

```rust
                if matches!(
                    workload,
                    "tcp-freedom" | "udp-freedom" | "reality-vision-xudp"
                ) {
```

Rename `run_chart_writes_twelve_theme_files` (:1082) to `run_chart_writes_fourteen_theme_files` and add the new stem to its check list:

```rust
        for (stem, title_fragment) in [
            ("memory-rss", "Peak resident set size"),
            ("latency", "Round-trip latency"),
            ("throughput", "Bulk TCP throughput"),
            ("reality-throughput", "VLESS + REALITY + Vision"),
            ("cpu-per-gib", "CPU cost"),
            ("geo-setup-latency", "Time to SOCKS CONNECT reply"),
            ("geo-memory", "Routing memory"),
        ] {
```

At the end of the test, after the existing `throughput` assertion (:1116-1118), add:

```rust
        let latency = fs::read_to_string(out_dir.join("latency-light.svg")).unwrap();
        assert!(latency.contains("udp-freedom"));
        let reality = fs::read_to_string(out_dir.join("reality-throughput-light.svg")).unwrap();
        assert!(reality.contains(">4.30<"));
        assert!(reality.contains("reality-vision-bulk-throughput"));
```

- [ ] **Step 2: Run the chart tests to verify the new expectations fail**

Run: `cargo test -p xray-bench chart::`
Expected: `run_chart_writes_fourteen_theme_files` FAILS (no `reality-throughput-light.svg` is written yet). Other chart tests pass.

- [ ] **Step 3: Implement the chart changes**

`CHART_SLOTS` (:464):

```rust
const CHART_SLOTS: [(WorkloadKind, Option<u64>); 9] = [
    (WorkloadKind::Idle, None),
    (WorkloadKind::ManyIdleFlows, Some(100)),
    (WorkloadKind::ManyIdleFlows, Some(1000)),
    (WorkloadKind::TcpFreedom, None),
    (WorkloadKind::UdpFreedom, None),
    (WorkloadKind::RealityVisionXudp, None),
    (WorkloadKind::TcpBulkThroughput, None),
    (WorkloadKind::RealityVisionBulkThroughput, None),
    (WorkloadKind::RoutedTcpFreedom, None),
];
```

Latency chart groups (:690-693):

```rust
                groups: vec![
                    latency_group(&loaded, WorkloadKind::TcpFreedom, None)?,
                    latency_group(&loaded, WorkloadKind::UdpFreedom, None)?,
                    latency_group(&loaded, WorkloadKind::RealityVisionXudp, None)?,
                ],
```

New chart entry, inserted in the `charts` vec directly after the `"throughput"` entry (:710):

```rust
        (
            "reality-throughput",
            ChartSpec {
                title: "Bulk TCP throughput through VLESS + REALITY + Vision — Gbps (higher is better)"
                    .to_owned(),
                series_labels: &SERIES_LABELS_ALL,
                groups: vec![optional_metric_group(
                    &loaded,
                    WorkloadKind::RealityVisionBulkThroughput,
                    None,
                    "throughput",
                    |summary| summary.throughput_mbps.as_ref(),
                    1000.0,
                )?],
            },
        ),
```

- [ ] **Step 4: Run the chart tests to verify they pass**

Run: `cargo test -p xray-bench chart::`
Expected: all PASS, including `run_chart_writes_fourteen_theme_files`.

- [ ] **Step 5: Run the full crate suite**

Run: `cargo test -p xray-bench`
Expected: all PASS.

- [ ] **Step 6: Amend the spec with the two corrections**

In `docs/superpowers/specs/2026-07-30-udp-latency-and-reality-bulk-benchmarks-design.md`:
- In "UDP Latency Group", replace `after `reality-vision-xudp`` with `between `tcp-freedom` and `reality-vision-xudp` (direct paths grouped before the tunneled one)`.
- In "Testing", replace the bullet `Golden charts regenerated (`UPDATE_CHART_GOLDENS=1`); chart e2e/determinism tests extended for the new stem and the 3-group latency chart.` with `Goldens are untouched — they cover `render_bar_chart` via a fixed memory-rss fixture this change does not affect; the chart e2e test is extended for the new stem and the 3-group latency chart instead.`

- [ ] **Step 7: Commit**

```bash
git add crates/xray-bench/src/chart.rs docs/superpowers/specs/2026-07-30-udp-latency-and-reality-bulk-benchmarks-design.md
git commit -m "$(cat <<'EOF'
Chart udp-freedom latency and REALITY bulk throughput

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Document the new workload and chart set in docs/benchmarks.md

**Files:**
- Modify: `docs/benchmarks.md` (workload list :9-24, run examples :50-70, sing-box slice :149, compare recipes :160-169, publishing :233-266, metrics :289-332)

- [ ] **Step 1: Apply the documentation edits**

Workload list (after `- \`reality-vision-xudp\`` :24):

```markdown
- `reality-vision-bulk-throughput`
```

"Run xray-rust Only" block (after the `reality-vision-xudp` line :67):

```sh
cargo run --release -p xray-bench -- run --engine xray-rust --workload reality-vision-bulk-throughput --xray-core-dir Xray-core --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
```

sing-box slice sentence (:149): change the list `… \`udp-freedom\`, and \`reality-vision-xudp\`` to `… \`udp-freedom\`, \`reality-vision-xudp\`, and \`reality-vision-bulk-throughput\``.

Compare block (after the `reality-vision-xudp` compare line :168):

```sh
cargo run --release -p xray-bench -- compare --workload reality-vision-bulk-throughput --xray-core-dir Xray-core --sing-box-bin "$SING_BOX_BIN" --runs 5 --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
```

Publishing section (:233-241): replace the charted-series sentence so it reads:

```markdown
Run the same release-binary compare for each charted workload — `idle`,
`many-idle-flows` ×100 and ×1000 (the ×1000 run needs a raised `ulimit -n`;
see the workload note), `tcp-freedom`, `udp-freedom`, `reality-vision-xudp`,
`tcp-bulk-throughput`, `reality-vision-bulk-throughput`, and
`routed-tcp-freedom` (nine series in total; the last needs `--geodata-dir`
after fetching geodata with
`scripts/fetch-geodata.sh --output-dir /private/tmp/bench-geodata`, see
above). Each compare invocation writes one `target/benchmarks/<run-id>`
group; the `--group` flags passed to `chart` must jointly cover all nine
series.
```

Chart description (:256-261): update the read list and stem list so they read `… for \`idle\`, \`many-idle-flows\` (once per charted connection count), \`tcp-freedom\`, \`udp-freedom\`, \`reality-vision-xudp\`, \`tcp-bulk-throughput\`, \`reality-vision-bulk-throughput\` across all three engines, and \`routed-tcp-freedom\` across xray-rust and Xray-core only, and writes light/dark SVG pairs (\`memory-rss\`, \`latency\`, \`throughput\`, \`reality-throughput\`, \`cpu-per-gib\`, \`geo-setup-latency\`, \`geo-memory\`) to \`docs/benchmarks/media/\` (override with \`--out-dir\`).`

Metrics section — after the `tcp-bulk-throughput` paragraph (:290), add:

```markdown
`reality-vision-bulk-throughput` is `tcp-bulk-throughput` carried through
VLESS REALITY with `xtls-rprx-vision` (uTLS fingerprint `chrome`) to the same
Xray-core server fixture that `reality-vision-xudp` uses; the fixture's
`freedom` outbound dials back to the local source server. The fixture process
is not sampled, but it shares loopback CPU with the client engine, so
absolute numbers understate a dedicated-server setup. The bulk pattern is not
inner TLS, so Vision does not switch to direct copy: the stream stays
REALITY-encrypted end to end, and the chart measures the encrypted relay
path.
```

- [ ] **Step 2: Commit**

```bash
git add docs/benchmarks.md
git commit -m "$(cat <<'EOF'
Document udp-freedom chart slot and reality bulk workload

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Publication benchmark run and chart render

Release builds on all sides, nine compare series, then `chart`. Run on an idle machine (no other heavy processes). Each compare prints its run directory; the script below captures each run id.

**Files:** none modified by hand; `docs/benchmarks/media/*.svg` regenerated by `chart`.

The sweep is 9 series across 11 run groups: the `many-idle-flows` ×1000
series runs as three single-engine groups with a TIME_WAIT drain between
them, because one three-engine `compare` invocation exhausts the ephemeral
port range at that connection count. Every other series runs as one
three-engine `compare` group.

- [ ] **Step 1: Prepare binaries and geodata**

```bash
ulimit -n 10240
cargo build --release -p xray-cli --bin xray-rust
git -C /Users/antonmalygin/sing-box describe --tags   # expect v1.13.15
scripts/fetch-geodata.sh --output-dir /private/tmp/bench-geodata
```

Expected: release binary at `target/release/xray-rust`; sing-box tag confirmed (if it moved, note the new tag for the chart footer); geodata script prints the pinned geosite/geoip tags — record them for `--geodata-version`.

- [ ] **Step 2: Run the nine compare series**

```bash
set -e
XRB=target/release/xray-rust
SBD=/Users/antonmalygin/sing-box
run_id() { ls -t target/benchmarks | head -1; }

cargo run --release -p xray-bench -- compare --workload idle --xray-rust-bin $XRB --xray-core-dir Xray-core --sing-box-dir $SBD --runs 5 --duration-ms 1000
G_IDLE=$(run_id)
cargo run --release -p xray-bench -- compare --workload many-idle-flows --xray-rust-bin $XRB --xray-core-dir Xray-core --sing-box-dir $SBD --runs 5 --connections 100 --duration-ms 1000
G_MIF100=$(run_id)
cargo run --release -p xray-bench -- compare --workload many-idle-flows --xray-rust-bin $XRB --xray-core-dir Xray-core --sing-box-dir $SBD --runs 5 --connections 1000 --duration-ms 1000
G_MIF1000=$(run_id)
cargo run --release -p xray-bench -- compare --workload tcp-freedom --xray-rust-bin $XRB --xray-core-dir Xray-core --sing-box-dir $SBD --runs 5 --connections 1 --iterations 1000 --payload-size 1024
G_TCP=$(run_id)
cargo run --release -p xray-bench -- compare --workload udp-freedom --xray-rust-bin $XRB --xray-core-dir Xray-core --sing-box-dir $SBD --runs 5 --connections 1 --iterations 1000 --payload-size 512
G_UDP=$(run_id)
cargo run --release -p xray-bench -- compare --workload reality-vision-xudp --xray-rust-bin $XRB --xray-core-dir Xray-core --sing-box-dir $SBD --runs 5 --connections 1 --iterations 1000 --payload-size 512
G_RVX=$(run_id)
cargo run --release -p xray-bench -- compare --workload tcp-bulk-throughput --xray-rust-bin $XRB --xray-core-dir Xray-core --sing-box-dir $SBD --runs 5 --connections 1 --iterations 2048 --payload-size 4194304 --run-timeout-ms 300000
G_BULK=$(run_id)
cargo run --release -p xray-bench -- compare --workload reality-vision-bulk-throughput --xray-rust-bin $XRB --xray-core-dir Xray-core --sing-box-dir $SBD --runs 5 --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
G_RBULK=$(run_id)
cargo run --release -p xray-bench -- compare --workload routed-tcp-freedom --xray-rust-bin $XRB --xray-core-dir Xray-core --geodata-dir /private/tmp/bench-geodata --runs 5 --connections 8 --iterations 100 --payload-size 1024 --run-timeout-ms 120000
G_GEO=$(run_id)
echo "$G_IDLE $G_MIF100 $G_MIF1000 $G_TCP $G_UDP $G_RVX $G_BULK $G_RBULK $G_GEO"
```

Expected: every compare finishes without error. The env vars don't survive the shell, so keep the echoed run-id list.

- [ ] **Step 3: Verify all summaries are ok before charting**

```bash
for g in <the nine run ids>; do
  for f in target/benchmarks/$g/*/*/summary.json; do
    python3 -c "import json,sys;s=json.load(open('$f'));print(s['status'],'$f')"
  done
done
```

Expected: every line starts with `ok`. A non-ok summary means rerunning that series, not proceeding.

- [ ] **Step 4: Render the charts**

```bash
cargo run --release -p xray-bench -- chart \
  --group target/benchmarks/<G_IDLE> --group target/benchmarks/<G_MIF100> \
  --group target/benchmarks/<G_MIF1000> --group target/benchmarks/<G_TCP> \
  --group target/benchmarks/<G_UDP> --group target/benchmarks/<G_RVX> \
  --group target/benchmarks/<G_BULK> --group target/benchmarks/<G_RBULK> \
  --group target/benchmarks/<G_GEO> \
  --date <today YYYY-MM-DD> \
  --hardware "Apple M3 Pro, 18 GB RAM, macOS 26.5.2" \
  --xray-rust-version $(git rev-parse --short HEAD) \
  --xray-core-version v26.5.9 \
  --sing-box-version v1.13.15 \
  --geodata-version "geosite-<tag> geoip-<tag>"
```

Expected: `wrote docs/benchmarks/media/<stem>-{light,dark}.svg` for seven stems (14 files), including the new `reality-throughput` pair. Substitute the geodata tags recorded in Step 1 and verify the hardware string still matches this machine (`sw_vers`).

---

### Task 6: Refresh the README and commit the published charts

**Files:**
- Modify: `README.md` (:25-73)
- Commit: `docs/benchmarks/media/*.svg`

- [ ] **Step 1: Extract the published numbers**

For each charted series, pull the values the alt texts need (medians; chart bars are medians of per-run values):

```bash
for e in xray-rust xray-core sing-box; do
  python3 -c "import json;s=json.load(open('target/benchmarks/<G_UDP>/$e/udp-freedom/summary.json'));print('$e', s['latency_us']['median']['median'])"
  python3 -c "import json;s=json.load(open('target/benchmarks/<G_RBULK>/$e/reality-vision-bulk-throughput/summary.json'));print('$e', s['throughput_mbps']['median'])"
done
```

Also re-extract the values for the five existing chart alt texts from their new run groups (same paths as the current alt texts: `peak_rss_kib` for memory groups, `latency_us` for tcp-freedom/reality-vision-xudp, `throughput_mbps` and `cpu_millis_per_gib` for bulk, `peak_rss_kib` for routed-tcp-freedom) — every number in the README changes with the rerun, not only the new ones.

- [ ] **Step 2: Update README.md**

- Header paragraph (:27-44): update the measured date, xray-rust rev, and — if the rerun changed the story — the comparative prose. Add one sentence describing the two new results, e.g. after the bulk-throughput sentence: `On the plain SOCKS-UDP relay it <compares how> on round-trip latency, and through a full VLESS + REALITY + Vision tunnel it moves <N> Gbps against Xray-core's <N> and sing-box's <N>.` (fill from Step 1 values; adjust the verbs to what the numbers show — do not overclaim).
- Latency picture alt text (:53): add the `udp-freedom` group values in chart order (tcp-freedom, udp-freedom, reality-vision-xudp).
- New picture block directly after the throughput block (:56-59):

```html
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/reality-throughput-dark.svg">
  <img alt="Bulk TCP throughput through a VLESS + REALITY + Vision tunnel, higher is better: xray-rust <N> Gbps, Xray-core <N>, sing-box <N>." src="docs/benchmarks/media/reality-throughput-light.svg">
</picture>
```

- Refresh the numbers in all five existing alt texts from the new run.

- [ ] **Step 3: Verify the README renders and numbers match**

Run: `git diff README.md` and cross-check each alt-text number against the Step 1 extractions. Confirm all 14 SVGs changed: `git status docs/benchmarks/media` shows 12 modified + 2 new files.

- [ ] **Step 4: Commit**

```bash
git add README.md docs/benchmarks/media
git commit -m "$(cat <<'EOF'
Publish UDP latency and REALITY bulk throughput charts

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
EOF
)"
```

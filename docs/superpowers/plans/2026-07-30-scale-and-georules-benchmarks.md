# Scale and Geo-Rules Benchmarks Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist workload parameters in benchmark results, chart `many-idle-flows` at 100 and 1000 connections, add a `routed-tcp-freedom` workload that exercises real geosite/geoip routing rules (xray-rust vs Xray-core), and publish two new README charts (routing setup latency, routing memory).

**Architecture:** All code in `crates/xray-bench` (`src/lib.rs` + `src/chart.rs`); the production runtime is untouched. The geo workload clones the `tcp-freedom` pattern with SOCKS5 domain CONNECT (ATYP=3); generated configs carry real rule lists; geodata files are an explicit `--geodata-dir` input staged into the run dir for xray-rust (config-parent search) and passed via `XRAY_LOCATION_ASSET` for Xray-core. Charts gain summary selection by connection count and per-chart series labels.

**Tech Stack:** Rust, existing workspace deps only (tokio, serde, serde_json, xray-config for a fixture-validation test). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-07-30-scale-and-georules-benchmarks-design.md`

**Grounding facts (verified against HEAD `203b72a` and Xray-core v26.5.9; do not re-derive):**
- xray-rust freedom `settings` accepts NO fields (`{}` only); its freedom dial always resolves domains through the config DNS layer, hosts-first. Xray-core freedom needs `"domainStrategy": "UseIP"` to use its dns app (hosts checked first) instead of the OS resolver. Configs are therefore per-engine.
- xray-rust locates `geosite.dat`/`geoip.dat` relative to the config file's parent dir (plus cwd); no env var. Xray-core accepts `XRAY_LOCATION_ASSET=<dir>`.
- xray-rust rules require `"type": "field"`; Xray-core tolerates it (non-strict default). Rule keys shared by both: `type`, `domain`, `ip`, `outboundTag`.
- xray-rust hosts key without prefix is a KEYWORD matcher; Xray-core's default is FULL. Always use explicit `full:` prefixes in hosts keys.
- `geoip:private` in xray-rust never reads geoip.dat (hardcoded ranges); Xray-core requires code `PRIVATE` present in the file. With routing `domainStrategy` AsIs (both engines), `ip` rules never match a domain CONNECT — they add rule-walk cost without changing the route.
- Referenced geosite/geoip codes missing from the `.dat` are hard startup errors in BOTH engines. Codes inside `.dat` files must be UPPERCASE. Xray-core's streaming reader additionally requires each entry body to START with the code field (`0x0A len CODE`).
- xray-rust domain-matcher budget is 250k per config; the rule set below (`category-ads-all` + `cn` + 2 geoip rules) stays under it. Do NOT add `geosite:geolocation-!cn` — it can blow the budget.
- `.dat` container framing: per entry `0x0A`, varint(body_len), body. `GeoSite` body: field1 code (string), field2 repeated GeoDomain. `GeoDomain`: field1 varint type (0=Substr,1=Regex,2=Domain/suffix,3=Full), field2 value. `GeoIp`: field1 code, field2 repeated GeoCidr (field1 bytes ip 4/16, field2 varint prefix), field3 bool reverse.
- Reference line anchors (drift expected; search for quoted text): `socks5_connect_measured` lib.rs:2529; `BenchResult` :398; `BenchSummary` :469; `summarize_results` :1311; result assembly in `run_engine_once` :6129; `WorkloadKind` :140; `engine_config` :3855ish; `start_engine` :4740ish; chart.rs 976 lines.
- LINT GATE: workspace has `-D warnings`; run `cargo clippy -p xray-bench --all-targets` before every commit.

**Conventions:** tests in the existing `mod tests` blocks; error style `BenchError::Io { action, source }` / `InvalidArguments`; commits sentence-case ending with `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`; `cargo fmt --all` before each commit.

**Spec deviation (controller-approved):** the synthetic geodata fixture is generated at test runtime by a helper (no binary blobs committed under testdata/) — supersedes the spec's "committed under testdata/geodata/" sentence.

---

### Task 1: Persist workload parameters in results

**Files:**
- Modify: `crates/xray-bench/src/lib.rs` — `BenchResult`, `BenchSummary`, result assembly in `run_engine_once`, `summarize_results`, tests

- [ ] **Step 1: Write the failing tests**

Add to `mod tests`:

```rust
    #[test]
    fn deserializes_summary_json_without_params_fields() {
        let raw = r#"{
            "engine": "xray-rust",
            "workload": "tcp-freedom",
            "status": "ok",
            "runs": 1,
            "duration_ms": { "min": 1, "median": 1, "p95": 1 },
            "peak_rss_kib": { "min": 1, "median": 1, "p95": 1 },
            "cpu_millis": { "min": 1, "median": 1, "p95": 1 },
            "cpu_millis_per_gib": null,
            "latency_us": null,
            "setup_us": null,
            "bytes_sent": { "min": 1, "median": 1, "p95": 1 },
            "bytes_received": { "min": 1, "median": 1, "p95": 1 },
            "results": []
        }"#;
        let summary: BenchSummary = serde_json::from_str(raw).unwrap();
        assert_eq!(summary.connections, 0);
        assert_eq!(summary.iterations, 0);
        assert_eq!(summary.payload_size, 0);
    }

    #[test]
    fn summarize_rejects_mixed_workload_parameters() {
        let mut first = BenchResult {
            engine: "xray-rust".to_owned(),
            workload: "tcp-freedom".to_owned(),
            status: "ok".to_owned(),
            duration_ms: 10,
            bytes_sent: 0,
            bytes_received: 0,
            peak_rss_kib: 1000,
            cpu_millis: 5,
            cpu_millis_per_gib: None,
            throughput_mbps: None,
            connections: 100,
            iterations: 1,
            payload_size: 512,
            latency_us: None,
            setup_us: None,
            samples: 2,
            blackhole_connections_accepted: None,
            blackhole_connections_active: None,
        };
        let mut second = first.clone();
        second.connections = 1000;
        let error = summarize_results(&[first.clone(), second]).unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot summarize mixed workload parameters"));

        first.connections = 100;
        let same = summarize_results(&[first.clone(), first.clone()]).unwrap();
        assert_eq!(same.connections, 100);
        assert_eq!(same.payload_size, 512);
    }
```

Also extend the existing `deserializes_result_json_without_throughput_field` test with one assertion after the existing one:

```rust
        assert_eq!(result.connections, 0);
```

And extend `summarizes_repeated_results_with_min_median_and_p95`: add to each of its three `BenchResult` literals (right after `throughput_mbps`):

```rust
                connections: 1,
                iterations: 10,
                payload_size: 4096,
```

and one assertion next to the engine/workload asserts:

```rust
        assert_eq!(summary.connections, 1);
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p xray-bench --lib params 2>&1 | tail -10`
Expected: compile errors — no `connections` field.

- [ ] **Step 3: Implement**

(a) `BenchResult` — after `pub throughput_mbps: Option<u128>,`:
```rust
    #[serde(default)]
    pub connections: u64,
    #[serde(default)]
    pub iterations: u64,
    #[serde(default)]
    pub payload_size: u64,
```

(b) `BenchSummary` — after `pub throughput_mbps: Option<MetricSummary>,`:
```rust
    #[serde(default)]
    pub connections: u64,
    #[serde(default)]
    pub iterations: u64,
    #[serde(default)]
    pub payload_size: u64,
```

(c) `run_engine_once` result assembly — in the `BenchResult` literal, after `throughput_mbps,`:
```rust
        connections: options.connections as u64,
        iterations: options.iterations as u64,
        payload_size: options.payload_size as u64,
```

(d) `summarize_results` — after the existing mixed-engine/workload check, add:
```rust
    if results.iter().any(|result| {
        result.connections != first.connections
            || result.iterations != first.iterations
            || result.payload_size != first.payload_size
    }) {
        return Err(BenchError::InvalidArguments(
            "cannot summarize mixed workload parameters".to_owned(),
        ));
    }
```
and in the `BenchSummary` literal, after `throughput_mbps: ...`:
```rust
        connections: first.connections,
        iterations: first.iterations,
        payload_size: first.payload_size,
```

(e) chart.rs `test_summary` helper — add to its `BenchSummary` literal (after `throughput_mbps`):
```rust
            connections: 0,
            iterations: 0,
            payload_size: 0,
```
(Compiler enforces this; Task 2 makes the values meaningful.)

- [ ] **Step 4: Verify**

Run: `cargo test -p xray-bench --lib 2>&1 | tail -3` — expect 78 passed (76 + 2 new), 0 failed.
Run: `cargo clippy -p xray-bench --all-targets 2>&1 | tail -3` — clean.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/xray-bench/src/lib.rs crates/xray-bench/src/chart.rs
git commit -m "Persist workload parameters in benchmark results

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 2: Chart selection by connection count and the 1000-flow memory group

**Files:**
- Modify: `crates/xray-bench/src/chart.rs`

- [ ] **Step 1: Write the failing tests**

In chart.rs `mod tests`, first make `test_summary` parameterizable: change its signature to

```rust
    fn test_summary_with(
        engine: &str,
        workload: &str,
        status: &str,
        connections: u64,
    ) -> BenchSummary {
```
setting `connections: connections` in the literal (iterations/payload stay 0), and re-add the old arity as a wrapper:
```rust
    fn test_summary(engine: &str, workload: &str, status: &str) -> BenchSummary {
        test_summary_with(engine, workload, status, 0)
    }
```

Then add tests:

```rust
    #[test]
    fn load_summary_selects_by_connection_count() {
        let root = temp_root("by-conn");
        let dir_100 = root.join("g100/xray-rust/many-idle-flows");
        let dir_1000 = root.join("g1000/xray-rust/many-idle-flows");
        fs::create_dir_all(&dir_100).unwrap();
        fs::create_dir_all(&dir_1000).unwrap();
        write_summary_json(
            &dir_100.join("summary.json"),
            &test_summary_with("xray-rust", "many-idle-flows", "ok", 100),
        )
        .unwrap();
        write_summary_json(
            &dir_1000.join("summary.json"),
            &test_summary_with("xray-rust", "many-idle-flows", "ok", 1000),
        )
        .unwrap();
        let groups = vec![root.join("g100"), root.join("g1000")];

        let summary = load_summary(
            &groups,
            EngineKind::XrayRust,
            WorkloadKind::ManyIdleFlows,
            Some(1000),
        )
        .unwrap();
        assert_eq!(summary.connections, 1000);

        let error = load_summary(
            &groups,
            EngineKind::XrayRust,
            WorkloadKind::ManyIdleFlows,
            Some(500),
        )
        .unwrap_err();
        assert!(error.to_string().contains("connections=500"));
        fs::remove_dir_all(&root).unwrap();
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p xray-bench --lib chart 2>&1 | tail -8`
Expected: compile error — `load_summary` takes 3 arguments.

- [ ] **Step 3: Implement**

(a) `load_summary` new signature and body (replace the found/dedup section; keep error prefixes intact):

```rust
fn load_summary(
    groups: &[PathBuf],
    engine: EngineKind,
    workload: WorkloadKind,
    connections: Option<u64>,
) -> Result<BenchSummary, BenchError> {
    let mut candidates = Vec::new();
    for group in groups {
        let candidate = group
            .join(engine.as_str())
            .join(workload.as_str())
            .join("summary.json");
        if !candidate.exists() {
            continue;
        }
        let data = fs::read_to_string(&candidate).map_err(|source| BenchError::Io {
            action: format!("reading benchmark summary `{}`", candidate.display()),
            source,
        })?;
        let summary: BenchSummary = serde_json::from_str(&data).map_err(|error| {
            BenchError::InvalidArguments(format!(
                "failed to parse summary `{}`: {error}",
                candidate.display()
            ))
        })?;
        if let Some(required) = connections {
            if summary.connections != required {
                continue;
            }
        }
        candidates.push((candidate, summary));
    }
    let filter_note = match connections {
        Some(required) => format!(" with connections={required}"),
        None => String::new(),
    };
    let (path, summary) = match candidates.len() {
        0 => {
            return Err(BenchError::InvalidArguments(format!(
                "missing summary for {} {}{filter_note}: no --group directory contains a matching {}/{}/summary.json",
                engine.as_str(),
                workload.as_str(),
                engine.as_str(),
                workload.as_str()
            )))
        }
        1 => candidates.remove(0),
        many => {
            return Err(BenchError::InvalidArguments(format!(
                "summary for {} {}{filter_note} found in {} group directories ({}); pass each run group once",
                engine.as_str(),
                workload.as_str(),
                many,
                candidates
                    .iter()
                    .map(|(path, _)| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    };
    if summary.status != "ok" {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` has status `{}`; charts require status `ok`",
            path.display(),
            summary.status
        )));
    }
    Ok(summary)
}
```

(b) Update all existing `load_summary` callers/tests to pass `None` as the 4th argument (`load_summary_reads_single_group`, `load_summary_rejects_missing_and_non_ok`, `load_summary_rejects_duplicate_groups`, and `run_chart`'s load loop — the loop is restructured next).

(c) Keyed loading. Replace `CHART_WORKLOADS` with:
```rust
const CHART_SLOTS: [(WorkloadKind, Option<u64>); 6] = [
    (WorkloadKind::Idle, None),
    (WorkloadKind::ManyIdleFlows, Some(100)),
    (WorkloadKind::ManyIdleFlows, Some(1000)),
    (WorkloadKind::TcpFreedom, None),
    (WorkloadKind::RealityVisionXudp, None),
    (WorkloadKind::TcpBulkThroughput, None),
];
```
`LoadedSummaries.entries` becomes `Vec<((EngineKind, WorkloadKind, Option<u64>), BenchSummary)>`; `get` takes `(engine, workload, connections: Option<u64>)` and matches all three. `run_chart`'s load loop iterates `CHART_SLOTS` × `ENGINES`.

(d) `rss_group` gains a label and slot:
```rust
fn rss_group(
    loaded: &LoadedSummaries,
    workload: WorkloadKind,
    connections: Option<u64>,
    label: &str,
) -> BarGroup {
    BarGroup {
        label: label.to_owned(),
        bars: ENGINES
            .iter()
            .enumerate()
            .map(|(series, engine)| {
                metric_bar(
                    &loaded.get(*engine, workload, connections).peak_rss_kib,
                    series,
                    1024.0,
                )
            })
            .collect(),
    }
}
```
memory-rss chart groups become:
```rust
                groups: vec![
                    rss_group(&loaded, WorkloadKind::Idle, None, "idle"),
                    rss_group(&loaded, WorkloadKind::ManyIdleFlows, Some(100), "many-idle-flows ×100"),
                    rss_group(&loaded, WorkloadKind::ManyIdleFlows, Some(1000), "many-idle-flows ×1000"),
                ],
```
`latency_group` and `optional_metric_group` get the same `connections: Option<u64>` pass-through parameter (pass `None` at their call sites), so `get` calls type-check.

(e) e2e fixtures: `write_full_group` writes `many-idle-flows` TWICE into two subgroup dirs — restructure the test to write per-workload groups the way `run_chart_writes_eight_theme_files` builds its group list. Concretely: change `write_full_group(root)` to create `root/g-<workload>[-<conn>]/<engine>/<workload>/summary.json` for slots `[("idle",0), ("many-idle-flows",100), ("many-idle-flows",1000), ("tcp-freedom",0), ("reality-vision-xudp",0), ("tcp-bulk-throughput",0)]` (0 means write connections=0 and chart slot uses the given Some/None mapping — write 0 only for slots charted with `None`), returning `Vec<PathBuf>` of group dirs; the e2e test passes ALL groups via `options.groups = write_full_group(&root);`. The memory-rss content assertion gains `assert!(svg.contains("many-idle-flows ×1000"));`.

- [ ] **Step 4: Verify**

Run: `cargo test -p xray-bench --lib 2>&1 | tail -3` — expect 79 passed.
Run: `cargo clippy -p xray-bench --all-targets 2>&1 | tail -3` — clean.
Renderer goldens must be untouched: `git status --short crates/xray-bench/testdata/` — empty.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/xray-bench/src/chart.rs
git commit -m "Select chart summaries by connection count and add 1000-flow memory group

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: SOCKS5 domain CONNECT in the harness client

**Files:**
- Modify: `crates/xray-bench/src/lib.rs` — next to `socks5_connect_measured`, tests

- [ ] **Step 1: Write the failing tests**

```rust
    #[tokio::test]
    async fn socks5_domain_connect_encodes_atyp3_request() {
        let (mut server, mut client_io) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            server.write_all(&[5, 0]).await.unwrap();
            let mut head = [0; 5];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head[..4], [5, 1, 0, 3]);
            let len = head[4] as usize;
            let mut domain = vec![0; len + 2];
            server.read_exact(&mut domain).await.unwrap();
            assert_eq!(&domain[..len], b"bench-miss.invalid");
            assert_eq!(&domain[len..], &9999u16.to_be_bytes());
            server.write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0]).await.unwrap();
        });

        let sample = socks5_connect_domain_measured(&mut client_io, "bench-miss.invalid", 9999)
            .await
            .unwrap();
        assert!(sample.total_us >= sample.connect_us);
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_reply_parser_accepts_domain_bound_address() {
        let (mut server, mut client_io) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut greeting = [0; 3];
            server.read_exact(&mut greeting).await.unwrap();
            server.write_all(&[5, 0]).await.unwrap();
            let mut head = [0; 5];
            server.read_exact(&mut head).await.unwrap();
            let len = head[4] as usize;
            let mut rest = vec![0; len + 2];
            server.read_exact(&mut rest).await.unwrap();
            let mut reply = vec![5, 0, 0, 3, 4];
            reply.extend_from_slice(b"echo");
            reply.extend_from_slice(&80u16.to_be_bytes());
            server.write_all(&reply).await.unwrap();
        });

        socks5_connect_domain_measured(&mut client_io, "x.example", 80)
            .await
            .unwrap();
        server_task.await.unwrap();
    }
```

Note: these drive a `DuplexStream`, so the new functions must be generic over `AsyncRead + AsyncWrite + Unpin` (unlike the existing `&mut TcpStream` helpers).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p xray-bench --lib socks5_domain 2>&1 | tail -8`
Expected: compile error — function not found.

- [ ] **Step 3: Implement**

Add next to `socks5_connect_measured`:

```rust
async fn socks5_connect_domain_measured<S>(
    client: &mut S,
    domain: &str,
    port: u16,
) -> Result<SocksSetupStageSample, BenchError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if domain.len() > 255 {
        return Err(BenchError::InvalidArguments(
            "SOCKS domain target exceeds 255 bytes".to_owned(),
        ));
    }
    let started = Instant::now();
    let method_started = Instant::now();
    client
        .write_all(&[5, 1, 0])
        .await
        .map_err(|source| BenchError::Io {
            action: "writing SOCKS greeting".to_owned(),
            source,
        })?;
    let mut method = [0; 2];
    client
        .read_exact(&mut method)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading SOCKS method".to_owned(),
            source,
        })?;
    if method != [5, 0] {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected SOCKS method response {method:?}"
        )));
    }
    let method_us = method_started.elapsed().as_micros();

    let mut request = vec![5, 1, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    let connect_started = Instant::now();
    client
        .write_all(&request)
        .await
        .map_err(|source| BenchError::Io {
            action: "writing SOCKS connect".to_owned(),
            source,
        })?;
    read_socks5_reply(client).await?;
    let connect_us = connect_started.elapsed().as_micros();

    Ok(SocksSetupStageSample {
        method_us,
        connect_us,
        total_us: started.elapsed().as_micros(),
    })
}

async fn read_socks5_reply<S>(client: &mut S) -> Result<(), BenchError>
where
    S: AsyncRead + Unpin,
{
    let mut head = [0; 4];
    client
        .read_exact(&mut head)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading SOCKS connect response".to_owned(),
            source,
        })?;
    if head[..2] != [5, 0] {
        return Err(BenchError::InvalidArguments(format!(
            "unexpected SOCKS connect response {head:?}"
        )));
    }
    let addr_len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut len = [0; 1];
            client
                .read_exact(&mut len)
                .await
                .map_err(|source| BenchError::Io {
                    action: "reading SOCKS reply domain length".to_owned(),
                    source,
                })?;
            len[0] as usize
        }
        other => {
            return Err(BenchError::InvalidArguments(format!(
                "unsupported SOCKS reply address type {other}"
            )));
        }
    };
    let mut rest = vec![0; addr_len + 2];
    client
        .read_exact(&mut rest)
        .await
        .map_err(|source| BenchError::Io {
            action: "reading SOCKS reply address".to_owned(),
            source,
        })?;
    Ok(())
}
```

Do NOT change the existing IPv4 `socks5_connect_measured` (its fixed 10-byte read stays; all its callers and tests are untouched).

- [ ] **Step 4: Verify**

Run: `cargo test -p xray-bench --lib 2>&1 | tail -3` — expect 81 passed.
Clippy clean. Note: the two new fns are unused by production code until Task 6 — if the non-test build fails `-D warnings`, add per-item `#[allow(dead_code)]` with comment `// wired into routed-tcp-freedom in a follow-up task` and report it for Task 6 removal.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/xray-bench/src/lib.rs
git commit -m "Add SOCKS5 domain CONNECT client helper

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: Synthetic geodata fixture writer (test helper)

**Files:**
- Modify: `crates/xray-bench/src/lib.rs` — `mod tests` only

- [ ] **Step 1: Write the helper and its tests together** (the helper is test-only code; its test is the fixture validity check through the real config parser)

Add inside `mod tests`:

```rust
    fn geo_encode_varint(mut value: u64, out: &mut Vec<u8>) {
        while value >= 0x80 {
            out.push(value as u8 | 0x80);
            value >>= 7;
        }
        out.push(value as u8);
    }

    fn geo_field_bytes(field: u8, payload: &[u8], out: &mut Vec<u8>) {
        out.push((field << 3) | 2);
        geo_encode_varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    fn geo_domain_body(domain_type: u8, value: &str) -> Vec<u8> {
        let mut body = vec![0x08, domain_type];
        geo_field_bytes(2, value.as_bytes(), &mut body);
        body
    }

    // Code MUST be the first field: Xray-core's streaming reader requires it.
    fn geo_site_body(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        geo_field_bytes(1, code.as_bytes(), &mut body);
        for domain in domains {
            geo_field_bytes(2, domain, &mut body);
        }
        body
    }

    fn geo_cidr_body(ip: &[u8], prefix: u8) -> Vec<u8> {
        let mut body = Vec::new();
        geo_field_bytes(1, ip, &mut body);
        body.push(0x10);
        geo_encode_varint(u64::from(prefix), &mut body);
        body
    }

    fn geo_ip_body(code: &str, cidrs: &[Vec<u8>]) -> Vec<u8> {
        let mut body = Vec::new();
        geo_field_bytes(1, code.as_bytes(), &mut body);
        for cidr in cidrs {
            geo_field_bytes(2, cidr, &mut body);
        }
        body
    }

    fn geo_entry_file(bodies: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for body in bodies {
            bytes.push(0x0A);
            geo_encode_varint(body.len() as u64, &mut bytes);
            bytes.extend_from_slice(body);
        }
        bytes
    }

    fn write_geo_fixture(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        let geosite = geo_entry_file(&[
            geo_site_body(
                "CATEGORY-ADS-ALL",
                &[geo_domain_body(2, "ads-bench.example")],
            ),
            geo_site_body("CN", &[geo_domain_body(2, "baidu.com")]),
        ]);
        std::fs::write(dir.join("geosite.dat"), geosite).unwrap();
        let geoip = geo_entry_file(&[
            geo_ip_body("CN", &[geo_cidr_body(&[114, 114, 114, 0], 24)]),
            geo_ip_body(
                "PRIVATE",
                &[
                    geo_cidr_body(&[10, 0, 0, 0], 8),
                    geo_cidr_body(&[127, 0, 0, 0], 8),
                ],
            ),
        ]);
        std::fs::write(dir.join("geoip.dat"), geoip).unwrap();
    }

    #[test]
    fn geo_fixture_parses_through_real_config_parser() {
        let dir = std::env::temp_dir().join(format!(
            "xray-bench-geo-fixture-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_geo_fixture(&dir);
        let config = routed_freedom_config(18099, EngineKind::XrayRust);
        let parsed = xray_config::parse_xray_json_with_geodata_dir(&config, &dir);
        assert!(
            parsed.is_ok(),
            "generated geo config must parse with the synthetic fixture: {:?}",
            parsed.err()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
```

The final test references `routed_freedom_config` from Task 5 — implement Tasks 4 and 5 in one working session, committing Task 4's helpers together with Task 5 (single commit at the end of Task 5). If `xray_config::parse_xray_json_with_geodata_dir` is not the exact public name, check `crates/xray-config/src/parser.rs` exports (`parse_xray_json_with_geodata_dir<P: AsRef<Path>>(raw, dir)` exists at parser.rs:118) and confirm the return type's `is_ok()` usage (it returns `Result<ParsedConfig, ConfigParseError>`).

- [ ] **Step 2: proceed to Task 5** (no separate commit; the fixture test goes green at Task 5 Step 4)

---

### Task 5: `routed-tcp-freedom` workload plumbing

**Files:**
- Modify: `crates/xray-bench/src/lib.rs` — WorkloadKind sites, `BenchOptions` + CLI, config generation, `engine_config`/`xray_rust_config`, `start_engine` geodata staging, temp dispatcher arm, tests
- Modify: `crates/xray-bench/Cargo.toml` — nothing (xray-config already a dependency)

- [ ] **Step 1: Write the failing tests**

```rust
    #[test]
    fn parses_compare_routed_tcp_freedom_with_geodata_dir() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "routed-tcp-freedom",
            "--connections",
            "4",
            "--iterations",
            "50",
            "--payload-size",
            "1024",
            "--geodata-dir",
            "/tmp/geodata",
        ])
        .unwrap();
        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::RoutedTcpFreedom);
        assert_eq!(options.geodata_dir, Some(PathBuf::from("/tmp/geodata")));
    }

    #[test]
    fn routed_config_carries_rules_hosts_and_engine_specific_freedom() {
        let rust_config = routed_freedom_config(18100, EngineKind::XrayRust);
        let value = serde_json::from_str::<serde_json::Value>(&rust_config).unwrap();
        assert_eq!(value["routing"]["rules"].as_array().unwrap().len(), 4);
        assert_eq!(
            value["routing"]["rules"][0]["domain"][0],
            "geosite:category-ads-all"
        );
        assert_eq!(value["routing"]["rules"][3]["domain"][0], "geosite:cn");
        assert!(value["dns"]["hosts"]["full:baidu.com"].is_string());
        assert!(value["dns"]["hosts"]["full:bench-miss.invalid"].is_string());
        assert_eq!(value["outbounds"][0]["tag"], "direct");
        assert_eq!(value["outbounds"][0]["settings"], serde_json::json!({}));

        let core_config = routed_freedom_config(18100, EngineKind::XrayCore);
        let value = serde_json::from_str::<serde_json::Value>(&core_config).unwrap();
        assert_eq!(
            value["outbounds"][0]["settings"]["domainStrategy"],
            "UseIP"
        );
    }

    #[test]
    fn routed_workload_rejects_sing_box_and_requires_geodata() {
        assert!(!WorkloadKind::RoutedTcpFreedom.supports_sing_box_process_engine());
        let fixture = WorkloadFixture::default();
        let error = sing_box_config(18101, WorkloadKind::RoutedTcpFreedom, &fixture).unwrap_err();
        assert!(error.to_string().contains("unsupported sing-box workload"));
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p xray-bench --lib routed 2>&1 | tail -8`
Expected: compile errors — no `RoutedTcpFreedom`, no `geodata_dir`, no `routed_freedom_config`.

- [ ] **Step 3: Implement**

(a) `WorkloadKind`: add variant `RoutedTcpFreedom,` after `TcpBulkThroughput,`; `as_str` → `"routed-tcp-freedom"`; `parse` arm; NOT added to `supports_sing_box_process_engine` or `uses_tun_fd`; `WorkloadFixture::start` no-fixture arm gains `| WorkloadKind::RoutedTcpFreedom`.

(b) `BenchOptions`: field `pub geodata_dir: Option<PathBuf>,` (+ `geodata_dir: None,` in `Default`, and in the full-struct-equality test `parses_run_idle_for_xray_rust`); CLI arm in `parse_cli_args`:
```rust
            "--geodata-dir" => {
                options.geodata_dir = Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
            }
```

(c) Domain constants + config generator (near `freedom_config`):
```rust
const GEO_HIT_DOMAIN: &str = "baidu.com";
const GEO_MISS_DOMAIN: &str = "bench-miss.invalid";

fn routed_freedom_config(port: u16, engine: EngineKind) -> String {
    // xray-rust freedom settings accept no fields; Xray-core needs UseIP so
    // its dns app (hosts-first) resolves instead of the OS resolver.
    let freedom_settings = match engine {
        EngineKind::XrayCore => r#"{ "domainStrategy": "UseIP" }"#,
        _ => "{}",
    };
    format!(
        r#"{{
  "log": {{ "loglevel": "warning" }},
  "dns": {{
    "hosts": {{
      "full:{GEO_HIT_DOMAIN}": "127.0.0.1",
      "full:{GEO_MISS_DOMAIN}": "127.0.0.1"
    }}
  }},
  "inbounds": [
    {{
      "tag": "socks-in",
      "protocol": "socks",
      "listen": "127.0.0.1",
      "port": {port},
      "settings": {{ "auth": "noauth", "udp": false }}
    }}
  ],
  "outbounds": [
    {{ "tag": "direct", "protocol": "freedom", "settings": {freedom_settings} }},
    {{ "tag": "direct-cn", "protocol": "freedom", "settings": {freedom_settings} }},
    {{ "tag": "direct-ads", "protocol": "freedom", "settings": {freedom_settings} }}
  ],
  "routing": {{
    "rules": [
      {{ "type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "direct-ads" }},
      {{ "type": "field", "ip": ["geoip:private"], "outboundTag": "direct" }},
      {{ "type": "field", "ip": ["geoip:cn"], "outboundTag": "direct-cn" }},
      {{ "type": "field", "domain": ["geosite:cn"], "outboundTag": "direct-cn" }}
    ]
  }}
}}"#
    )
}
```

(d) `engine_config`: new arm BEFORE the plain-SOCKS group:
```rust
        WorkloadKind::RoutedTcpFreedom => Ok(routed_freedom_config(port, engine)),
```
`xray_rust_config`: arm `WorkloadKind::RoutedTcpFreedom => routed_freedom_config(port, EngineKind::XrayRust),`. `sing_box_config` needs no change (falls to its unsupported arm because the supports flag is false).

(e) `start_engine` — after the config file is written and before command construction, add geodata staging:
```rust
    if options.workload == WorkloadKind::RoutedTcpFreedom {
        stage_geodata(options, run_dir)?;
    }
```
and per-engine env after the config arg is set (inside the existing `match kind` or right after it):
```rust
    if options.workload == WorkloadKind::RoutedTcpFreedom && kind == EngineKind::XrayCore {
        let geodata_dir = geodata_dir_for(options)?;
        command.env("XRAY_LOCATION_ASSET", absolute_path(&geodata_dir)?);
    }
```
with helpers near `start_engine`:
```rust
fn geodata_dir_for(options: &BenchOptions) -> Result<PathBuf, BenchError> {
    options.geodata_dir.clone().ok_or_else(|| {
        BenchError::InvalidArguments(
            "routed-tcp-freedom requires --geodata-dir <dir> containing geosite.dat and geoip.dat"
                .to_owned(),
        )
    })
}

// xray-rust resolves geodata relative to the config file's directory, so the
// files are staged (hardlinked, falling back to copy) into the run dir.
fn stage_geodata(options: &BenchOptions, run_dir: &Path) -> Result<(), BenchError> {
    let geodata_dir = geodata_dir_for(options)?;
    for name in ["geosite.dat", "geoip.dat"] {
        let source = geodata_dir.join(name);
        if !source.is_file() {
            return Err(BenchError::InvalidArguments(format!(
                "missing geodata file `{}`; pass --geodata-dir pointing at geosite.dat and geoip.dat",
                source.display()
            )));
        }
        let destination = run_dir.join(name);
        if destination.exists() {
            continue;
        }
        if fs::hard_link(&source, &destination).is_err() {
            fs::copy(&source, &destination).map_err(|source| BenchError::Io {
                action: format!("copying geodata into `{}`", destination.display()),
                source,
            })?;
        }
    }
    Ok(())
}
```

(f) Temporary dispatcher arm in `run_engine_once` (replaced in Task 6):
```rust
            WorkloadKind::RoutedTcpFreedom => run_idle_workload(options.duration).await,
```

(g) Add `use` for the fixture test if needed: xray-config's parse fn — call as `xray_config::parse_xray_json_with_geodata_dir(...)` (crate already in deps).

- [ ] **Step 4: Verify**

Run: `cargo test -p xray-bench --lib 2>&1 | tail -3` — expect 85 passed (81 + fixture test + 3 new), 0 failed. The Task 4 fixture test now compiles and must PASS — it proves the generated xray-rust config parses against the synthetic `.dat` files through the real parser.
Clippy clean (see Task 3 note about temporary allows if any).

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/xray-bench/src/lib.rs
git commit -m "Add routed-tcp-freedom workload plumbing and geodata staging

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: Routed workload runner and smoke tests

**Files:**
- Modify: `crates/xray-bench/src/lib.rs` — runner next to `run_tcp_freedom_workload`, dispatcher arm, tests

- [ ] **Step 1: Write the failing test**

A domain-aware in-test SOCKS5 forwarder (keep the existing IPv4 forwarder untouched) plus a workload smoke:

```rust
    async fn spawn_test_socks5_domain_forwarder() -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut client, _peer)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut greeting = [0; 2];
                    client.read_exact(&mut greeting).await.unwrap();
                    let mut methods = vec![0; greeting[1] as usize];
                    client.read_exact(&mut methods).await.unwrap();
                    client.write_all(&[5, 0]).await.unwrap();
                    let mut head = [0; 4];
                    client.read_exact(&mut head).await.unwrap();
                    assert_eq!(head[..3], [5, 1, 0]);
                    assert_eq!(head[3], 3, "domain forwarder expects ATYP=3");
                    let mut len = [0; 1];
                    client.read_exact(&mut len).await.unwrap();
                    let mut domain = vec![0; len[0] as usize];
                    client.read_exact(&mut domain).await.unwrap();
                    let domain = String::from_utf8(domain).unwrap();
                    assert!(
                        domain == GEO_HIT_DOMAIN || domain == GEO_MISS_DOMAIN,
                        "unexpected domain {domain}"
                    );
                    let mut port = [0; 2];
                    client.read_exact(&mut port).await.unwrap();
                    let port = u16::from_be_bytes(port);
                    let mut upstream =
                        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await.unwrap();
                    client
                        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (addr, task)
    }

    #[tokio::test]
    async fn routed_workload_collects_setup_and_latency_samples() {
        let (socks_addr, socks_task) = spawn_test_socks5_domain_forwarder().await;
        let options = BenchOptions {
            workload: WorkloadKind::RoutedTcpFreedom,
            connections: 4,
            iterations: 8,
            payload_size: 2048,
            ..BenchOptions::default()
        };

        let outcome = run_routed_tcp_freedom_workload(socks_addr, &options)
            .await
            .unwrap();

        assert_eq!(outcome.bytes_sent, 4 * 8 * 2048);
        assert_eq!(outcome.bytes_received, 4 * 8 * 2048);
        assert_eq!(outcome.setup_samples.len(), 4);
        assert_eq!(outcome.latencies_us.len(), 4 * 8);
        socks_task.abort();
    }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p xray-bench --lib routed_workload_collects 2>&1 | tail -6`
Expected: compile error — `run_routed_tcp_freedom_workload` not found.

- [ ] **Step 3: Implement**

Next to `run_tcp_freedom_workload` (mirror its echo server and fan-in exactly):

```rust
pub async fn run_routed_tcp_freedom_workload(
    socks_addr: SocketAddr,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .map_err(|source| BenchError::Io {
            action: "binding TCP echo server".to_owned(),
            source,
        })?;
    let echo_addr = listener.local_addr().map_err(|source| BenchError::Io {
        action: "reading TCP echo server address".to_owned(),
        source,
    })?;
    let echo_task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    let mut tasks = Vec::with_capacity(options.connections);
    for index in 0..options.connections {
        let options = options.clone();
        let domain = if index % 2 == 0 {
            GEO_HIT_DOMAIN
        } else {
            GEO_MISS_DOMAIN
        };
        tasks.push(tokio::spawn(async move {
            run_routed_connection(socks_addr, domain, echo_addr.port(), &options).await
        }));
    }

    let mut outcome = WorkloadOutcome::empty();
    for task in tasks {
        let task_outcome = task.await.map_err(|error| {
            BenchError::InvalidArguments(format!("routed workload task failed: {error}"))
        })??;
        outcome.extend(task_outcome);
    }
    echo_task.abort();

    Ok(outcome)
}

async fn run_routed_connection(
    socks_addr: SocketAddr,
    domain: &str,
    echo_port: u16,
    options: &BenchOptions,
) -> Result<WorkloadOutcome, BenchError> {
    let setup_started = Instant::now();
    let tcp_started = Instant::now();
    let mut client = TcpStream::connect(socks_addr)
        .await
        .map_err(|source| BenchError::Io {
            action: format!("connecting to SOCKS inbound at {socks_addr}"),
            source,
        })?;
    let tcp_connect_us = tcp_started.elapsed().as_micros();
    let socks = socks5_connect_domain_measured(&mut client, domain, echo_port).await?;
    let setup_sample = FlowSetupSample {
        tcp_connect_us,
        socks_method_us: socks.method_us,
        socks_connect_us: socks.connect_us,
        socks_setup_us: socks.total_us,
        total_us: setup_started.elapsed().as_micros(),
    };

    let payload = vec![0x5a; options.payload_size];
    let mut echoed = vec![0; options.payload_size];
    let mut sent = 0;
    let mut received = 0;
    let mut latencies_us = Vec::with_capacity(options.iterations);
    for _ in 0..options.iterations {
        let started = Instant::now();
        client
            .write_all(&payload)
            .await
            .map_err(|source| BenchError::Io {
                action: "writing benchmark payload".to_owned(),
                source,
            })?;
        sent += payload.len() as u64;
        client
            .read_exact(&mut echoed)
            .await
            .map_err(|source| BenchError::Io {
                action: "reading benchmark echo".to_owned(),
                source,
            })?;
        if echoed != payload {
            return Err(BenchError::InvalidArguments(
                "echo payload mismatch".to_owned(),
            ));
        }
        received += echoed.len() as u64;
        latencies_us.push(started.elapsed().as_micros());
    }

    Ok(WorkloadOutcome {
        bytes_sent: sent,
        bytes_received: received,
        latencies_us,
        setup_samples: vec![setup_sample],
        ..WorkloadOutcome::default()
    })
}
```

Replace the temporary dispatcher arm:
```rust
            WorkloadKind::RoutedTcpFreedom => {
                run_routed_tcp_freedom_workload(engine.socks_addr, options).await
            }
```
Remove any temporary `#[allow(dead_code)]` from Task 3.

- [ ] **Step 4: Verify**

Run: `cargo test -p xray-bench --lib 2>&1 | tail -3` — expect 86 passed. Clippy clean, no leftover allows.

- [ ] **Step 5: Manual CLI smoke with real geodata**

```bash
scripts/fetch-geodata.sh --output-dir /tmp/bench-geodata
cargo run --release -p xray-bench -- run --engine xray-rust --xray-rust-bin target/release/xray-rust --workload routed-tcp-freedom --geodata-dir /tmp/bench-geodata --connections 8 --iterations 10 --payload-size 1024 --run-timeout-ms 120000
```
Expected: `status=ok`, non-empty `setup_socks_connect_us` figures, `bytes_received=81920`. Then the same with `--engine xray-core --xray-core-dir Xray-core` — also `status=ok`. If Xray-core fails to start, read its `stderr.log` in the run dir before changing anything (likely geodata or dns config issues) and report DONE_WITH_CONCERNS with the exact error.

- [ ] **Step 6: Commit**

```bash
cargo fmt --all
git add crates/xray-bench/src/lib.rs
git commit -m "Add routed-tcp-freedom workload runner

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Geo charts and per-chart series

**Files:**
- Modify: `crates/xray-bench/src/chart.rs`

- [ ] **Step 1: Write the failing tests**

In chart.rs tests: extend `write_full_group` slots with routed summaries for xray-rust and xray-core ONLY (no sing-box), giving them `setup_us` aggregates. Concretely, inside the slot loop add a branch: for the routed slot write summaries whose `setup_us` is
```rust
                    summary.setup_us = Some(crate::FlowSetupSummaryAggregate {
                        tcp_connect_us: aggregate(40, 60, 90),
                        socks_method_us: aggregate(10, 15, 25),
                        socks_connect_us: aggregate(120, 180, 400),
                        socks_setup_us: aggregate(140, 200, 420),
                        total_us: aggregate(180, 260, 500),
                    });
```
with a local helper
```rust
    fn aggregate(min: u128, median: u128, p95: u128) -> crate::LatencySummaryAggregate {
        crate::LatencySummaryAggregate {
            min: MetricSummary { min, median, p95 },
            median: MetricSummary { min, median, p95 },
            p95: MetricSummary { min: p95, median: p95 * 2, p95: p95 * 3 },
            p99: MetricSummary { min, median, p95 },
        }
    }
```
(NOTE: `FlowSetupSummaryAggregate` fields are `LatencySummaryAggregate`s — check the struct at lib.rs:461 and adapt: each stage field is a `LatencySummaryAggregate`.)

New/changed assertions in `run_chart_writes_eight_theme_files` (rename to `run_chart_writes_twelve_theme_files`): stems list becomes
```rust
        for (stem, title_fragment) in [
            ("memory-rss", "Peak resident set size"),
            ("latency", "Round-trip latency"),
            ("throughput", "Bulk TCP throughput"),
            ("cpu-per-gib", "CPU cost"),
            ("geo-setup-latency", "Routing setup"),
            ("geo-memory", "Routing memory"),
        ]
```
plus `assert!(fs::read_to_string(out_dir.join("geo-setup-latency-light.svg")).unwrap().contains("Xray-core"));` and a negative check that the geo charts do NOT contain `sing-box` legend text:
```rust
        let geo = fs::read_to_string(out_dir.join("geo-memory-light.svg")).unwrap();
        assert!(!geo.contains(">sing-box<"));
```
Also add a `--geodata-version` parse test:
```rust
    #[test]
    fn parses_optional_geodata_version() {
        let mut args_vec = full_args("target/benchmarks/123");
        args_vec.push("--geodata-version".to_owned());
        args_vec.push("geosite-20260727 geoip-202607171233".to_owned());
        let options = parse_chart_args(&args_vec).unwrap();
        assert_eq!(
            options.geodata_version.as_deref(),
            Some("geosite-20260727 geoip-202607171233")
        );
    }
```
and a footer assertion in the twelve-files test: geo charts contain the geodata segment when the option is set (set `options.geodata_version = Some("geodata-test".to_owned());` before `run_chart` and assert `geo.contains("geodata-test")` while `memory-rss-light.svg` does NOT contain it).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p xray-bench --lib chart 2>&1 | tail -8` — compile errors (`geodata_version` missing etc.).

- [ ] **Step 3: Implement**

(a) `ChartOptions` gains `pub geodata_version: Option<String>,`; `parse_chart_args` arm `"--geodata-version" => { geodata_version = Some(required_value(...)?.to_owned()); }` (optional — no `required()` wrapper); struct init updated.

(b) `ChartSpec` gains `pub series_labels: &'static [&'static str],`. Define
```rust
const SERIES_LABELS_ALL: [&str; 3] = ["xray-rust", "Xray-core", "sing-box"];
const SERIES_LABELS_GEO: [&str; 2] = ["xray-rust", "Xray-core"];
const GEO_ENGINES: [EngineKind; 2] = [EngineKind::XrayRust, EngineKind::XrayCore];
```
`render_bar_chart` legend loop iterates `spec.series_labels` instead of the global `SERIES_LABELS` (delete the old const or keep it as `SERIES_LABELS_ALL`). All existing `ChartSpec` literals (incl. `fixture_spec()`) gain `series_labels: &SERIES_LABELS_ALL,`. Renderer goldens must stay byte-identical (same labels → same markup) — verify in Step 4.

(c) Footer: `Footer` gains `pub geodata: Option<String>,`; the second footer line becomes
```rust
        line = escape_xml(&match &footer.geodata {
            Some(geodata) => format!(
                "xray-rust {} · Xray-core {} · sing-box {} · geodata {}",
                footer.xray_rust_version, footer.xray_core_version, footer.sing_box_version, geodata
            ),
            None => format!(
                "xray-rust {} · Xray-core {} · sing-box {}",
                footer.xray_rust_version, footer.xray_core_version, footer.sing_box_version
            ),
        }),
```
For non-geo charts pass a Footer with `geodata: None`; for geo charts pass `geodata: options.geodata_version.clone()`. Implement by building two Footer values in `run_chart` (`footer` and `geo_footer`) and choosing per chart. `fixture_footer()` gains `geodata: None,`.

(d) Loading: `CHART_SLOTS` gains `(WorkloadKind::RoutedTcpFreedom, None)` as its last element (array type becomes `[(WorkloadKind, Option<u64>); 7]`); the load loop must load routed summaries only for `GEO_ENGINES` (skip sing-box):
```rust
    for (workload, connections) in CHART_SLOTS {
        let engines: &[EngineKind] = if workload == WorkloadKind::RoutedTcpFreedom {
            &GEO_ENGINES
        } else {
            &ENGINES
        };
        for engine in engines {
            let summary = load_summary(&options.groups, *engine, workload, connections)?;
            entries.push(((*engine, workload, connections), summary));
        }
    }
```

(e) Geo group builders:
```rust
fn geo_setup_group(loaded: &LoadedSummaries) -> Result<BarGroup, BenchError> {
    let bars = GEO_ENGINES
        .iter()
        .enumerate()
        .map(|(series, engine)| {
            let summary = loaded.get(*engine, WorkloadKind::RoutedTcpFreedom, None);
            let setup = summary.setup_us.as_ref().ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "summary for {} routed-tcp-freedom has no setup data",
                    engine.as_str()
                ))
            })?;
            // Bar: median of per-run median SOCKS CONNECT round-trips (rule
            // evaluation + hosts resolution + local dial). Whisker: min run
            // median up to the median run p95.
            Ok(Bar {
                series,
                value: setup.socks_connect_us.median.median as f64,
                lo: setup.socks_connect_us.median.min as f64,
                hi: setup.socks_connect_us.p95.median as f64,
            })
        })
        .collect::<Result<Vec<_>, BenchError>>()?;
    Ok(BarGroup {
        label: "routed-tcp-freedom".to_owned(),
        bars,
    })
}

fn geo_memory_group(loaded: &LoadedSummaries) -> BarGroup {
    BarGroup {
        label: "routed-tcp-freedom".to_owned(),
        bars: GEO_ENGINES
            .iter()
            .enumerate()
            .map(|(series, engine)| {
                metric_bar(
                    &loaded
                        .get(*engine, WorkloadKind::RoutedTcpFreedom, None)
                        .peak_rss_kib,
                    series,
                    1024.0,
                )
            })
            .collect(),
    }
}
```

(f) Charts vec gains two entries (after cpu-per-gib), with the geo footer:
```rust
        (
            "geo-setup-latency",
            ChartSpec {
                title: "Routing setup with real geodata — µs per connection (lower is better)"
                    .to_owned(),
                series_labels: &SERIES_LABELS_GEO,
                groups: vec![geo_setup_group(&loaded)?],
            },
        ),
        (
            "geo-memory",
            ChartSpec {
                title: "Routing memory with real geodata — MiB (lower is better)".to_owned(),
                series_labels: &SERIES_LABELS_GEO,
                groups: vec![geo_memory_group(&loaded)],
            },
        ),
```
The write loop selects `geo_footer` for stems starting with `geo-`.

- [ ] **Step 4: Verify**

Run: `cargo test -p xray-bench --lib 2>&1 | tail -3` — expect 88 passed (86 + geodata-version parse + twelve-files replaces eight-files; count the actual delta and report).
`git status --short crates/xray-bench/testdata/` — EMPTY (renderer goldens byte-stable; if not, the legend/footer change altered 3-series output — fix before committing).
Clippy clean.

- [ ] **Step 5: Commit**

```bash
cargo fmt --all
git add crates/xray-bench/src/chart.rs
git commit -m "Add geo routing charts with per-chart series and geodata footer

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Documentation

**Files:**
- Modify: `docs/benchmarks.md`

- [ ] **Step 1: Apply the edits**

(a) "First Slice" list: add `- \`routed-tcp-freedom\`` after `tcp-bulk-throughput`.

(b) "Run xray-rust Only" block, after the bulk example:
```sh
scripts/fetch-geodata.sh --output-dir /tmp/bench-geodata
cargo run --release -p xray-bench -- run --engine xray-rust --workload routed-tcp-freedom --geodata-dir /tmp/bench-geodata --connections 8 --iterations 100 --payload-size 1024 --run-timeout-ms 120000
```

(c) Compare Engines: add to the xray-rust-vs-Xray-core-only block (the one that skips sing-box):
```sh
cargo run --release -p xray-bench -- compare --workload routed-tcp-freedom --xray-core-dir Xray-core --geodata-dir /tmp/bench-geodata --runs 5 --connections 8 --iterations 100 --payload-size 1024 --run-timeout-ms 120000
```
and extend the sentence about workloads excluded from sing-box with: "`routed-tcp-freedom` is also xray-rust vs Xray-core only: sing-box ≥1.8 does not read Xray-format `.dat` geodata, and semantically equivalent `.srs` rule-sets cannot be guaranteed."

(d) Metrics section, workload paragraph (place after the `tcp-bulk-throughput` paragraph):
```markdown
`routed-tcp-freedom` is `tcp-freedom` with SOCKS5 domain CONNECT through a
config carrying real geosite/geoip routing rules
(`geosite:category-ads-all`, `geoip:private`, `geoip:cn`, `geosite:cn`) and
several tagged `freedom` outbounds. Connections alternate between a domain
that matches the last geosite rule and one that falls through every rule to
the default outbound; both resolve to `127.0.0.1` via `dns.hosts`, so no
packet leaves the machine. `--geodata-dir` must contain `geosite.dat` and
`geoip.dat` (fetch pinned, checksum-verified files with
`scripts/fetch-geodata.sh --output-dir <dir>`). Headline numbers:
`setup_socks_connect_us` (rule evaluation + hosts resolution + local dial per
connection) and `peak_rss_kib` (matcher memory for the loaded geodata).
```

(e) 1000-flow scale note, appended to the existing `many-idle-flows` paragraph:
```markdown
For a scale point, the publication charts also run `many-idle-flows` with
`--connections 1000`. xray-rust's SOCKS inbound admits at most 1024
concurrent connections (`DEFAULT_MAX_INBOUND_CONNECTIONS`), so 1000 fits with
little headroom and higher counts would be refused; the harness side needs a
file-descriptor limit of several thousand (`ulimit -n`).
```

(f) Publishing Numbers and Charts: extend the charted-workload sentence to name the seven series (`idle`, `many-idle-flows` ×100 and ×1000, `tcp-freedom`, `reality-vision-xudp`, `tcp-bulk-throughput`, `routed-tcp-freedom`) and add the geodata flags to the chart example: `--geodata-version "geosite-<tag> geoip-<tag>"` plus a sentence: "Charts select `many-idle-flows` summaries by their recorded connection count, so both scales come from separate compare runs; geo charts read the `routed-tcp-freedom` summaries (xray-rust and Xray-core only)."

- [ ] **Step 2: Verify accuracy against code**

Grep chart.rs for the stems and flags you cited; run `cargo run --release -p xray-bench -- chart 2>&1 | head -2` to confirm the error mentions `--group` (binary sanity).

- [ ] **Step 3: Commit**

```bash
git add docs/benchmarks.md
git commit -m "Document routed-tcp-freedom, 1000-flow scale point, and geo charts

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: Publication data run

Operator task on the maintainer's Mac; quiet machine, release builds.

- [ ] **Step 1: Build + fetch**

```bash
cargo build --release -p xray-cli --bin xray-rust
cargo build --release -p xray-bench
scripts/fetch-geodata.sh --output-dir /tmp/bench-geodata
```
Record geodata tags from the script (`GEOSITE_VERSION`, `GEOIP_VERSION` — currently 20260727084448 / 202607171233; read the script, do not assume).

- [ ] **Step 2: Run the seven compare series** (sequentially; sing-box via `--sing-box-dir /Users/antonmalygin/sing-box`; Xray-core via `--xray-core-dir Xray-core`; always `--xray-rust-bin target/release/xray-rust`)

```bash
B="target/release/xray-bench"; XR="--xray-rust-bin target/release/xray-rust"; XC="--xray-core-dir Xray-core"; SB="--sing-box-dir /Users/antonmalygin/sing-box"
$B compare --workload idle $XC $SB $XR --runs 5 --duration-ms 5000
$B compare --workload many-idle-flows $XC $SB $XR --runs 5 --connections 100 --duration-ms 5000
$B compare --workload many-idle-flows $XC $SB $XR --runs 5 --connections 1000 --duration-ms 5000 --run-timeout-ms 120000
$B compare --workload tcp-freedom $XC $SB $XR --runs 5 --connections 1 --iterations 1000 --payload-size 4096
$B compare --workload reality-vision-xudp $XC $SB $XR --runs 5 --connections 1 --iterations 1000 --payload-size 512 --run-timeout-ms 120000
$B compare --workload tcp-bulk-throughput $XC $SB $XR --runs 5 --connections 1 --iterations 256 --payload-size 4194304 --run-timeout-ms 120000
$B compare --workload routed-tcp-freedom $XC $XR --geodata-dir /tmp/bench-geodata --runs 5 --connections 8 --iterations 100 --payload-size 1024 --run-timeout-ms 120000
```
Sanity-check every printed line `status=ok`; the routed compare must print the sing-box skip message. A transient timeout (seen once before on reality-vision-xudp) → retry that series once.

- [ ] **Step 3: Render charts**

`ls -t target/benchmarks | head -7` for the group ids (oldest of the seven = idle). Then:
```bash
$B chart \
  --group target/benchmarks/<id1> ... --group target/benchmarks/<id7> \
  --date $(date +%F) \
  --hardware "Apple M3 Pro, 18 GB RAM, macOS $(sw_vers -productVersion)" \
  --xray-rust-version $(git rev-parse --short HEAD) \
  --xray-core-version v26.5.9 \
  --sing-box-version v1.13.15 \
  --geodata-version "geosite-<GEOSITE_VERSION> geoip-<GEOIP_VERSION>"
```
12 files written. Visually verify at least memory-rss (3 groups now), geo-setup-latency, geo-memory (2 bars each, no sing-box legend). The controller performs the human visual pass — hand back PNG renders via `qlmanage -t -s 900 -o <dir> <svg>`.

- [ ] **Step 4: Commit**

```bash
git add docs/benchmarks/media/
git commit -m "Publish scale and geo-rules benchmark charts

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 10: README updates

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Apply the edits** (numbers marked `<N>` come from the Task 9 charts — read each value off the light SVG value labels and verify with grep `>value<` before writing)

(a) Methodology paragraph: extend the series sentence to mention the geodata series: after "...sing-box `v1.13.15`." add:
```markdown
The routing charts load real, pinned V2Fly geodata
(`geosite <GEOSITE_VERSION>`, `geoip <GEOIP_VERSION>`); sing-box is absent
from those two charts because it does not read Xray-format `.dat` rule data.
```

(b) memory-rss alt text — new three-group version:
```markdown
alt="Peak resident set size, lower is better. Idle: xray-rust <N> MiB, Xray-core <N>, sing-box <N>. 100 idle flows: xray-rust <N>, Xray-core <N>, sing-box <N>. 1000 idle flows: xray-rust <N>, Xray-core <N>, sing-box <N>."
```

(c) Two new `<picture>` blocks after cpu-per-gib:
```markdown
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/geo-setup-latency-dark.svg">
  <img alt="Connection setup through real geosite and geoip routing rules, lower is better: xray-rust <N> µs, Xray-core <N> µs." src="docs/benchmarks/media/geo-setup-latency-light.svg">
</picture>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/benchmarks/media/geo-memory-dark.svg">
  <img alt="Peak memory with real geodata loaded, lower is better: xray-rust <N> MiB, Xray-core <N> MiB." src="docs/benchmarks/media/geo-memory-light.svg">
</picture>
```

(d) Update the takeaway sentence if the geo numbers change the story (state the geo result neutrally, e.g. "with real geosite/geoip rules loaded it uses <N>× less memory and sets up connections <faster/slower/comparably>"). Keep the honest-tone rule: report whatever the numbers say.

- [ ] **Step 2: Verify** — every `<N>` matches an SVG value label; anchors/paths exist; `## Prerequisites` still follows the section.

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "Add scale and geo-rules charts to README

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 11: Final verification

- [ ] **Step 1: CI-equivalent checks**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings -W clippy::perf -W clippy::suspicious
cargo test --workspace --all-targets --locked
```

- [ ] **Step 2: Chart byte-stability** — re-run the Task 9 chart command verbatim; `git status --short docs/benchmarks/media/` must be empty.

---

## Self-Review Notes

- Spec coverage: params persistence (T1), chart selection + ×1000 group (T2), domain CONNECT (T3), fixture helper generating at test time (T4 — approved deviation from "committed testdata"), routed workload with per-engine configs/staging/env (T5-T6), 2-engine charts + geodata footer (T7), docs (T8), publication (T9), README (T10), verification (T11).
- The T4 fixture test doubles as the strongest correctness gate: the generated xray-rust config must parse against synthetic `.dat` files through the real `xray-config` parser.
- Known behavior nuance documented in grounding facts: `geoip:private` is hardcoded in xray-rust but file-loaded in Xray-core; `ip` rules never match domain CONNECTs under AsIs in either engine (they contribute rule-walk cost only).
- Counts of expected passing tests are estimates ±1; implementers report actual deltas.

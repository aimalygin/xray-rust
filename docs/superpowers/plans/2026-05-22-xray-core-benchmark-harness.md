# Xray Core Benchmark Harness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first reproducible process-level benchmark harness that compares `xray-rust` and Xray-core on idle and TCP Freedom echo workloads.

**Architecture:** Add a dedicated `xray-bench` workspace binary so benchmarking stays outside the core data path. The binary generates equivalent Xray JSON configs, starts either engine as a child process, runs a shared workload, samples OS process metrics, and writes raw samples plus summaries under `target/benchmarks`.

**Tech Stack:** Rust 2021, Tokio TCP, `serde`/`serde_json`, std process management, macOS/Linux `ps` sampling, Xray SOCKS5 TCP path, local TCP echo server.

---

### Task 1: Add Plan and Workspace Skeleton

**Files:**
- Modify: `Cargo.toml`
- Create: `crates/xray-bench/Cargo.toml`
- Create: `crates/xray-bench/src/main.rs`
- Create: `crates/xray-bench/src/lib.rs`

- [ ] **Step 1: Add `xray-bench` to the workspace**

Modify the root `Cargo.toml` members list to include:

```toml
    "crates/xray-bench",
```

Keep it next to `crates/xray-cli` because both are process-facing tools.

- [ ] **Step 2: Create the crate manifest**

Create `crates/xray-bench/Cargo.toml`:

```toml
[package]
name = "xray-bench"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[[bin]]
name = "xray-bench"
path = "src/main.rs"

[dependencies]
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tokio.workspace = true
```

- [ ] **Step 3: Create the CLI entrypoint**

Create `crates/xray-bench/src/main.rs`:

```rust
#[tokio::main]
async fn main() {
    if let Err(error) = xray_bench::run_cli(std::env::args()).await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
```

- [ ] **Step 4: Create a minimal library surface**

Create `crates/xray-bench/src/lib.rs`:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BenchError {
    #[error("{0}")]
    InvalidArguments(String),
}

pub async fn run_cli<I, S>(_args: I) -> Result<(), BenchError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    Err(BenchError::InvalidArguments(
        "usage: xray-bench run|compare [options]".to_owned(),
    ))
}
```

- [ ] **Step 5: Run the skeleton build**

Run:

```sh
cargo check -p xray-bench
```

Expected: PASS.

- [ ] **Step 6: Commit**

```sh
git add Cargo.toml crates/xray-bench docs/superpowers/plans/2026-05-22-xray-core-benchmark-harness.md
git commit -m "build(bench): add benchmark harness crate"
```

### Task 2: CLI Parsing and Workload Options

**Files:**
- Modify: `crates/xray-bench/src/lib.rs`

- [ ] **Step 1: Add failing CLI parsing tests**

Add this test module to `crates/xray-bench/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn parses_run_idle_for_xray_rust() {
        let args = parse_cli_args([
            "xray-bench",
            "run",
            "--engine",
            "xray-rust",
            "--workload",
            "idle",
            "--duration-ms",
            "250",
            "--sample-interval-ms",
            "50",
            "--out-dir",
            "target/benchmarks/test",
        ])
        .unwrap();

        assert_eq!(
            args,
            CliArgs::Run(BenchOptions {
                engine: Some(EngineKind::XrayRust),
                workload: WorkloadKind::Idle,
                duration: Duration::from_millis(250),
                sample_interval: Duration::from_millis(50),
                connections: 1,
                iterations: 1,
                payload_size: 1024,
                out_dir: PathBuf::from("target/benchmarks/test"),
                xray_rust_bin: None,
                xray_core_bin: None,
                xray_core_dir: None,
                no_auto_build: false,
            })
        );
    }

    #[test]
    fn parses_compare_tcp_freedom() {
        let args = parse_cli_args([
            "xray-bench",
            "compare",
            "--workload",
            "tcp-freedom",
            "--connections",
            "2",
            "--iterations",
            "3",
            "--payload-size",
            "64",
            "--xray-core-dir",
            "../Xray-core",
        ])
        .unwrap();

        let CliArgs::Compare(options) = args else {
            panic!("expected compare args");
        };
        assert_eq!(options.workload, WorkloadKind::TcpFreedom);
        assert_eq!(options.connections, 2);
        assert_eq!(options.iterations, 3);
        assert_eq!(options.payload_size, 64);
        assert_eq!(options.xray_core_dir, Some(PathBuf::from("../Xray-core")));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```sh
cargo test -p xray-bench parses_
```

Expected: FAIL because `parse_cli_args`, `CliArgs`, `BenchOptions`, `EngineKind`, and `WorkloadKind` do not exist yet.

- [ ] **Step 3: Implement CLI types and parser**

Replace `crates/xray-bench/src/lib.rs` with parser support that defines:

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliArgs {
    Run(BenchOptions),
    Compare(BenchOptions),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineKind {
    XrayRust,
    XrayCore,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkloadKind {
    Idle,
    TcpFreedom,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchOptions {
    pub engine: Option<EngineKind>,
    pub workload: WorkloadKind,
    pub duration: std::time::Duration,
    pub sample_interval: std::time::Duration,
    pub connections: usize,
    pub iterations: usize,
    pub payload_size: usize,
    pub out_dir: std::path::PathBuf,
    pub xray_rust_bin: Option<std::path::PathBuf>,
    pub xray_core_bin: Option<std::path::PathBuf>,
    pub xray_core_dir: Option<std::path::PathBuf>,
    pub no_auto_build: bool,
}
```

The parser must support:

```text
xray-bench run --engine xray-rust|xray-core --workload idle|tcp-freedom
xray-bench compare --workload idle|tcp-freedom
--duration-ms <u64>
--sample-interval-ms <u64>
--connections <usize>
--iterations <usize>
--payload-size <usize>
--out-dir <path>
--xray-rust-bin <path>
--xray-core-bin <path>
--xray-core-dir <path>
--no-auto-build
```

Defaults:

```rust
workload = WorkloadKind::Idle
duration = Duration::from_secs(2)
sample_interval = Duration::from_millis(100)
connections = 1
iterations = 1
payload_size = 1024
out_dir = PathBuf::from("target/benchmarks")
no_auto_build = false
```

- [ ] **Step 4: Run parser tests**

Run:

```sh
cargo test -p xray-bench parses_
```

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/xray-bench/src/lib.rs
git commit -m "feat(bench): parse benchmark cli options"
```

### Task 3: Process Sampling and Report Files

**Files:**
- Modify: `crates/xray-bench/src/lib.rs`

- [ ] **Step 1: Add failing sampler/report tests**

Add tests for:

```rust
#[test]
fn parses_ps_sample_line_with_thread_count() {
    let sample = parse_ps_sample(" 12345 00:01.23 7").unwrap();
    assert_eq!(sample.rss_kib, 12345);
    assert_eq!(sample.cpu_millis, 1230);
    assert_eq!(sample.threads, Some(7));
}

#[test]
fn parses_ps_time_with_hours() {
    let sample = parse_ps_sample(" 2048 01:02:03 9").unwrap();
    assert_eq!(sample.cpu_millis, 3_723_000);
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```sh
cargo test -p xray-bench parses_ps
```

Expected: FAIL because `parse_ps_sample` does not exist.

- [ ] **Step 3: Implement process sample parsing and report types**

Add:

```rust
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ProcessSample {
    pub elapsed_ms: u128,
    pub rss_kib: u64,
    pub cpu_millis: u64,
    pub threads: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BenchResult {
    pub engine: String,
    pub workload: String,
    pub status: String,
    pub duration_ms: u128,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub peak_rss_kib: u64,
    pub cpu_millis: u64,
    pub samples: usize,
}
```

Implement `parse_ps_sample` for `rss time [threads]`, and `parse_ps_time_to_millis` for `MM:SS`, `MM:SS.xx`, `HH:MM:SS`, and `DD-HH:MM:SS`.

- [ ] **Step 4: Run sampler tests**

Run:

```sh
cargo test -p xray-bench parses_ps
```

Expected: PASS.

- [ ] **Step 5: Add result writers**

Implement:

```rust
fn write_result_json(path: &std::path::Path, result: &BenchResult) -> Result<(), BenchError>;
fn write_samples_csv(path: &std::path::Path, samples: &[ProcessSample]) -> Result<(), BenchError>;
```

The CSV header must be:

```text
elapsed_ms,rss_kib,cpu_millis,threads
```

- [ ] **Step 6: Commit**

```sh
git add crates/xray-bench/src/lib.rs
git commit -m "feat(bench): add process metric reports"
```

### Task 4: Engine Processes and Config Generation

**Files:**
- Modify: `crates/xray-bench/src/lib.rs`

- [ ] **Step 1: Add failing config generation tests**

Add tests:

```rust
#[test]
fn xray_rust_freedom_config_uses_requested_socks_port() {
    let config = xray_rust_freedom_config(18080);
    assert!(config.contains(r#""protocol": "socks""#));
    assert!(config.contains(r#""port": 18080"#));
    assert!(config.contains(r#""protocol": "freedom""#));
}

#[test]
fn xray_core_freedom_config_uses_requested_socks_port() {
    let config = xray_core_freedom_config(18081);
    assert!(config.contains(r#""protocol": "socks""#));
    assert!(config.contains(r#""port": 18081"#));
    assert!(config.contains(r#""protocol": "freedom""#));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run:

```sh
cargo test -p xray-bench freedom_config
```

Expected: FAIL because config functions do not exist.

- [ ] **Step 3: Implement config generation**

Add:

```rust
fn xray_rust_freedom_config(port: u16) -> String;
fn xray_core_freedom_config(port: u16) -> String;
```

`xray-rust` config must use empty Freedom settings because the Rust parser rejects unknown Freedom settings. Xray-core config can also use empty Freedom settings so both configs stay equivalent.

- [ ] **Step 4: Implement engine process start/stop**

Add:

```rust
struct RunningEngine {
    kind: EngineKind,
    child: std::process::Child,
    pid: u32,
    socks_addr: std::net::SocketAddr,
    run_dir: std::path::PathBuf,
    stdout_path: std::path::PathBuf,
    stderr_path: std::path::PathBuf,
}
```

Implement:

```rust
fn allocate_loopback_port() -> Result<u16, BenchError>;
async fn wait_for_tcp_listener(child: &mut std::process::Child, addr: std::net::SocketAddr, stdout_path: &std::path::Path, stderr_path: &std::path::Path) -> Result<(), BenchError>;
fn ensure_xray_rust_binary(options: &BenchOptions) -> Result<std::path::PathBuf, BenchError>;
fn ensure_xray_core_binary(options: &BenchOptions, bin_dir: &std::path::Path) -> Result<std::path::PathBuf, BenchError>;
async fn start_engine(kind: EngineKind, options: &BenchOptions, run_dir: &std::path::Path) -> Result<RunningEngine, BenchError>;
```

`ensure_xray_rust_binary` should prefer `--xray-rust-bin`, then `target/debug/xray-rust`, and if missing and auto-build is enabled, run `cargo build -p xray-cli --bin xray-rust`.

`ensure_xray_core_binary` should prefer `--xray-core-bin`, then build `./main` from `--xray-core-dir` into the run directory when auto-build is enabled.

- [ ] **Step 5: Run checks**

Run:

```sh
cargo test -p xray-bench freedom_config
cargo check -p xray-bench
```

Expected: PASS.

- [ ] **Step 6: Commit**

```sh
git add crates/xray-bench/src/lib.rs
git commit -m "feat(bench): start benchmark engine processes"
```

### Task 5: Idle and TCP Freedom Workloads

**Files:**
- Modify: `crates/xray-bench/src/lib.rs`

- [ ] **Step 1: Add failing workload unit tests**

Add tests:

```rust
#[test]
fn summarizes_samples_with_peak_rss_and_cpu_delta() {
    let samples = vec![
        ProcessSample { elapsed_ms: 0, rss_kib: 100, cpu_millis: 10, threads: Some(2) },
        ProcessSample { elapsed_ms: 10, rss_kib: 150, cpu_millis: 25, threads: Some(2) },
    ];
    let summary = summarize_samples(&samples);
    assert_eq!(summary.peak_rss_kib, 150);
    assert_eq!(summary.cpu_millis, 15);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```sh
cargo test -p xray-bench summarizes_samples
```

Expected: FAIL because `summarize_samples` does not exist.

- [ ] **Step 3: Implement workload primitives**

Add:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WorkloadSummary {
    bytes_sent: u64,
    bytes_received: u64,
    peak_rss_kib: u64,
    cpu_millis: u64,
}

fn summarize_samples(samples: &[ProcessSample]) -> WorkloadSummary;
async fn run_idle_workload(duration: std::time::Duration) -> Result<(u64, u64), BenchError>;
async fn run_tcp_freedom_workload(socks_addr: std::net::SocketAddr, options: &BenchOptions) -> Result<(u64, u64), BenchError>;
```

`run_tcp_freedom_workload` should start a local TCP echo server, connect through SOCKS5, send `payload_size` bytes for `iterations` on each connection, read exact echoes, and return sent/received byte counts.

- [ ] **Step 4: Implement the sampler loop**

Add:

```rust
async fn sample_while<F, T>(pid: u32, interval: std::time::Duration, future: F) -> Result<(T, Vec<ProcessSample>), BenchError>
where
    F: std::future::Future<Output = Result<T, BenchError>>;
```

The function should sample before and during the workload. If `ps` sampling fails for permission reasons, return a clear `BenchError::Sample`.

- [ ] **Step 5: Run tests and check**

Run:

```sh
cargo test -p xray-bench summarizes_samples
cargo check -p xray-bench
```

Expected: PASS.

- [ ] **Step 6: Commit**

```sh
git add crates/xray-bench/src/lib.rs
git commit -m "feat(bench): add idle and tcp freedom workloads"
```

### Task 6: Run/Compare Orchestration

**Files:**
- Modify: `crates/xray-bench/src/lib.rs`

- [ ] **Step 1: Add failing orchestration tests**

Add tests:

```rust
#[test]
fn run_directory_contains_engine_and_workload() {
    let dir = run_directory(
        std::path::Path::new("target/benchmarks"),
        "123",
        EngineKind::XrayRust,
        WorkloadKind::Idle,
    );
    assert_eq!(
        dir,
        std::path::PathBuf::from("target/benchmarks/123/xray-rust/idle")
    );
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```sh
cargo test -p xray-bench run_directory
```

Expected: FAIL because `run_directory` does not exist.

- [ ] **Step 3: Implement orchestration**

Implement:

```rust
pub async fn run_cli<I, S>(args: I) -> Result<(), BenchError>;
async fn run_single_engine(kind: EngineKind, options: &BenchOptions, run_id: &str) -> Result<BenchResult, BenchError>;
async fn run_compare(options: BenchOptions) -> Result<(), BenchError>;
fn run_directory(base: &std::path::Path, run_id: &str, engine: EngineKind, workload: WorkloadKind) -> std::path::PathBuf;
```

`run_cli` should:

- Parse args.
- For `run`, require `--engine`.
- For `compare`, run `xray-rust` then Xray-core with the same workload options.
- Print a compact text summary to stdout.
- Always write `config.json`, `result.json`, `samples.csv`, `stdout.log`, and `stderr.log` under the run directory.

- [ ] **Step 4: Run orchestration tests**

Run:

```sh
cargo test -p xray-bench run_directory parses_
cargo check -p xray-bench
```

Expected: PASS.

- [ ] **Step 5: Commit**

```sh
git add crates/xray-bench/src/lib.rs
git commit -m "feat(bench): orchestrate benchmark runs"
```

### Task 7: Documentation and First Local Verification

**Files:**
- Create: `docs/benchmarks.md`
- Modify: `README.md` if it already has a verification section mentioning mobile/runtime checks.

- [ ] **Step 1: Write benchmark docs**

Create `docs/benchmarks.md` with:

```markdown
# Benchmarks

The benchmark harness compares `xray-rust` and the cloned Xray-core under the same local workloads.

## First Slice

Supported workloads:

- `idle`
- `tcp-freedom`

The harness writes results under `target/benchmarks/<run-id>/<engine>/<workload>/`.

## Run xray-rust Only

```sh
cargo run -p xray-bench -- run --engine xray-rust --workload idle --duration-ms 1000
cargo run -p xray-bench -- run --engine xray-rust --workload tcp-freedom --connections 1 --iterations 10 --payload-size 1024
```

## Compare with Xray-core

```sh
cargo run -p xray-bench -- compare --workload tcp-freedom --xray-core-dir Xray-core --connections 1 --iterations 10 --payload-size 1024
```

The compare command auto-builds `target/debug/xray-rust` and an Xray-core binary under the run directory unless `--no-auto-build` is provided.

## Metrics

- `result.json` contains summary RSS, CPU, throughput bytes, status, and workload metadata.
- `samples.csv` contains raw timestamped process samples.
- `stdout.log` and `stderr.log` contain child process logs.
```

- [ ] **Step 2: Run unit tests**

Run:

```sh
cargo test -p xray-bench
```

Expected: PASS.

- [ ] **Step 3: Run xray-rust idle smoke**

Run with escalation if the sandbox blocks `ps`:

```sh
cargo run -p xray-bench -- run --engine xray-rust --workload idle --duration-ms 500 --sample-interval-ms 100 --out-dir target/benchmarks/smoke
```

Expected: PASS and files under `target/benchmarks/smoke/<run-id>/xray-rust/idle/`.

- [ ] **Step 4: Run xray-rust TCP Freedom smoke**

Run with escalation if the sandbox blocks process metrics or local sockets:

```sh
cargo run -p xray-bench -- run --engine xray-rust --workload tcp-freedom --connections 1 --iterations 3 --payload-size 128 --out-dir target/benchmarks/smoke
```

Expected: PASS and `result.json` reports `bytes_sent = 384` and `bytes_received = 384`.

- [ ] **Step 5: Try Xray-core compare smoke**

Run:

```sh
cargo run -p xray-bench -- compare --workload tcp-freedom --connections 1 --iterations 3 --payload-size 128 --out-dir target/benchmarks/smoke --xray-core-dir Xray-core
```

Expected: PASS if Go can build the local Xray-core checkout. If the Go toolchain or module cache blocks the build, document the blocker in the final answer and keep the xray-rust smoke evidence.

- [ ] **Step 6: Run workspace checks**

Run:

```sh
cargo fmt --all
cargo test -p xray-bench
cargo clippy -p xray-bench --all-targets --locked -- -D warnings
```

Expected: PASS.

- [ ] **Step 7: Commit**

```sh
git add docs/benchmarks.md crates/xray-bench Cargo.toml
git commit -m "docs(bench): document benchmark harness"
```

## Self-Review

- Spec coverage: the plan covers a process-level harness, OS-level RSS/CPU sampling, result directories, idle workload, TCP Freedom workload, xray-rust and Xray-core engines, and docs. UDP/VLESS/Vision workloads remain future tasks as intended by the first slice.
- Placeholder scan: no unresolved markers remain in implementation steps.
- Type consistency: `BenchOptions`, `EngineKind`, `WorkloadKind`, `ProcessSample`, and `BenchResult` names are consistent across tasks.

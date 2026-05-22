use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use thiserror::Error;

const USAGE: &str = "usage: xray-bench run|compare [options]";

#[derive(Debug, Error)]
pub enum BenchError {
    #[error("{0}")]
    InvalidArguments(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliArgs {
    Run(BenchOptions),
    Compare(BenchOptions),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineKind {
    XrayRust,
    XrayCore,
}

impl EngineKind {
    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "xray-rust" => Ok(Self::XrayRust),
            "xray-core" => Ok(Self::XrayCore),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported engine `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkloadKind {
    Idle,
    TcpFreedom,
}

impl WorkloadKind {
    fn parse(raw: &str) -> Result<Self, BenchError> {
        match raw {
            "idle" => Ok(Self::Idle),
            "tcp-freedom" => Ok(Self::TcpFreedom),
            other => Err(BenchError::InvalidArguments(format!(
                "unsupported workload `{other}`"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BenchOptions {
    pub engine: Option<EngineKind>,
    pub workload: WorkloadKind,
    pub duration: Duration,
    pub sample_interval: Duration,
    pub connections: usize,
    pub iterations: usize,
    pub payload_size: usize,
    pub out_dir: PathBuf,
    pub xray_rust_bin: Option<PathBuf>,
    pub xray_core_bin: Option<PathBuf>,
    pub xray_core_dir: Option<PathBuf>,
    pub no_auto_build: bool,
}

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

impl Default for BenchOptions {
    fn default() -> Self {
        Self {
            engine: None,
            workload: WorkloadKind::Idle,
            duration: Duration::from_secs(2),
            sample_interval: Duration::from_millis(100),
            connections: 1,
            iterations: 1,
            payload_size: 1024,
            out_dir: PathBuf::from("target/benchmarks"),
            xray_rust_bin: None,
            xray_core_bin: None,
            xray_core_dir: None,
            no_auto_build: false,
        }
    }
}

pub fn parse_cli_args<I, S>(args: I) -> Result<CliArgs, BenchError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut args = args.into_iter().map(Into::into);
    let _program = args.next();
    let Some(command) = args.next() else {
        return Err(BenchError::InvalidArguments(USAGE.to_owned()));
    };

    let mut options = BenchOptions::default();
    let rest = args.collect::<Vec<_>>();
    let mut index = 0;
    while index < rest.len() {
        let flag = rest[index].as_str();
        index += 1;
        match flag {
            "--engine" => {
                options.engine = Some(EngineKind::parse(required_value(&rest, &mut index, flag)?)?);
            }
            "--workload" => {
                options.workload = WorkloadKind::parse(required_value(&rest, &mut index, flag)?)?;
            }
            "--duration-ms" => {
                options.duration = Duration::from_millis(parse_u64(
                    required_value(&rest, &mut index, flag)?,
                    flag,
                )?);
            }
            "--sample-interval-ms" => {
                options.sample_interval = Duration::from_millis(parse_u64(
                    required_value(&rest, &mut index, flag)?,
                    flag,
                )?);
            }
            "--connections" => {
                options.connections = parse_usize(required_value(&rest, &mut index, flag)?, flag)?;
            }
            "--iterations" => {
                options.iterations = parse_usize(required_value(&rest, &mut index, flag)?, flag)?;
            }
            "--payload-size" => {
                options.payload_size = parse_usize(required_value(&rest, &mut index, flag)?, flag)?;
            }
            "--out-dir" => {
                options.out_dir = PathBuf::from(required_value(&rest, &mut index, flag)?);
            }
            "--xray-rust-bin" => {
                options.xray_rust_bin =
                    Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
            }
            "--xray-core-bin" => {
                options.xray_core_bin =
                    Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
            }
            "--xray-core-dir" => {
                options.xray_core_dir =
                    Some(PathBuf::from(required_value(&rest, &mut index, flag)?));
            }
            "--no-auto-build" => {
                options.no_auto_build = true;
            }
            other => {
                return Err(BenchError::InvalidArguments(format!(
                    "unknown argument `{other}`\n{USAGE}"
                )));
            }
        }
    }

    match command.as_str() {
        "run" => {
            if options.engine.is_none() {
                return Err(BenchError::InvalidArguments(
                    "run requires --engine xray-rust|xray-core".to_owned(),
                ));
            }
            Ok(CliArgs::Run(options))
        }
        "compare" => {
            options.engine = None;
            Ok(CliArgs::Compare(options))
        }
        other => Err(BenchError::InvalidArguments(format!(
            "unknown command `{other}`\n{USAGE}"
        ))),
    }
}

fn required_value<'a>(
    args: &'a [String],
    index: &mut usize,
    flag: &str,
) -> Result<&'a str, BenchError> {
    let Some(value) = args.get(*index) else {
        return Err(BenchError::InvalidArguments(format!(
            "missing value for {flag}"
        )));
    };
    if value.starts_with("--") {
        return Err(BenchError::InvalidArguments(format!(
            "missing value for {flag}"
        )));
    }
    *index += 1;
    Ok(value)
}

fn parse_u64(raw: &str, flag: &str) -> Result<u64, BenchError> {
    raw.parse::<u64>()
        .map_err(|_| BenchError::InvalidArguments(format!("invalid integer `{raw}` for {flag}")))
}

fn parse_usize(raw: &str, flag: &str) -> Result<usize, BenchError> {
    raw.parse::<usize>()
        .map_err(|_| BenchError::InvalidArguments(format!("invalid integer `{raw}` for {flag}")))
}

pub fn parse_ps_sample(raw: &str) -> Result<ProcessSample, BenchError> {
    let fields = raw.split_whitespace().collect::<Vec<_>>();
    if fields.len() < 2 {
        return Err(BenchError::InvalidArguments(format!(
            "invalid ps sample `{raw}`"
        )));
    }
    let rss_kib = fields[0].parse::<u64>().map_err(|_| {
        BenchError::InvalidArguments(format!("invalid ps rss field `{}`", fields[0]))
    })?;
    let cpu_millis = parse_ps_time_to_millis(fields[1])?;
    let threads = fields
        .get(2)
        .map(|raw| {
            raw.parse::<u64>().map_err(|_| {
                BenchError::InvalidArguments(format!("invalid ps thread field `{raw}`"))
            })
        })
        .transpose()?;

    Ok(ProcessSample {
        elapsed_ms: 0,
        rss_kib,
        cpu_millis,
        threads,
    })
}

fn parse_ps_time_to_millis(raw: &str) -> Result<u64, BenchError> {
    let (days, time) = match raw.split_once('-') {
        Some((days, time)) => (
            days.parse::<u64>().map_err(|_| {
                BenchError::InvalidArguments(format!("invalid ps day field `{days}`"))
            })?,
            time,
        ),
        None => (0, raw),
    };
    let parts = time.split(':').collect::<Vec<_>>();
    let (hours, minutes, seconds) = match parts.as_slice() {
        [minutes, seconds] => (0, parse_time_part(minutes)?, parse_seconds(seconds)?),
        [hours, minutes, seconds] => (
            parse_time_part(hours)?,
            parse_time_part(minutes)?,
            parse_seconds(seconds)?,
        ),
        _ => {
            return Err(BenchError::InvalidArguments(format!(
                "invalid ps time field `{raw}`"
            )));
        }
    };

    Ok(days * 24 * 60 * 60 * 1000 + hours * 60 * 60 * 1000 + minutes * 60 * 1000 + seconds)
}

fn parse_time_part(raw: &str) -> Result<u64, BenchError> {
    raw.parse::<u64>()
        .map_err(|_| BenchError::InvalidArguments(format!("invalid ps time component `{raw}`")))
}

fn parse_seconds(raw: &str) -> Result<u64, BenchError> {
    let (whole, fractional) = raw.split_once('.').unwrap_or((raw, ""));
    let whole = parse_time_part(whole)?;
    let mut millis = 0;
    for (index, byte) in fractional.as_bytes().iter().take(3).enumerate() {
        if !byte.is_ascii_digit() {
            return Err(BenchError::InvalidArguments(format!(
                "invalid ps second component `{raw}`"
            )));
        }
        let digit = u64::from(byte - b'0');
        millis += match index {
            0 => digit * 100,
            1 => digit * 10,
            _ => digit,
        };
    }
    Ok(whole * 1000 + millis)
}

pub fn write_result_json(path: &Path, result: &BenchResult) -> Result<(), BenchError> {
    let data = serde_json::to_vec_pretty(result).map_err(|error| {
        BenchError::InvalidArguments(format!("failed to encode result json: {error}"))
    })?;
    fs::write(path, data).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "failed to write result json `{}`: {error}",
            path.display()
        ))
    })
}

pub fn write_samples_csv(path: &Path, samples: &[ProcessSample]) -> Result<(), BenchError> {
    let mut csv = String::from("elapsed_ms,rss_kib,cpu_millis,threads\n");
    for sample in samples {
        let threads = sample
            .threads
            .map(|threads| threads.to_string())
            .unwrap_or_default();
        csv.push_str(&format!(
            "{},{},{},{}\n",
            sample.elapsed_ms, sample.rss_kib, sample.cpu_millis, threads
        ));
    }
    fs::write(path, csv).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "failed to write samples csv `{}`: {error}",
            path.display()
        ))
    })
}

pub async fn run_cli<I, S>(args: I) -> Result<(), BenchError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let _args = parse_cli_args(args)?;
    Err(BenchError::InvalidArguments(
        "benchmark execution is not implemented yet".to_owned(),
    ))
}

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
}

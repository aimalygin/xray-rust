use std::fs;
use std::path::PathBuf;

use crate::{required_value, BenchError, BenchSummary, EngineKind, WorkloadKind, USAGE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChartOptions {
    pub groups: Vec<PathBuf>,
    pub out_dir: PathBuf,
    pub date: String,
    pub hardware: String,
    pub xray_rust_version: String,
    pub xray_core_version: String,
    pub sing_box_version: String,
}

pub fn parse_chart_args(args: &[String]) -> Result<ChartOptions, BenchError> {
    let mut groups = Vec::new();
    let mut out_dir = PathBuf::from("docs/benchmarks/media");
    let mut date = None;
    let mut hardware = None;
    let mut xray_rust_version = None;
    let mut xray_core_version = None;
    let mut sing_box_version = None;

    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--group" => {
                groups.push(PathBuf::from(required_value(args, &mut index, flag)?));
            }
            "--out-dir" => {
                out_dir = PathBuf::from(required_value(args, &mut index, flag)?);
            }
            "--date" => {
                date = Some(required_value(args, &mut index, flag)?.to_owned());
            }
            "--hardware" => {
                hardware = Some(required_value(args, &mut index, flag)?.to_owned());
            }
            "--xray-rust-version" => {
                xray_rust_version = Some(required_value(args, &mut index, flag)?.to_owned());
            }
            "--xray-core-version" => {
                xray_core_version = Some(required_value(args, &mut index, flag)?.to_owned());
            }
            "--sing-box-version" => {
                sing_box_version = Some(required_value(args, &mut index, flag)?.to_owned());
            }
            other => {
                return Err(BenchError::InvalidArguments(format!(
                    "unknown argument `{other}`\n{USAGE}"
                )));
            }
        }
    }

    if groups.is_empty() {
        return Err(BenchError::InvalidArguments(
            "chart requires at least one --group <run-dir>".to_owned(),
        ));
    }
    let required = |value: Option<String>, flag: &str| {
        value.ok_or_else(|| BenchError::InvalidArguments(format!("chart requires {flag} <value>")))
    };
    Ok(ChartOptions {
        groups,
        out_dir,
        date: required(date, "--date")?,
        hardware: required(hardware, "--hardware")?,
        xray_rust_version: required(xray_rust_version, "--xray-rust-version")?,
        xray_core_version: required(xray_core_version, "--xray-core-version")?,
        sing_box_version: required(sing_box_version, "--sing-box-version")?,
    })
}

// wired into run_chart in a follow-up task
#[allow(dead_code)]
fn load_summary(
    groups: &[PathBuf],
    engine: EngineKind,
    workload: WorkloadKind,
) -> Result<BenchSummary, BenchError> {
    let mut found = Vec::new();
    for group in groups {
        let candidate = group
            .join(engine.as_str())
            .join(workload.as_str())
            .join("summary.json");
        if candidate.exists() {
            found.push(candidate);
        }
    }
    let path = match found.as_slice() {
        [] => {
            return Err(BenchError::InvalidArguments(format!(
                "missing summary for {} {}: no --group directory contains {}/{}/summary.json",
                engine.as_str(),
                workload.as_str(),
                engine.as_str(),
                workload.as_str()
            )))
        }
        [path] => path,
        many => {
            return Err(BenchError::InvalidArguments(format!(
                "summary for {} {} found in {} group directories ({}); pass each run group once",
                engine.as_str(),
                workload.as_str(),
                many.len(),
                many.iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )))
        }
    };
    let data = fs::read_to_string(path).map_err(|source| BenchError::Io {
        action: format!("reading benchmark summary `{}`", path.display()),
        source,
    })?;
    let summary: BenchSummary = serde_json::from_str(&data).map_err(|error| {
        BenchError::InvalidArguments(format!(
            "failed to parse summary `{}`: {error}",
            path.display()
        ))
    })?;
    if summary.status != "ok" {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` has status `{}`; charts require status `ok`",
            path.display(),
            summary.status
        )));
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{write_summary_json, MetricSummary};
    use std::path::Path;

    fn args(raw: &[&str]) -> Vec<String> {
        raw.iter().map(|arg| (*arg).to_owned()).collect()
    }

    fn full_args(group: &str) -> Vec<String> {
        args(&[
            "--group",
            group,
            "--date",
            "2026-07-29",
            "--hardware",
            "Apple M4 Pro, 24 GB RAM, macOS 15.5",
            "--xray-rust-version",
            "1659143",
            "--xray-core-version",
            "v26.5.9",
            "--sing-box-version",
            "v1.12.0",
        ])
    }

    fn test_summary(engine: &str, workload: &str, status: &str) -> BenchSummary {
        let metric = MetricSummary {
            min: 1,
            median: 2,
            p95: 3,
        };
        BenchSummary {
            engine: engine.to_owned(),
            workload: workload.to_owned(),
            status: status.to_owned(),
            runs: 5,
            duration_ms: metric.clone(),
            peak_rss_kib: MetricSummary {
                min: 10_240,
                median: 12_288,
                p95: 14_336,
            },
            cpu_millis: metric.clone(),
            cpu_millis_per_gib: Some(metric.clone()),
            throughput_mbps: Some(MetricSummary {
                min: 4000,
                median: 4300,
                p95: 4500,
            }),
            latency_us: None,
            setup_us: None,
            bytes_sent: metric.clone(),
            bytes_received: metric,
            results: Vec::new(),
        }
    }

    fn write_group(root: &Path, engine: &str, workload: &str, status: &str) {
        let dir = root.join(engine).join(workload);
        fs::create_dir_all(&dir).unwrap();
        write_summary_json(
            &dir.join("summary.json"),
            &test_summary(engine, workload, status),
        )
        .unwrap();
    }

    fn temp_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("xray-bench-chart-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn parses_chart_args_with_defaults_and_metadata() {
        let options = parse_chart_args(&full_args("target/benchmarks/123")).unwrap();
        assert_eq!(options.groups, vec![PathBuf::from("target/benchmarks/123")]);
        assert_eq!(options.out_dir, PathBuf::from("docs/benchmarks/media"));
        assert_eq!(options.date, "2026-07-29");
        assert_eq!(options.xray_core_version, "v26.5.9");

        let options = parse_chart_args(&args(&[
            "--group",
            "a",
            "--group",
            "b",
            "--out-dir",
            "custom",
            "--date",
            "2026-07-29",
            "--hardware",
            "Apple M4 Pro, 24 GB RAM, macOS 15.5",
            "--xray-rust-version",
            "1659143",
            "--xray-core-version",
            "v26.5.9",
            "--sing-box-version",
            "v1.12.0",
        ]))
        .unwrap();
        assert_eq!(options.groups.len(), 2);
        assert_eq!(options.out_dir, PathBuf::from("custom"));
    }

    #[test]
    fn chart_args_require_group_and_metadata() {
        let error = parse_chart_args(&args(&["--date", "2026-07-29"])).unwrap_err();
        assert!(error.to_string().contains("at least one --group"));

        let error = parse_chart_args(&args(&["--group", "target/benchmarks/123"])).unwrap_err();
        assert!(error.to_string().contains("chart requires --date"));
    }

    #[test]
    fn load_summary_reads_single_group() {
        let root = temp_root("load-ok");
        write_group(&root, "xray-rust", "idle", "ok");

        let summary = load_summary(
            std::slice::from_ref(&root),
            EngineKind::XrayRust,
            WorkloadKind::Idle,
        )
        .unwrap();

        assert_eq!(summary.engine, "xray-rust");
        assert_eq!(summary.runs, 5);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_summary_rejects_missing_and_non_ok() {
        let root = temp_root("load-bad");
        write_group(&root, "xray-rust", "idle", "mixed");

        let error = load_summary(
            std::slice::from_ref(&root),
            EngineKind::XrayCore,
            WorkloadKind::Idle,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("missing summary for xray-core idle"));

        let error = load_summary(
            std::slice::from_ref(&root),
            EngineKind::XrayRust,
            WorkloadKind::Idle,
        )
        .unwrap_err();
        assert!(error.to_string().contains("charts require status `ok`"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_summary_rejects_duplicate_groups() {
        let root = temp_root("load-dup");
        write_group(&root, "xray-rust", "idle", "ok");

        let groups = vec![root.clone(), root.clone()];
        let error = load_summary(&groups, EngineKind::XrayRust, WorkloadKind::Idle).unwrap_err();

        assert!(error.to_string().contains("found in 2 group directories"));
        fs::remove_dir_all(&root).unwrap();
    }
}

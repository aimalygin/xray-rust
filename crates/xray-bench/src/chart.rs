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

pub(crate) struct Theme {
    name: &'static str,
    surface: &'static str,
    ink_primary: &'static str,
    ink_secondary: &'static str,
    ink_muted: &'static str,
    gridline: &'static str,
    baseline: &'static str,
    series: [&'static str; 3],
}

pub(crate) const LIGHT: Theme = Theme {
    name: "light",
    surface: "#fcfcfb",
    ink_primary: "#0b0b0b",
    ink_secondary: "#52514e",
    ink_muted: "#898781",
    gridline: "#e1e0d9",
    baseline: "#c3c2b7",
    series: ["#2a78d6", "#eb6834", "#1baf7a"],
};

pub(crate) const DARK: Theme = Theme {
    name: "dark",
    surface: "#1a1a19",
    ink_primary: "#ffffff",
    ink_secondary: "#c3c2b7",
    ink_muted: "#898781",
    gridline: "#2c2c2a",
    baseline: "#383835",
    series: ["#3987e5", "#d95926", "#199e70"],
};

const SERIES_LABELS: [&str; 3] = ["xray-rust", "Xray-core", "sing-box"];
const FONT_FAMILY: &str = "system-ui, -apple-system, 'Segoe UI', sans-serif";

const CANVAS_WIDTH: f64 = 760.0;
const CANVAS_HEIGHT: f64 = 440.0;
const PLOT_LEFT: f64 = 64.0;
const PLOT_RIGHT: f64 = 736.0;
const PLOT_TOP: f64 = 92.0;
const PLOT_BOTTOM: f64 = 330.0;
const BAR_WIDTH: f64 = 44.0;
const BAR_GAP: f64 = 2.0;

pub(crate) struct Bar {
    pub series: usize,
    pub value: f64,
    pub lo: f64,
    pub hi: f64,
}

pub(crate) struct BarGroup {
    pub label: String,
    pub bars: Vec<Bar>,
}

pub(crate) struct ChartSpec {
    pub title: String,
    pub groups: Vec<BarGroup>,
}

pub(crate) struct Footer {
    pub date: String,
    pub hardware: String,
    pub runs_label: String,
    pub xray_rust_version: String,
    pub xray_core_version: String,
    pub sing_box_version: String,
}

fn escape_xml(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn format_value(value: f64) -> String {
    if value >= 100.0 {
        format!("{value:.0}")
    } else if value >= 10.0 {
        format!("{value:.1}")
    } else {
        format!("{value:.2}")
    }
}

fn nice_axis_max(raw_max: f64) -> f64 {
    if raw_max <= 0.0 {
        return 1.0;
    }
    let raw_step = raw_max / 4.0;
    let magnitude = 10f64.powf(raw_step.log10().floor());
    let residual = raw_step / magnitude;
    let step = if residual <= 1.0 {
        magnitude
    } else if residual <= 1.5 {
        1.5 * magnitude
    } else if residual <= 2.0 {
        2.0 * magnitude
    } else if residual <= 2.5 {
        2.5 * magnitude
    } else if residual <= 5.0 {
        5.0 * magnitude
    } else {
        10.0 * magnitude
    };
    step * 4.0
}

fn bar_path(x: f64, y_top: f64, width: f64, height: f64) -> String {
    let radius = 4.0_f64.min(height / 2.0).min(width / 2.0);
    let bottom = y_top + height;
    let right = x + width;
    let shoulder = y_top + radius;
    format!(
        "M {x:.2} {bottom:.2} L {x:.2} {shoulder:.2} Q {x:.2} {y_top:.2} {left_arc:.2} {y_top:.2} L {right_arc:.2} {y_top:.2} Q {right:.2} {y_top:.2} {right:.2} {shoulder:.2} L {right:.2} {bottom:.2} Z",
        left_arc = x + radius,
        right_arc = right - radius,
    )
}

pub(crate) fn render_bar_chart(spec: &ChartSpec, theme: &Theme, footer: &Footer) -> String {
    let axis_max = nice_axis_max(
        spec.groups
            .iter()
            .flat_map(|group| group.bars.iter())
            .map(|bar| bar.hi.max(bar.value))
            .fold(0.0, f64::max),
    );
    let scale = |value: f64| PLOT_BOTTOM - (value / axis_max) * (PLOT_BOTTOM - PLOT_TOP);

    let mut svg = String::new();
    svg.push_str(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{CANVAS_WIDTH:.0}" height="{CANVAS_HEIGHT:.0}" viewBox="0 0 {CANVAS_WIDTH:.0} {CANVAS_HEIGHT:.0}" role="img" aria-label="{title}">
<rect width="{CANVAS_WIDTH:.0}" height="{CANVAS_HEIGHT:.0}" fill="{surface}" rx="8"/>
<text x="24" y="34" font-family="{FONT_FAMILY}" font-size="17" font-weight="600" fill="{ink}">{title}</text>
"#,
        title = escape_xml(&spec.title),
        surface = theme.surface,
        ink = theme.ink_primary,
    ));

    let mut legend_x = 24.0;
    for (index, label) in SERIES_LABELS.iter().enumerate() {
        svg.push_str(&format!(
            r#"<rect x="{legend_x:.2}" y="52" width="12" height="12" rx="3" fill="{color}"/>
<text x="{text_x:.2}" y="62" font-family="{FONT_FAMILY}" font-size="12.5" fill="{ink}">{label}</text>
"#,
            color = theme.series[index],
            text_x = legend_x + 18.0,
            ink = theme.ink_secondary,
        ));
        legend_x += 18.0 + 8.0 * label.len() as f64 + 24.0;
    }

    for tick in 0..=4 {
        let value = axis_max * tick as f64 / 4.0;
        let y = scale(value);
        if tick > 0 {
            svg.push_str(&format!(
                r#"<line x1="{PLOT_LEFT:.0}" y1="{y:.2}" x2="{PLOT_RIGHT:.0}" y2="{y:.2}" stroke="{grid}" stroke-width="1"/>
"#,
                grid = theme.gridline,
            ));
        }
        svg.push_str(&format!(
            r#"<text x="{tick_x:.0}" y="{label_y:.2}" font-family="{FONT_FAMILY}" font-size="11" fill="{muted}" text-anchor="end">{label}</text>
"#,
            tick_x = PLOT_LEFT - 10.0,
            label_y = y + 4.0,
            muted = theme.ink_muted,
            label = format_value(value),
        ));
    }
    svg.push_str(&format!(
        r#"<line x1="{PLOT_LEFT:.0}" y1="{PLOT_BOTTOM:.0}" x2="{PLOT_RIGHT:.0}" y2="{PLOT_BOTTOM:.0}" stroke="{baseline}" stroke-width="1"/>
"#,
        baseline = theme.baseline,
    ));

    let group_count = spec.groups.len() as f64;
    let group_span = (PLOT_RIGHT - PLOT_LEFT) / group_count;
    for (group_index, group) in spec.groups.iter().enumerate() {
        let bar_count = group.bars.len() as f64;
        let cluster_width = bar_count * BAR_WIDTH + (bar_count - 1.0) * BAR_GAP;
        let cluster_left =
            PLOT_LEFT + group_span * group_index as f64 + (group_span - cluster_width) / 2.0;
        for (bar_index, bar) in group.bars.iter().enumerate() {
            let x = cluster_left + bar_index as f64 * (BAR_WIDTH + BAR_GAP);
            let y_top = scale(bar.value);
            svg.push_str(&format!(
                r#"<path d="{path}" fill="{color}"/>
"#,
                path = bar_path(x, y_top, BAR_WIDTH, PLOT_BOTTOM - y_top),
                color = theme.series[bar.series],
            ));
            let center = x + BAR_WIDTH / 2.0;
            let y_lo = scale(bar.lo);
            let y_hi = scale(bar.hi);
            svg.push_str(&format!(
                r#"<line x1="{center:.2}" y1="{y_lo:.2}" x2="{center:.2}" y2="{y_hi:.2}" stroke="{ink}" stroke-width="1.5"/>
<line x1="{cap_left:.2}" y1="{y_lo:.2}" x2="{cap_right:.2}" y2="{y_lo:.2}" stroke="{ink}" stroke-width="1.5"/>
<line x1="{cap_left:.2}" y1="{y_hi:.2}" x2="{cap_right:.2}" y2="{y_hi:.2}" stroke="{ink}" stroke-width="1.5"/>
"#,
                ink = theme.ink_secondary,
                cap_left = center - 5.0,
                cap_right = center + 5.0,
            ));
            svg.push_str(&format!(
                r#"<text x="{center:.2}" y="{label_y:.2}" font-family="{FONT_FAMILY}" font-size="12" font-weight="600" fill="{ink}" text-anchor="middle">{label}</text>
"#,
                label_y = y_hi.min(y_top) - 8.0,
                ink = theme.ink_primary,
                label = format_value(bar.value),
            ));
        }
        svg.push_str(&format!(
            r#"<text x="{group_center:.2}" y="{label_y:.0}" font-family="{FONT_FAMILY}" font-size="12.5" fill="{ink}" text-anchor="middle">{label}</text>
"#,
            group_center = PLOT_LEFT + group_span * (group_index as f64 + 0.5),
            label_y = PLOT_BOTTOM + 24.0,
            ink = theme.ink_secondary,
            label = escape_xml(&group.label),
        ));
    }

    svg.push_str(&format!(
        r#"<text x="24" y="404" font-family="{FONT_FAMILY}" font-size="11" fill="{muted}">{line}</text>
"#,
        muted = theme.ink_muted,
        line = escape_xml(&format!(
            "{} · {} · runs={} · synthetic localhost benchmark",
            footer.date, footer.hardware, footer.runs_label
        )),
    ));
    svg.push_str(&format!(
        r#"<text x="24" y="422" font-family="{FONT_FAMILY}" font-size="11" fill="{muted}">{line}</text>
</svg>
"#,
        muted = theme.ink_muted,
        line = escape_xml(&format!(
            "xray-rust {} · Xray-core {} · sing-box {}",
            footer.xray_rust_version, footer.xray_core_version, footer.sing_box_version
        )),
    ));
    svg
}

struct LoadedSummaries {
    entries: Vec<((EngineKind, WorkloadKind), BenchSummary)>,
}

impl LoadedSummaries {
    fn get(&self, engine: EngineKind, workload: WorkloadKind) -> &BenchSummary {
        &self
            .entries
            .iter()
            .find(|((e, w), _)| *e == engine && *w == workload)
            .expect("summary loaded for every charted engine/workload pair")
            .1
    }
}

const ENGINES: [EngineKind; 3] = [
    EngineKind::XrayRust,
    EngineKind::XrayCore,
    EngineKind::SingBox,
];

const CHART_WORKLOADS: [WorkloadKind; 5] = [
    WorkloadKind::Idle,
    WorkloadKind::ManyIdleFlows,
    WorkloadKind::TcpFreedom,
    WorkloadKind::RealityVisionXudp,
    WorkloadKind::TcpBulkThroughput,
];

fn metric_bar(metric: &crate::MetricSummary, series: usize, divisor: f64) -> Bar {
    Bar {
        series,
        value: metric.median as f64 / divisor,
        lo: metric.min as f64 / divisor,
        hi: metric.p95 as f64 / divisor,
    }
}

fn rss_group(loaded: &LoadedSummaries, workload: WorkloadKind) -> BarGroup {
    BarGroup {
        label: workload.as_str().to_owned(),
        bars: ENGINES
            .iter()
            .enumerate()
            .map(|(series, engine)| {
                metric_bar(&loaded.get(*engine, workload).peak_rss_kib, series, 1024.0)
            })
            .collect(),
    }
}

fn latency_group(loaded: &LoadedSummaries, workload: WorkloadKind) -> Result<BarGroup, BenchError> {
    let bars = ENGINES
        .iter()
        .enumerate()
        .map(|(series, engine)| {
            let summary = loaded.get(*engine, workload);
            let latency = summary.latency_us.as_ref().ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "summary for {} {} has no latency data",
                    engine.as_str(),
                    workload.as_str()
                ))
            })?;
            // Bar: median of per-run medians. Whisker: min run median up to
            // the median of per-run p95s.
            Ok(Bar {
                series,
                value: latency.median.median as f64,
                lo: latency.median.min as f64,
                hi: latency.p95.median as f64,
            })
        })
        .collect::<Result<Vec<_>, BenchError>>()?;
    Ok(BarGroup {
        label: workload.as_str().to_owned(),
        bars,
    })
}

fn optional_metric_group(
    loaded: &LoadedSummaries,
    workload: WorkloadKind,
    metric_name: &str,
    select: impl Fn(&BenchSummary) -> Option<&crate::MetricSummary>,
    divisor: f64,
) -> Result<BarGroup, BenchError> {
    let bars = ENGINES
        .iter()
        .enumerate()
        .map(|(series, engine)| {
            let summary = loaded.get(*engine, workload);
            let metric = select(summary).ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "summary for {} {} has no {metric_name} data",
                    engine.as_str(),
                    workload.as_str()
                ))
            })?;
            Ok(metric_bar(metric, series, divisor))
        })
        .collect::<Result<Vec<_>, BenchError>>()?;
    Ok(BarGroup {
        label: workload.as_str().to_owned(),
        bars,
    })
}

pub fn run_chart(options: &ChartOptions) -> Result<(), BenchError> {
    let mut entries = Vec::new();
    for engine in ENGINES {
        for workload in CHART_WORKLOADS {
            let summary = load_summary(&options.groups, engine, workload)?;
            entries.push(((engine, workload), summary));
        }
    }
    let loaded = LoadedSummaries { entries };

    let runs: Vec<usize> = loaded.entries.iter().map(|(_, s)| s.runs).collect();
    let runs_label = if runs.windows(2).all(|pair| pair[0] == pair[1]) {
        runs[0].to_string()
    } else {
        eprintln!("warning: run counts differ across summaries; footer will say runs=varies");
        "varies".to_owned()
    };
    let footer = Footer {
        date: options.date.clone(),
        hardware: options.hardware.clone(),
        runs_label,
        xray_rust_version: options.xray_rust_version.clone(),
        xray_core_version: options.xray_core_version.clone(),
        sing_box_version: options.sing_box_version.clone(),
    };

    let charts: Vec<(&str, ChartSpec)> = vec![
        (
            "memory-rss",
            ChartSpec {
                title: "Peak resident set size — MiB (lower is better)".to_owned(),
                groups: vec![
                    rss_group(&loaded, WorkloadKind::Idle),
                    rss_group(&loaded, WorkloadKind::ManyIdleFlows),
                ],
            },
        ),
        (
            "latency",
            ChartSpec {
                title: "Round-trip latency — µs, median with p95 whisker (lower is better)"
                    .to_owned(),
                groups: vec![
                    latency_group(&loaded, WorkloadKind::TcpFreedom)?,
                    latency_group(&loaded, WorkloadKind::RealityVisionXudp)?,
                ],
            },
        ),
        (
            "throughput",
            ChartSpec {
                title: "Bulk TCP throughput — Gbps (higher is better)".to_owned(),
                groups: vec![optional_metric_group(
                    &loaded,
                    WorkloadKind::TcpBulkThroughput,
                    "throughput",
                    |summary| summary.throughput_mbps.as_ref(),
                    1000.0,
                )?],
            },
        ),
        (
            "cpu-per-gib",
            ChartSpec {
                title: "CPU cost — milliseconds per GiB transferred (lower is better)".to_owned(),
                groups: vec![optional_metric_group(
                    &loaded,
                    WorkloadKind::TcpBulkThroughput,
                    "cpu-per-GiB",
                    |summary| summary.cpu_millis_per_gib.as_ref(),
                    1.0,
                )?],
            },
        ),
    ];

    fs::create_dir_all(&options.out_dir).map_err(|source| BenchError::Io {
        action: format!("creating chart directory `{}`", options.out_dir.display()),
        source,
    })?;
    for (stem, spec) in &charts {
        for theme in [&LIGHT, &DARK] {
            let svg = render_bar_chart(spec, theme, &footer);
            let path = options.out_dir.join(format!("{stem}-{}.svg", theme.name));
            fs::write(&path, svg).map_err(|source| BenchError::Io {
                action: format!("writing chart `{}`", path.display()),
                source,
            })?;
            println!("wrote {}", path.display());
        }
    }
    Ok(())
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
            connections: 0,
            iterations: 0,
            payload_size: 0,
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

    fn write_full_group(root: &Path) {
        for engine in ["xray-rust", "xray-core", "sing-box"] {
            for workload in [
                "idle",
                "many-idle-flows",
                "tcp-freedom",
                "reality-vision-xudp",
                "tcp-bulk-throughput",
            ] {
                let mut summary = test_summary(engine, workload, "ok");
                if matches!(workload, "tcp-freedom" | "reality-vision-xudp") {
                    let metric = MetricSummary {
                        min: 90,
                        median: 130,
                        p95: 200,
                    };
                    summary.latency_us = Some(crate::LatencySummaryAggregate {
                        min: metric.clone(),
                        median: metric.clone(),
                        p95: MetricSummary {
                            min: 800,
                            median: 1400,
                            p95: 2100,
                        },
                        p99: metric,
                    });
                }
                let dir = root.join(engine).join(workload);
                fs::create_dir_all(&dir).unwrap();
                write_summary_json(&dir.join("summary.json"), &summary).unwrap();
            }
        }
    }

    #[test]
    fn run_chart_writes_eight_theme_files() {
        let root = temp_root("e2e");
        write_full_group(&root);
        let out_dir = root.join("media");
        let mut options = parse_chart_args(&full_args(root.to_str().unwrap())).unwrap();
        options.out_dir = out_dir.clone();

        run_chart(&options).unwrap();

        for (stem, title_fragment) in [
            ("memory-rss", "Peak resident set size"),
            ("latency", "Round-trip latency"),
            ("throughput", "Bulk TCP throughput"),
            ("cpu-per-gib", "CPU cost"),
        ] {
            for theme in ["light", "dark"] {
                let path = out_dir.join(format!("{stem}-{theme}.svg"));
                let svg = fs::read_to_string(&path).unwrap();
                assert!(svg.contains(title_fragment), "{stem}-{theme}");
                assert!(
                    svg.contains("synthetic localhost benchmark"),
                    "{stem}-{theme}"
                );
                assert!(svg.contains("runs=5"), "{stem}-{theme}");
            }
        }

        let memory = fs::read_to_string(out_dir.join("memory-rss-light.svg")).unwrap();
        assert!(memory.contains(">12.0<"));
        let throughput = fs::read_to_string(out_dir.join("throughput-light.svg")).unwrap();
        assert!(throughput.contains(">4.30<"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn run_chart_fails_on_missing_latency() {
        let root = temp_root("no-latency");
        write_full_group(&root);
        let broken = test_summary("xray-rust", "tcp-freedom", "ok");
        write_summary_json(&root.join("xray-rust/tcp-freedom/summary.json"), &broken).unwrap();
        let mut options = parse_chart_args(&full_args(root.to_str().unwrap())).unwrap();
        options.out_dir = root.join("media");

        let error = run_chart(&options).unwrap_err();

        assert!(error.to_string().contains("no latency data"));
        assert!(!options.out_dir.exists());
        fs::remove_dir_all(&root).unwrap();
    }

    fn fixture_spec() -> ChartSpec {
        ChartSpec {
            title: "Peak resident set size — MiB (lower is better)".to_owned(),
            groups: vec![
                BarGroup {
                    label: "idle".to_owned(),
                    bars: vec![
                        Bar {
                            series: 0,
                            value: 9.4,
                            lo: 9.1,
                            hi: 10.2,
                        },
                        Bar {
                            series: 1,
                            value: 29.8,
                            lo: 28.4,
                            hi: 31.0,
                        },
                        Bar {
                            series: 2,
                            value: 21.5,
                            lo: 20.9,
                            hi: 22.6,
                        },
                    ],
                },
                BarGroup {
                    label: "many-idle-flows".to_owned(),
                    bars: vec![
                        Bar {
                            series: 0,
                            value: 12.1,
                            lo: 11.8,
                            hi: 13.0,
                        },
                        Bar {
                            series: 1,
                            value: 41.3,
                            lo: 39.6,
                            hi: 44.2,
                        },
                        Bar {
                            series: 2,
                            value: 30.2,
                            lo: 29.5,
                            hi: 31.8,
                        },
                    ],
                },
            ],
        }
    }

    fn fixture_footer() -> Footer {
        Footer {
            date: "2026-07-29".to_owned(),
            hardware: "Apple M4 Pro, 24 GB RAM, macOS 15.5".to_owned(),
            runs_label: "5".to_owned(),
            xray_rust_version: "1659143".to_owned(),
            xray_core_version: "v26.5.9".to_owned(),
            sing_box_version: "v1.12.0".to_owned(),
        }
    }

    fn assert_matches_golden(name: &str, actual: &str) {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/chart")
            .join(name);
        if std::env::var_os("UPDATE_CHART_GOLDENS").is_some() {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, actual).unwrap();
            return;
        }
        let expected = fs::read_to_string(&path).unwrap_or_else(|_| {
            panic!(
                "missing golden `{}`; run with UPDATE_CHART_GOLDENS=1 to create it",
                path.display()
            )
        });
        assert_eq!(
            actual, &expected,
            "golden mismatch for {name}; rerun with UPDATE_CHART_GOLDENS=1 and review the diff"
        );
    }

    #[test]
    fn renders_light_and_dark_goldens() {
        let spec = fixture_spec();
        let footer = fixture_footer();
        assert_matches_golden(
            "memory-rss-light.svg",
            &render_bar_chart(&spec, &LIGHT, &footer),
        );
        assert_matches_golden(
            "memory-rss-dark.svg",
            &render_bar_chart(&spec, &DARK, &footer),
        );
    }

    #[test]
    fn rendering_is_deterministic() {
        let spec = fixture_spec();
        let footer = fixture_footer();
        let first = render_bar_chart(&spec, &LIGHT, &footer);
        let second = render_bar_chart(&spec, &LIGHT, &footer);
        assert_eq!(first, second);
    }

    #[test]
    fn svg_contains_labels_and_footer_metadata() {
        let svg = render_bar_chart(&fixture_spec(), &LIGHT, &fixture_footer());
        assert!(svg.contains("Peak resident set size"));
        assert!(svg.contains("xray-rust"));
        assert!(svg.contains("sing-box"));
        assert!(svg.contains("synthetic localhost benchmark"));
        assert!(svg.contains("runs=5"));
        assert!(svg.contains("Xray-core v26.5.9"));
        assert!(svg.contains("29.8"));
    }

    #[test]
    fn escapes_metadata_in_footer() {
        let mut footer = fixture_footer();
        footer.hardware = "Mac <mini> & friends".to_owned();
        let svg = render_bar_chart(&fixture_spec(), &LIGHT, &footer);
        assert!(svg.contains("Mac &lt;mini&gt; &amp; friends"));
        assert!(!svg.contains("<mini>"));
    }
}

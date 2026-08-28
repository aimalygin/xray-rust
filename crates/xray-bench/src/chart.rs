use std::fs;
use std::path::PathBuf;

use crate::{required_value, BenchError, BenchSummary, EngineKind, WorkloadKind, USAGE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChartOptions {
    pub groups: Vec<PathBuf>,
    pub dns_groups: Vec<PathBuf>,
    pub out_dir: PathBuf,
    pub date: String,
    pub hardware: String,
    pub xray_rust_version: String,
    pub xray_core_version: String,
    pub sing_box_version: String,
    pub geodata_version: Option<String>,
}

pub fn parse_chart_args(args: &[String]) -> Result<ChartOptions, BenchError> {
    let mut groups = Vec::new();
    let mut dns_groups = Vec::new();
    let mut out_dir = PathBuf::from("docs/benchmarks/media");
    let mut date = None;
    let mut hardware = None;
    let mut xray_rust_version = None;
    let mut xray_core_version = None;
    let mut sing_box_version = None;
    let mut geodata_version = None;

    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        match flag {
            "--group" => {
                groups.push(PathBuf::from(required_value(args, &mut index, flag)?));
            }
            "--dns-group" => {
                dns_groups.push(PathBuf::from(required_value(args, &mut index, flag)?));
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
            "--geodata-version" => {
                geodata_version = Some(required_value(args, &mut index, flag)?.to_owned());
            }
            other => {
                return Err(BenchError::InvalidArguments(format!(
                    "unknown argument `{other}`\n{USAGE}"
                )));
            }
        }
    }

    if groups.is_empty() && dns_groups.is_empty() {
        return Err(BenchError::InvalidArguments(
            "chart requires at least one --group <run-dir> or --dns-group <run-dir>".to_owned(),
        ));
    }
    let required = |value: Option<String>, flag: &str| {
        value.ok_or_else(|| BenchError::InvalidArguments(format!("chart requires {flag} <value>")))
    };
    let has_comparison_groups = !groups.is_empty();
    Ok(ChartOptions {
        groups,
        dns_groups,
        out_dir,
        date: required(date, "--date")?,
        hardware: required(hardware, "--hardware")?,
        xray_rust_version: required(xray_rust_version, "--xray-rust-version")?,
        xray_core_version: if has_comparison_groups {
            required(xray_core_version, "--xray-core-version")?
        } else {
            xray_core_version.unwrap_or_default()
        },
        sing_box_version: if has_comparison_groups {
            required(sing_box_version, "--sing-box-version")?
        } else {
            sing_box_version.unwrap_or_default()
        },
        geodata_version,
    })
}

// connections filter: Some(n) selects summaries whose recorded connection
// count matches; summaries with connections == 0 are pre-params legacy data
// (the CLI rejects 0 for real runs) and only match when no filter is given.
fn load_summary(
    groups: &[PathBuf],
    engine: EngineKind,
    workload: WorkloadKind,
    connections: Option<u64>,
) -> Result<BenchSummary, BenchError> {
    let mut candidates = Vec::new();
    let mut rejected_connections = Vec::new();
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
                rejected_connections.push(summary.connections);
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
            let found_note = if rejected_connections.is_empty() {
                String::new()
            } else {
                let mut found = rejected_connections.clone();
                found.sort_unstable();
                found.dedup();
                format!(
                    " (found summaries with connections={})",
                    found
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            return Err(BenchError::InvalidArguments(format!(
                "missing summary for {} {}{filter_note}: no --group directory contains a matching {}/{}/summary.json{found_note}",
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

const SERIES_LABELS_ALL: [&str; 3] = ["xray-rust", "Xray-core", "sing-box"];
const SERIES_LABELS_GEO: [&str; 2] = ["xray-rust", "Xray-core"];
const GEO_ENGINES: [EngineKind; 2] = [EngineKind::XrayRust, EngineKind::XrayCore];
const FONT_FAMILY: &str = "system-ui, -apple-system, 'Segoe UI', sans-serif";

const CANVAS_WIDTH: f64 = 760.0;
const CANVAS_HEIGHT: f64 = 440.0;
const PLOT_LEFT: f64 = 64.0;
const PLOT_RIGHT: f64 = 736.0;
const PLOT_TOP: f64 = 92.0;
const PLOT_BOTTOM: f64 = 330.0;
const BAR_WIDTH: f64 = 44.0;
const BAR_GAP: f64 = 2.0;

#[derive(Debug)]
pub(crate) struct Bar {
    pub series: usize,
    pub value: f64,
    pub lo: f64,
    pub hi: f64,
}

#[derive(Debug)]
pub(crate) struct BarGroup {
    pub label: String,
    pub bars: Vec<Bar>,
}

pub(crate) struct ChartSpec {
    pub title: String,
    pub series_labels: &'static [&'static str],
    pub groups: Vec<BarGroup>,
    pub note: Option<String>,
}

pub(crate) struct Footer {
    pub date: String,
    pub hardware: String,
    pub runs_label: String,
    pub xray_rust_version: String,
    pub xray_core_version: String,
    pub sing_box_version: String,
    pub geodata: Option<String>,
    pub comparison_versions: bool,
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
    for (index, label) in spec.series_labels.iter().enumerate() {
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

    if let Some(note) = &spec.note {
        svg.push_str(&format!(
            r#"<text x="24" y="386" font-family="{FONT_FAMILY}" font-size="11" fill="{muted}">{note}</text>
"#,
            muted = theme.ink_muted,
            note = escape_xml(note),
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
        line = escape_xml(&if footer.comparison_versions {
            match &footer.geodata {
                Some(geodata) => format!(
                    "xray-rust {} · Xray-core {} · sing-box {} · geodata {}",
                    footer.xray_rust_version,
                    footer.xray_core_version,
                    footer.sing_box_version,
                    geodata
                ),
                None => format!(
                    "xray-rust {} · Xray-core {} · sing-box {}",
                    footer.xray_rust_version, footer.xray_core_version, footer.sing_box_version
                ),
            }
        } else {
            format!("xray-rust {}", footer.xray_rust_version)
        }),
    ));
    svg
}

type SummaryKey = (EngineKind, WorkloadKind, Option<u64>);

struct LoadedSummaries {
    entries: Vec<(SummaryKey, BenchSummary)>,
}

impl LoadedSummaries {
    fn get(
        &self,
        engine: EngineKind,
        workload: WorkloadKind,
        connections: Option<u64>,
    ) -> &BenchSummary {
        &self
            .entries
            .iter()
            .find(|((e, w, c), _)| *e == engine && *w == workload && *c == connections)
            .expect("summary loaded for every charted engine/workload/connections triple")
            .1
    }
}

const ENGINES: [EngineKind; 3] = [
    EngineKind::XrayRust,
    EngineKind::XrayCore,
    EngineKind::SingBox,
];

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

const DNS_SERIES_LABELS: [&str; 2] = ["UDP client", "TCP client"];
const DNS_CLIENTS: [DnsClient; 2] = [DnsClient::Udp, DnsClient::Tcp];
const DNS_SCENARIOS: [DnsScenario; 4] = [
    DnsScenario::FakeDns,
    DnsScenario::Classic,
    DnsScenario::TcpRouted,
    DnsScenario::TcpLocal,
];
const DNS_WORKLOADS: [WorkloadKind; 3] = [
    WorkloadKind::TunFakeDns,
    WorkloadKind::TunFakeDnsTcp,
    WorkloadKind::TunDnsProxy,
];
const DNS_CHART_NOTE: &str = "Hybrid A + HTTPS queries · cache-warmed fixture";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsClient {
    Udp,
    Tcp,
}

impl DnsClient {
    fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
        }
    }

    fn series(self) -> usize {
        match self {
            Self::Udp => 0,
            Self::Tcp => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsScenario {
    FakeDns,
    Classic,
    TcpRouted,
    TcpLocal,
}

impl DnsScenario {
    fn label(self) -> &'static str {
        match self {
            Self::FakeDns => "FakeDNS",
            Self::Classic => "classic",
            Self::TcpRouted => "tcp-routed",
            Self::TcpLocal => "tcp-local",
        }
    }

    fn upstream(self) -> Option<&'static str> {
        match self {
            Self::FakeDns => None,
            Self::Classic => Some("classic"),
            Self::TcpRouted => Some("tcp-routed"),
            Self::TcpLocal => Some("tcp-local"),
        }
    }

    fn workload(self, client: DnsClient) -> WorkloadKind {
        match (self, client) {
            (Self::FakeDns, DnsClient::Udp) => WorkloadKind::TunFakeDns,
            (Self::FakeDns, DnsClient::Tcp) => WorkloadKind::TunFakeDnsTcp,
            _ => WorkloadKind::TunDnsProxy,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DnsSummaryKey {
    scenario: DnsScenario,
    client: DnsClient,
}

impl DnsSummaryKey {
    fn label(self) -> String {
        format!("{}/{}", self.scenario.label(), self.client.as_str())
    }
}

#[derive(Debug)]
struct LoadedDnsSummaries {
    entries: Vec<(DnsSummaryKey, PathBuf, BenchSummary)>,
}

impl LoadedDnsSummaries {
    fn get(&self, scenario: DnsScenario, client: DnsClient) -> &BenchSummary {
        &self
            .entries
            .iter()
            .find(|(key, _, _)| key.scenario == scenario && key.client == client)
            .expect("validated DNS chart input contains every scenario/client pair")
            .2
    }
}

fn parse_dns_client(path: &std::path::Path, raw: Option<&str>) -> Result<DnsClient, BenchError> {
    match raw {
        Some("udp") => Ok(DnsClient::Udp),
        Some("tcp") => Ok(DnsClient::Tcp),
        Some("both") => Err(BenchError::InvalidArguments(format!(
            "summary `{}` uses dns_transport=both; published DNS charts require separated UDP and TCP client runs",
            path.display()
        ))),
        Some(other) => Err(BenchError::InvalidArguments(format!(
            "summary `{}` has unsupported dns_transport `{other}`; expected `udp` or `tcp`",
            path.display()
        ))),
        None => Err(BenchError::InvalidArguments(format!(
            "summary `{}` is missing dns_transport; rerun it with the current benchmark harness",
            path.display()
        ))),
    }
}

fn dns_summary_key(
    path: &std::path::Path,
    workload: WorkloadKind,
    summary: &BenchSummary,
) -> Result<DnsSummaryKey, BenchError> {
    let client = parse_dns_client(path, summary.dns_transport.as_deref())?;
    let scenario = match workload {
        WorkloadKind::TunFakeDns => {
            if client != DnsClient::Udp || summary.dns_upstream_transport.is_some() {
                return Err(BenchError::InvalidArguments(format!(
                    "summary `{}` has mismatched tun-fake-dns semantics; expected dns_transport=udp and no dns_upstream_transport",
                    path.display()
                )));
            }
            DnsScenario::FakeDns
        }
        WorkloadKind::TunFakeDnsTcp => {
            if client != DnsClient::Tcp || summary.dns_upstream_transport.is_some() {
                return Err(BenchError::InvalidArguments(format!(
                    "summary `{}` has mismatched tun-fake-dns-tcp semantics; expected dns_transport=tcp and no dns_upstream_transport",
                    path.display()
                )));
            }
            DnsScenario::FakeDns
        }
        WorkloadKind::TunDnsProxy => match summary.dns_upstream_transport.as_deref() {
            Some("classic") => DnsScenario::Classic,
            Some("tcp-routed") => DnsScenario::TcpRouted,
            Some("tcp-local") => DnsScenario::TcpLocal,
            Some(other) => {
                return Err(BenchError::InvalidArguments(format!(
                    "summary `{}` has unsupported dns_upstream_transport `{other}`",
                    path.display()
                )))
            }
            None => {
                return Err(BenchError::InvalidArguments(format!(
                    "summary `{}` is missing dns_upstream_transport",
                    path.display()
                )))
            }
        },
        _ => unreachable!("caller scans only DNS chart workloads"),
    };
    Ok(DnsSummaryKey { scenario, client })
}

fn dns_query_count(result: &crate::BenchResult) -> Result<u128, BenchError> {
    u128::from(result.connections)
        .checked_mul(u128::from(result.iterations))
        .and_then(|count| count.checked_mul(2))
        .ok_or_else(|| {
            BenchError::InvalidArguments(
                "DNS query count overflowed while calculating 2*connections*iterations".to_owned(),
            )
        })
}

const DNS_SCENARIO_INVOCATION_FLAGS: [&str; 3] =
    ["--workload", "--transport", "--dns-upstream-transport"];

fn normalized_dns_invocation_args(
    path: &std::path::Path,
    args: &[String],
) -> Result<Vec<String>, BenchError> {
    if args.is_empty() {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` has empty provenance.invocation_args; published DNS charts require canonical replay arguments",
            path.display()
        )));
    }
    if args.first().map(String::as_str) != Some("run") {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` has non-canonical provenance.invocation_args: first argument must be `run`",
            path.display()
        )));
    }

    let mut normalized = Vec::with_capacity(args.len() - 1);
    let mut seen = [false; DNS_SCENARIO_INVOCATION_FLAGS.len()];
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        let Some(flag_index) = DNS_SCENARIO_INVOCATION_FLAGS
            .iter()
            .position(|flag| argument == flag)
        else {
            normalized.push(argument.clone());
            index += 1;
            continue;
        };
        if seen[flag_index] {
            return Err(BenchError::InvalidArguments(format!(
                "summary `{}` has duplicate `{argument}` in provenance.invocation_args",
                path.display()
            )));
        }
        let Some(value) = args.get(index + 1) else {
            return Err(BenchError::InvalidArguments(format!(
                "summary `{}` has `{argument}` without a value in provenance.invocation_args",
                path.display()
            )));
        };
        if value.is_empty() || value.starts_with("--") {
            return Err(BenchError::InvalidArguments(format!(
                "summary `{}` has invalid value `{value}` for `{argument}` in provenance.invocation_args",
                path.display()
            )));
        }
        seen[flag_index] = true;
        index += 2;
    }
    if let Some((missing_index, _)) = seen.iter().enumerate().find(|(_, present)| !**present) {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` is missing `{}` from canonical provenance.invocation_args",
            path.display(),
            DNS_SCENARIO_INVOCATION_FLAGS[missing_index]
        )));
    }
    Ok(normalized)
}

fn validate_dns_binary_sha256(
    path: &std::path::Path,
    field: &str,
    value: Option<&str>,
) -> Result<(), BenchError> {
    let Some(value) = value else {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` is missing provenance.{field}; published DNS charts require measured binary SHA-256 provenance",
            path.display()
        )));
    };
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if !valid {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` has invalid provenance.{field} `{value}`; expected exactly 64 lowercase hexadecimal characters",
            path.display()
        )));
    }
    Ok(())
}

fn validate_dns_summary(
    path: &std::path::Path,
    key: DnsSummaryKey,
    summary: &BenchSummary,
) -> Result<(), BenchError> {
    let expected_workload = key.scenario.workload(key.client).as_str();
    if summary.engine != EngineKind::XrayRust.as_str() || summary.workload != expected_workload {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` has engine/workload {}/{}; expected xray-rust/{expected_workload}",
            path.display(),
            summary.engine,
            summary.workload
        )));
    }
    if summary.status != "ok" {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` has status `{}`; DNS charts require status `ok`",
            path.display(),
            summary.status
        )));
    }
    if summary.provenance.harness_profile != "release" {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` records provenance.harness_profile=`{}`; published DNS charts require `release`",
            path.display(),
            summary.provenance.harness_profile
        )));
    }
    validate_dns_binary_sha256(
        path,
        "harness_binary_sha256",
        summary.provenance.harness_binary_sha256.as_deref(),
    )?;
    validate_dns_binary_sha256(
        path,
        "engine_binary_sha256",
        summary.provenance.engine_binary_sha256.as_deref(),
    )?;
    let _ = normalized_dns_invocation_args(path, &summary.provenance.invocation_args)?;
    if summary.runs == 0 || summary.results.len() != summary.runs {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` has runs={} but {} raw results; DNS charts derive rates and costs from every raw run",
            path.display(),
            summary.runs,
            summary.results.len()
        )));
    }
    if summary.connections == 0 || summary.iterations == 0 || summary.latency_us.is_none() {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` needs non-zero connections/iterations and latency data for DNS charts",
            path.display()
        )));
    }
    if summary.iterations < MIN_CHARTED_LATENCY_ITERATIONS {
        return Err(BenchError::InvalidArguments(format!(
            "summary `{}` has {} iterations; published DNS charts require at least {}",
            path.display(),
            summary.iterations,
            MIN_CHARTED_LATENCY_ITERATIONS
        )));
    }

    let expected_transport = Some(key.client.as_str());
    let expected_upstream = key.scenario.upstream();
    for (index, result) in summary.results.iter().enumerate() {
        let semantics_match = result.engine == summary.engine
            && result.run_id == summary.run_id
            && result.provenance == summary.provenance
            && result.workload == summary.workload
            && result.status == "ok"
            && result.connections == summary.connections
            && result.iterations == summary.iterations
            && result.payload_size == summary.payload_size
            && result.dns_transport.as_deref() == expected_transport
            && result.dns_upstream_transport.as_deref() == expected_upstream;
        if !semantics_match {
            return Err(BenchError::InvalidArguments(format!(
                "summary `{}` raw result {} has mismatched DNS semantics, provenance, or workload parameters",
                path.display(),
                index + 1
            )));
        }
        if result.duration_ms == 0 || result.latency_us.is_none() || dns_query_count(result)? == 0 {
            return Err(BenchError::InvalidArguments(format!(
                "summary `{}` raw result {} needs non-zero duration/query count and latency data",
                path.display(),
                index + 1
            )));
        }
    }
    Ok(())
}

fn dns_provenance_mismatch(
    field: &str,
    first_path: &std::path::Path,
    first_value: &impl std::fmt::Debug,
    path: &std::path::Path,
    value: &impl std::fmt::Debug,
) -> BenchError {
    BenchError::InvalidArguments(format!(
        "DNS chart provenance mismatch for {field}: `{}` records {first_value:?}, but `{}` records {value:?}",
        first_path.display(),
        path.display()
    ))
}

fn validate_dns_matrix_provenance(
    entries: &[(DnsSummaryKey, PathBuf, BenchSummary)],
) -> Result<(), BenchError> {
    let Some((_, first_path, first)) = entries.first() else {
        return Err(BenchError::InvalidArguments(
            "cannot validate provenance for an empty DNS chart matrix".to_owned(),
        ));
    };
    let first_invocation =
        normalized_dns_invocation_args(first_path, &first.provenance.invocation_args)?;
    for (_, path, summary) in entries.iter().skip(1) {
        let first_provenance = &first.provenance;
        let provenance = &summary.provenance;
        if provenance.workspace_git != first_provenance.workspace_git {
            return Err(dns_provenance_mismatch(
                "provenance.workspace_git",
                first_path,
                &first_provenance.workspace_git,
                path,
                &provenance.workspace_git,
            ));
        }
        if provenance.harness_binary_path != first_provenance.harness_binary_path {
            return Err(dns_provenance_mismatch(
                "provenance.harness_binary_path",
                first_path,
                &first_provenance.harness_binary_path,
                path,
                &provenance.harness_binary_path,
            ));
        }
        if provenance.harness_binary_sha256 != first_provenance.harness_binary_sha256 {
            return Err(dns_provenance_mismatch(
                "provenance.harness_binary_sha256",
                first_path,
                &first_provenance.harness_binary_sha256,
                path,
                &provenance.harness_binary_sha256,
            ));
        }
        if provenance.engine_binary_path != first_provenance.engine_binary_path {
            return Err(dns_provenance_mismatch(
                "provenance.engine_binary_path",
                first_path,
                &first_provenance.engine_binary_path,
                path,
                &provenance.engine_binary_path,
            ));
        }
        if provenance.engine_binary_sha256 != first_provenance.engine_binary_sha256 {
            return Err(dns_provenance_mismatch(
                "provenance.engine_binary_sha256",
                first_path,
                &first_provenance.engine_binary_sha256,
                path,
                &provenance.engine_binary_sha256,
            ));
        }
        if provenance.working_directory != first_provenance.working_directory {
            return Err(dns_provenance_mismatch(
                "provenance.working_directory",
                first_path,
                &first_provenance.working_directory,
                path,
                &provenance.working_directory,
            ));
        }
        let invocation = normalized_dns_invocation_args(path, &provenance.invocation_args)?;
        if invocation != first_invocation {
            return Err(BenchError::InvalidArguments(format!(
                "DNS chart provenance.invocation_args mismatch after removing only scenario-specific --workload/--transport/--dns-upstream-transport pairs: `{}` records {first_invocation:?}, but `{}` records {invocation:?}",
                first_path.display(),
                path.display()
            )));
        }
    }
    Ok(())
}

fn load_dns_summaries(groups: &[PathBuf]) -> Result<LoadedDnsSummaries, BenchError> {
    let mut entries: Vec<(DnsSummaryKey, PathBuf, BenchSummary)> = Vec::new();
    for group in groups {
        let mut found_in_group = false;
        for workload in DNS_WORKLOADS {
            let candidate = group
                .join(EngineKind::XrayRust.as_str())
                .join(workload.as_str())
                .join("summary.json");
            if !candidate.exists() {
                continue;
            }
            found_in_group = true;
            let data = fs::read_to_string(&candidate).map_err(|source| BenchError::Io {
                action: format!("reading DNS benchmark summary `{}`", candidate.display()),
                source,
            })?;
            let summary: BenchSummary = serde_json::from_str(&data).map_err(|error| {
                BenchError::InvalidArguments(format!(
                    "failed to parse DNS summary `{}`: {error}",
                    candidate.display()
                ))
            })?;
            let key = dns_summary_key(&candidate, workload, &summary)?;
            validate_dns_summary(&candidate, key, &summary)?;
            if let Some((_, previous, _)) = entries.iter().find(|(existing, _, _)| *existing == key)
            {
                return Err(BenchError::InvalidArguments(format!(
                    "duplicate DNS chart input for {}: `{}` and `{}`",
                    key.label(),
                    previous.display(),
                    candidate.display()
                )));
            }
            entries.push((key, candidate, summary));
        }
        if !found_in_group {
            return Err(BenchError::InvalidArguments(format!(
                "DNS group `{}` contains no xray-rust tun-fake-dns, tun-fake-dns-tcp, or tun-dns-proxy summary",
                group.display()
            )));
        }
    }

    let missing = DNS_SCENARIOS
        .iter()
        .flat_map(|scenario| {
            DNS_CLIENTS.iter().map(move |client| DnsSummaryKey {
                scenario: *scenario,
                client: *client,
            })
        })
        .filter(|required| entries.iter().all(|(key, _, _)| key != required))
        .map(DnsSummaryKey::label)
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(BenchError::InvalidArguments(format!(
            "missing DNS chart summaries for: {}",
            missing.join(", ")
        )));
    }
    let (_, first_path, first) = &entries[0];
    if let Some((_, path, summary)) = entries.iter().skip(1).find(|(_, _, summary)| {
        summary.runs != first.runs
            || summary.connections != first.connections
            || summary.iterations != first.iterations
    }) {
        return Err(BenchError::InvalidArguments(format!(
            "DNS chart summaries have mixed run parameters: `{}` records runs={}/connections={}/iterations={}, but `{}` records runs={}/connections={}/iterations={}",
            first_path.display(),
            first.runs,
            first.connections,
            first.iterations,
            path.display(),
            summary.runs,
            summary.connections,
            summary.iterations
        )));
    }
    validate_dns_matrix_provenance(&entries)?;
    Ok(LoadedDnsSummaries { entries })
}

#[derive(Debug, Clone, Copy)]
struct DnsMetricAggregate {
    min: f64,
    median: f64,
    p95: f64,
}

fn aggregate_dns_metric(mut values: Vec<f64>) -> DnsMetricAggregate {
    values.sort_by(f64::total_cmp);
    let len = values.len();
    let median = if len % 2 == 1 {
        values[len / 2]
    } else {
        (values[len / 2 - 1] + values[len / 2]) / 2.0
    };
    let p95_rank = (len * 95).div_ceil(100);
    DnsMetricAggregate {
        min: values[0],
        median,
        p95: values[p95_rank.saturating_sub(1)],
    }
}

fn dns_metric_group(
    loaded: &LoadedDnsSummaries,
    scenario: DnsScenario,
    derive: impl Fn(&crate::BenchResult, u128) -> f64,
) -> Result<BarGroup, BenchError> {
    let bars = DNS_CLIENTS
        .iter()
        .map(|client| {
            let summary = loaded.get(scenario, *client);
            let values = summary
                .results
                .iter()
                .map(|result| dns_query_count(result).map(|count| derive(result, count)))
                .collect::<Result<Vec<_>, BenchError>>()?;
            let aggregate = aggregate_dns_metric(values);
            Ok(Bar {
                series: client.series(),
                value: aggregate.median,
                lo: aggregate.min,
                hi: aggregate.p95,
            })
        })
        .collect::<Result<Vec<_>, BenchError>>()?;
    Ok(BarGroup {
        label: scenario.label().to_owned(),
        bars,
    })
}

fn dns_latency_group(loaded: &LoadedDnsSummaries, scenario: DnsScenario) -> BarGroup {
    let bars = DNS_CLIENTS
        .iter()
        .map(|client| {
            let summary = loaded.get(scenario, *client);
            let medians = aggregate_dns_metric(
                summary
                    .results
                    .iter()
                    .filter_map(|result| result.latency_us.as_ref())
                    .map(|latency| latency.median as f64)
                    .collect(),
            );
            let p95s = aggregate_dns_metric(
                summary
                    .results
                    .iter()
                    .filter_map(|result| result.latency_us.as_ref())
                    .map(|latency| latency.p95 as f64)
                    .collect(),
            );
            Bar {
                series: client.series(),
                value: medians.median,
                lo: medians.min,
                hi: p95s.median,
            }
        })
        .collect();
    BarGroup {
        label: scenario.label().to_owned(),
        bars,
    }
}

fn metric_bar(metric: &crate::MetricSummary, series: usize, divisor: f64) -> Bar {
    Bar {
        series,
        value: metric.median as f64 / divisor,
        lo: metric.min as f64 / divisor,
        hi: metric.p95 as f64 / divisor,
    }
}

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

/// A latency series needs enough iterations to outlast the engine's warm-up
/// transient; ten-iteration runs measure only that transient and swing by more
/// than 2x between sessions. Summaries written before the harness recorded
/// workload parameters report zero and are rejected the same way.
const MIN_CHARTED_LATENCY_ITERATIONS: u64 = 100;

fn latency_group(
    loaded: &LoadedSummaries,
    workload: WorkloadKind,
    connections: Option<u64>,
) -> Result<BarGroup, BenchError> {
    let bars = ENGINES
        .iter()
        .enumerate()
        .map(|(series, engine)| {
            let summary = loaded.get(*engine, workload, connections);
            let latency = summary.latency_us.as_ref().ok_or_else(|| {
                BenchError::InvalidArguments(format!(
                    "summary for {} {} has no latency data",
                    engine.as_str(),
                    workload.as_str()
                ))
            })?;
            if summary.iterations < MIN_CHARTED_LATENCY_ITERATIONS {
                return Err(BenchError::InvalidArguments(format!(
                    "summary for {} {} has {} iterations; charted latency series need at least {} (see docs/benchmarks.md)",
                    engine.as_str(),
                    workload.as_str(),
                    summary.iterations,
                    MIN_CHARTED_LATENCY_ITERATIONS,
                )));
            }
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
    connections: Option<u64>,
    metric_name: &str,
    select: impl Fn(&BenchSummary) -> Option<&crate::MetricSummary>,
    divisor: f64,
) -> Result<BarGroup, BenchError> {
    let bars = ENGINES
        .iter()
        .enumerate()
        .map(|(series, engine)| {
            let summary = loaded.get(*engine, workload, connections);
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

pub fn run_chart(options: &ChartOptions) -> Result<(), BenchError> {
    let loaded = if options.groups.is_empty() {
        None
    } else {
        let mut entries = Vec::new();
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
        Some(LoadedSummaries { entries })
    };
    let dns_loaded = if options.dns_groups.is_empty() {
        None
    } else {
        Some(load_dns_summaries(&options.dns_groups)?)
    };

    let (footer, geo_footer) = if let Some(loaded) = &loaded {
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
            runs_label: runs_label.clone(),
            xray_rust_version: options.xray_rust_version.clone(),
            xray_core_version: options.xray_core_version.clone(),
            sing_box_version: options.sing_box_version.clone(),
            geodata: None,
            comparison_versions: true,
        };
        if options.geodata_version.is_none() {
            eprintln!(
                "warning: --geodata-version not set; geo charts will omit the geodata provenance segment"
            );
        }
        let geo_footer = Footer {
            date: options.date.clone(),
            hardware: options.hardware.clone(),
            runs_label,
            xray_rust_version: options.xray_rust_version.clone(),
            xray_core_version: options.xray_core_version.clone(),
            sing_box_version: options.sing_box_version.clone(),
            geodata: options.geodata_version.clone(),
            comparison_versions: true,
        };
        (Some(footer), Some(geo_footer))
    } else {
        (None, None)
    };
    let dns_footer = dns_loaded.as_ref().map(|loaded| {
        let runs = loaded
            .entries
            .iter()
            .map(|(_, _, summary)| summary.runs)
            .collect::<Vec<_>>();
        let runs_label = if runs.windows(2).all(|pair| pair[0] == pair[1]) {
            runs[0].to_string()
        } else {
            eprintln!(
                "warning: run counts differ across DNS summaries; DNS chart footer will say runs=varies"
            );
            "varies".to_owned()
        };
        Footer {
            date: options.date.clone(),
            hardware: options.hardware.clone(),
            runs_label,
            xray_rust_version: options.xray_rust_version.clone(),
            xray_core_version: options.xray_core_version.clone(),
            sing_box_version: options.sing_box_version.clone(),
            geodata: None,
            comparison_versions: false,
        }
    });

    let mut charts: Vec<(&str, ChartSpec)> = if let Some(loaded) = &loaded {
        vec![
        (
            "memory-rss",
            ChartSpec {
                title: "Peak resident set size — MiB (lower is better)".to_owned(),
                series_labels: &SERIES_LABELS_ALL,
                groups: vec![
                    rss_group(loaded, WorkloadKind::Idle, None, "idle"),
                    rss_group(
                        loaded,
                        WorkloadKind::ManyIdleFlows,
                        Some(100),
                        "many-idle-flows ×100",
                    ),
                    rss_group(
                        loaded,
                        WorkloadKind::ManyIdleFlows,
                        Some(1000),
                        "many-idle-flows ×1000",
                    ),
                ],
                note: None,
            },
        ),
        (
            "latency",
            ChartSpec {
                title: "Round-trip latency — µs, median with p95 whisker (lower is better)"
                    .to_owned(),
                series_labels: &SERIES_LABELS_ALL,
                groups: vec![
                    latency_group(loaded, WorkloadKind::TcpFreedom, None)?,
                    latency_group(loaded, WorkloadKind::UdpFreedom, None)?,
                    latency_group(loaded, WorkloadKind::RealityVisionXudp, None)?,
                ],
                note: None,
            },
        ),
        (
            "throughput",
            ChartSpec {
                title: "Bulk TCP throughput through SOCKS — Gbps (higher is better)".to_owned(),
                series_labels: &SERIES_LABELS_ALL,
                groups: vec![optional_metric_group(
                    loaded,
                    WorkloadKind::TcpBulkThroughput,
                    None,
                    "throughput",
                    |summary| summary.throughput_mbps.as_ref(),
                    1000.0,
                )?],
                note: None,
            },
        ),
        (
            "reality-throughput",
            ChartSpec {
                title:
                    "Bulk TCP throughput through VLESS + REALITY + Vision — Gbps (higher is better)"
                        .to_owned(),
                series_labels: &SERIES_LABELS_ALL,
                groups: vec![optional_metric_group(
                    loaded,
                    WorkloadKind::RealityVisionBulkThroughput,
                    None,
                    "throughput",
                    |summary| summary.throughput_mbps.as_ref(),
                    1000.0,
                )?],
                note: None,
            },
        ),
        (
            "cpu-per-gib",
            ChartSpec {
                title: "CPU cost — milliseconds per GiB transferred (lower is better)".to_owned(),
                series_labels: &SERIES_LABELS_ALL,
                groups: vec![optional_metric_group(
                    loaded,
                    WorkloadKind::TcpBulkThroughput,
                    None,
                    "cpu-per-GiB",
                    |summary| summary.cpu_millis_per_gib.as_ref(),
                    1.0,
                )?],
                note: None,
            },
        ),
        (
            "geo-setup-latency",
            ChartSpec {
                title: "Time to SOCKS CONNECT reply with real geodata — µs (see docs note)"
                    .to_owned(),
                series_labels: &SERIES_LABELS_GEO,
                groups: vec![geo_setup_group(loaded)?],
                note: None,
            },
        ),
        (
            "geo-memory",
            ChartSpec {
                title: "Routing memory with real geodata — MiB (lower is better)".to_owned(),
                series_labels: &SERIES_LABELS_GEO,
                groups: vec![geo_memory_group(loaded)],
                note: None,
            },
        ),
        ]
    } else {
        Vec::new()
    };

    if let Some(loaded) = &dns_loaded {
        let latency_groups = DNS_SCENARIOS
            .iter()
            .map(|scenario| dns_latency_group(loaded, *scenario))
            .collect();
        let query_rate_groups = DNS_SCENARIOS
            .iter()
            .map(|scenario| {
                dns_metric_group(loaded, *scenario, |result, queries| {
                    queries as f64 * 1000.0 / result.duration_ms as f64
                })
            })
            .collect::<Result<Vec<_>, BenchError>>()?;
        let cpu_cost_groups = DNS_SCENARIOS
            .iter()
            .map(|scenario| {
                dns_metric_group(loaded, *scenario, |result, queries| {
                    result.cpu_millis as f64 * 1000.0 / queries as f64
                })
            })
            .collect::<Result<Vec<_>, BenchError>>()?;
        let rss_groups = DNS_SCENARIOS
            .iter()
            .map(|scenario| {
                dns_metric_group(loaded, *scenario, |result, _| {
                    result.peak_rss_kib as f64 / 1024.0
                })
            })
            .collect::<Result<Vec<_>, BenchError>>()?;
        charts.extend([
            (
                "dns-latency",
                ChartSpec {
                    title: "DNS latency — µs, median with p95 whisker (lower is better)".to_owned(),
                    series_labels: &DNS_SERIES_LABELS,
                    groups: latency_groups,
                    note: Some(DNS_CHART_NOTE.to_owned()),
                },
            ),
            (
                "dns-query-rate",
                ChartSpec {
                    title: "DNS throughput — queries/s (higher is better)".to_owned(),
                    series_labels: &DNS_SERIES_LABELS,
                    groups: query_rate_groups,
                    note: Some(DNS_CHART_NOTE.to_owned()),
                },
            ),
            (
                "dns-cpu-per-1k-queries",
                ChartSpec {
                    title: "DNS CPU cost — ms per 1k queries (lower is better)".to_owned(),
                    series_labels: &DNS_SERIES_LABELS,
                    groups: cpu_cost_groups,
                    note: Some(DNS_CHART_NOTE.to_owned()),
                },
            ),
            (
                "dns-memory-rss",
                ChartSpec {
                    title: "DNS peak resident set size — MiB (lower is better)".to_owned(),
                    series_labels: &DNS_SERIES_LABELS,
                    groups: rss_groups,
                    note: Some(DNS_CHART_NOTE.to_owned()),
                },
            ),
        ]);
    }

    fs::create_dir_all(&options.out_dir).map_err(|source| BenchError::Io {
        action: format!("creating chart directory `{}`", options.out_dir.display()),
        source,
    })?;
    for (stem, spec) in &charts {
        let chart_footer = if stem.starts_with("dns-") {
            dns_footer
                .as_ref()
                .expect("DNS charts are built only when DNS summaries were loaded")
        } else if stem.starts_with("geo-") {
            geo_footer
                .as_ref()
                .expect("geo charts are built only when comparison summaries were loaded")
        } else {
            footer
                .as_ref()
                .expect("comparison charts are built only when comparison summaries were loaded")
        };
        for theme in [&LIGHT, &DARK] {
            let svg = render_bar_chart(spec, theme, chart_footer);
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
    use crate::{
        summarize_results, write_summary_json, BenchProvenance, BenchResult, LatencySummary,
        MetricSummary, WorkspaceGitProvenance,
    };
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
            "v26.7.28",
            "--sing-box-version",
            "v1.12.0",
        ])
    }

    fn test_summary_with(
        engine: &str,
        workload: &str,
        status: &str,
        connections: u64,
    ) -> BenchSummary {
        let metric = MetricSummary {
            min: 1,
            median: 2,
            p95: 3,
        };
        BenchSummary {
            run_id: String::new(),
            provenance: crate::BenchProvenance::default(),
            engine: engine.to_owned(),
            workload: workload.to_owned(),
            status: status.to_owned(),
            runs: 5,
            duration_ms: metric.clone(),
            transfer_duration_ms: Some(metric.clone()),
            peak_rss_kib: MetricSummary {
                min: 10_240,
                median: 12_288,
                p95: 14_336,
            },
            cpu_millis: metric.clone(),
            // Distinct from `metric` so a test asserting on this value pins metric
            // selection, not just workload selection.
            cpu_millis_per_gib: Some(MetricSummary {
                min: 700,
                median: 820,
                p95: 900,
            }),
            throughput_mbps: Some(MetricSummary {
                min: 4000,
                median: 4300,
                p95: 4500,
            }),
            connections,
            iterations: 0,
            payload_size: 0,
            stream_transport: None,
            stream_traffic: None,
            xhttp_mode: None,
            xhttp_profile: None,
            xhttp_max_post_bytes: None,
            settle_ms: 0,
            uplink_write_ops: None,
            uplink_write_ops_per_second: None,
            dns_transport: None,
            dns_upstream_transport: None,
            latency_us: None,
            setup_us: None,
            bytes_sent: metric.clone(),
            bytes_received: metric,
            results: Vec::new(),
        }
    }

    fn test_summary(engine: &str, workload: &str, status: &str) -> BenchSummary {
        test_summary_with(engine, workload, status, 0)
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
        assert_eq!(options.xray_core_version, "v26.7.28");

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
            "v26.7.28",
            "--sing-box-version",
            "v1.12.0",
        ]))
        .unwrap();
        assert_eq!(options.groups.len(), 2);
        assert_eq!(options.out_dir, PathBuf::from("custom"));
    }

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

    #[test]
    fn parses_repeatable_dns_groups_without_comparison_versions() {
        let options = parse_chart_args(&args(&[
            "--dns-group",
            "dns-a",
            "--dns-group",
            "dns-b",
            "--date",
            "2026-08-01",
            "--hardware",
            "Apple M3 Pro",
            "--xray-rust-version",
            "e1491bd",
        ]))
        .unwrap();

        assert_eq!(
            options.dns_groups,
            vec![PathBuf::from("dns-a"), PathBuf::from("dns-b")]
        );
        assert!(options.groups.is_empty());
        assert!(options.xray_core_version.is_empty());
        assert!(options.sing_box_version.is_empty());
    }

    #[test]
    fn chart_args_require_group_and_metadata() {
        let error = parse_chart_args(&args(&["--date", "2026-07-29"])).unwrap_err();
        assert!(error
            .to_string()
            .contains("--group <run-dir> or --dns-group"));

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
            None,
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
            None,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("missing summary for xray-core idle"));

        let error = load_summary(
            std::slice::from_ref(&root),
            EngineKind::XrayRust,
            WorkloadKind::Idle,
            None,
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
        let error =
            load_summary(&groups, EngineKind::XrayRust, WorkloadKind::Idle, None).unwrap_err();

        assert!(error.to_string().contains("found in 2 group directories"));
        fs::remove_dir_all(&root).unwrap();
    }

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
        assert!(error
            .to_string()
            .contains("found summaries with connections="));
        fs::remove_dir_all(&root).unwrap();
    }

    fn aggregate(min: u128, median: u128, p95: u128) -> crate::LatencySummaryAggregate {
        crate::LatencySummaryAggregate {
            min: MetricSummary { min, median, p95 },
            median: MetricSummary { min, median, p95 },
            p95: MetricSummary {
                min: p95,
                median: p95 * 2,
                p95: p95 * 3,
            },
            p99: MetricSummary { min, median, p95 },
        }
    }

    fn write_full_group(root: &Path) -> Vec<PathBuf> {
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
        let mut groups = Vec::new();
        for (workload, connections) in slots {
            let group_dir = match connections {
                Some(conn) => root.join(format!("g-{workload}-{conn}")),
                None => root.join(format!("g-{workload}")),
            };
            let engines: Vec<&str> = if workload == "routed-tcp-freedom" {
                vec!["xray-rust", "xray-core"]
            } else {
                vec!["xray-rust", "xray-core", "sing-box"]
            };
            for engine in engines {
                let mut summary =
                    test_summary_with(engine, workload, "ok", connections.unwrap_or(0));
                if matches!(
                    workload,
                    "tcp-freedom" | "udp-freedom" | "reality-vision-xudp"
                ) {
                    // Charted latency series must clear MIN_CHARTED_LATENCY_ITERATIONS.
                    summary.iterations = 1000;
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
                if workload == "routed-tcp-freedom" {
                    summary.setup_us = Some(crate::FlowSetupSummaryAggregate {
                        tcp_connect_us: aggregate(40, 60, 90),
                        socks_method_us: aggregate(10, 15, 25),
                        socks_connect_us: aggregate(120, 180, 400),
                        socks_setup_us: aggregate(140, 200, 420),
                        total_us: aggregate(180, 260, 500),
                    });
                }
                let dir = group_dir.join(engine).join(workload);
                fs::create_dir_all(&dir).unwrap();
                write_summary_json(&dir.join("summary.json"), &summary).unwrap();
            }
            groups.push(group_dir);
        }
        groups
    }

    fn dns_provenance(key: DnsSummaryKey) -> BenchProvenance {
        BenchProvenance {
            harness_profile: "release".to_owned(),
            workspace_git: Some(WorkspaceGitProvenance {
                revision: "fixture-revision".to_owned(),
                dirty: Some(true),
            }),
            engine_source_git: Some(WorkspaceGitProvenance {
                revision: "engine-fixture-revision".to_owned(),
                dirty: Some(false),
            }),
            harness_binary_path: Some(PathBuf::from("/bench/xray-bench")),
            harness_binary_sha256: Some("11".repeat(32)),
            engine_binary_path: Some(PathBuf::from("/bench/xray-rust")),
            engine_binary_sha256: Some("22".repeat(32)),
            working_directory: Some(PathBuf::from("/workspace/xray-rust")),
            invocation_args: vec![
                "run".to_owned(),
                "--engine".to_owned(),
                "xray-rust".to_owned(),
                "--workload".to_owned(),
                key.scenario.workload(key.client).as_str().to_owned(),
                "--duration-ms".to_owned(),
                "1000".to_owned(),
                "--sample-interval-ms".to_owned(),
                "10".to_owned(),
                "--run-timeout-ms".to_owned(),
                "120000".to_owned(),
                "--connections".to_owned(),
                "2".to_owned(),
                "--iterations".to_owned(),
                "100".to_owned(),
                "--payload-size".to_owned(),
                "512".to_owned(),
                "--transport".to_owned(),
                key.client.as_str().to_owned(),
                "--dns-upstream-transport".to_owned(),
                key.scenario.upstream().unwrap_or("classic").to_owned(),
                "--runs".to_owned(),
                "3".to_owned(),
                "--out-dir".to_owned(),
                "target/benchmarks".to_owned(),
                "--xray-rust-bin".to_owned(),
                "/bench/xray-rust".to_owned(),
            ],
        }
    }

    fn dns_result(key: DnsSummaryKey, run: usize) -> BenchResult {
        let duration_ms = [100, 200, 400][run];
        let cpu_millis = [10, 20, 40][run];
        let peak_rss_kib = [10_240, 12_288, 14_336][run];
        let latency_median = [100, 120, 140][run];
        let latency_p95 = [200, 240, 280][run];
        BenchResult {
            run_id: format!(
                "dns-{}-{}",
                key.scenario.label().to_ascii_lowercase(),
                key.client.as_str()
            ),
            provenance: dns_provenance(key),
            engine: "xray-rust".to_owned(),
            workload: key.scenario.workload(key.client).as_str().to_owned(),
            status: "ok".to_owned(),
            duration_ms,
            transfer_duration_ms: None,
            bytes_sent: 0,
            bytes_received: 0,
            peak_rss_kib,
            cpu_millis,
            cpu_millis_per_gib: None,
            throughput_mbps: None,
            connections: 2,
            iterations: 100,
            payload_size: 512,
            stream_transport: None,
            stream_traffic: None,
            xhttp_mode: None,
            xhttp_profile: None,
            xhttp_max_post_bytes: None,
            settle_ms: 0,
            memory_phases: Vec::new(),
            uplink_write_ops: None,
            uplink_write_ops_per_second: None,
            dns_transport: Some(key.client.as_str().to_owned()),
            dns_upstream_transport: key.scenario.upstream().map(str::to_owned),
            latency_us: Some(LatencySummary {
                min: latency_median - 20,
                median: latency_median,
                p95: latency_p95,
                p99: latency_p95 + 20,
            }),
            setup_us: None,
            samples: 10,
            blackhole_connections_accepted: None,
            blackhole_connections_active: None,
        }
    }

    fn dns_summary(key: DnsSummaryKey) -> BenchSummary {
        let results = (0..3).map(|run| dns_result(key, run)).collect::<Vec<_>>();
        summarize_results(&results).unwrap()
    }

    fn write_dns_summary(group: &Path, key: DnsSummaryKey, summary: &BenchSummary) {
        let dir = group
            .join("xray-rust")
            .join(key.scenario.workload(key.client).as_str());
        fs::create_dir_all(&dir).unwrap();
        write_summary_json(&dir.join("summary.json"), summary).unwrap();
    }

    fn write_dns_matrix(root: &Path) -> Vec<PathBuf> {
        let mut groups = Vec::new();
        for scenario in DNS_SCENARIOS {
            for client in DNS_CLIENTS {
                let key = DnsSummaryKey { scenario, client };
                let group = root.join(format!(
                    "dns-{}-{}",
                    scenario.label().to_ascii_lowercase(),
                    client.as_str()
                ));
                write_dns_summary(&group, key, &dns_summary(key));
                groups.push(group);
            }
        }
        groups
    }

    fn dns_only_options(root: &Path, groups: Vec<PathBuf>) -> ChartOptions {
        let mut options = parse_chart_args(&args(&[
            "--dns-group",
            groups[0].to_str().unwrap(),
            "--date",
            "2026-08-01",
            "--hardware",
            "Apple M3 Pro",
            "--xray-rust-version",
            "e1491bd",
        ]))
        .unwrap();
        options.dns_groups = groups;
        options.out_dir = root.join("media");
        options
    }

    #[test]
    fn run_chart_writes_eight_dns_theme_files_from_dns_only_inputs() {
        let root = temp_root("dns-e2e");
        let groups = write_dns_matrix(&root);
        let options = dns_only_options(&root, groups);

        run_chart(&options).unwrap();

        for stem in [
            "dns-latency",
            "dns-query-rate",
            "dns-cpu-per-1k-queries",
            "dns-memory-rss",
        ] {
            for theme in ["light", "dark"] {
                assert!(options
                    .out_dir
                    .join(format!("{stem}-{theme}.svg"))
                    .is_file());
            }
        }
        assert!(!options.out_dir.join("memory-rss-light.svg").exists());

        let latency = fs::read_to_string(options.out_dir.join("dns-latency-light.svg")).unwrap();
        assert!(latency.contains("Hybrid A + HTTPS queries"));
        assert!(latency.contains("cache-warmed fixture"));
        assert!(latency.contains("UDP client"));
        assert!(latency.contains("TCP client"));
        assert!(latency.contains("FakeDNS"));
        assert!(latency.contains("tcp-local"));
        assert!(latency.contains(">120<"));
        assert!(latency.contains("xray-rust e1491bd"));
        assert!(!latency.contains("Xray-core"));

        let query_rate =
            fs::read_to_string(options.out_dir.join("dns-query-rate-light.svg")).unwrap();
        assert!(query_rate.contains(">2000<"));
        let cpu =
            fs::read_to_string(options.out_dir.join("dns-cpu-per-1k-queries-light.svg")).unwrap();
        assert!(cpu.contains(">50.0<"));
        let rss = fs::read_to_string(options.out_dir.join("dns-memory-rss-light.svg")).unwrap();
        assert!(rss.contains(">12.0<"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_both_client_transport() {
        let root = temp_root("dns-both");
        let key = DnsSummaryKey {
            scenario: DnsScenario::Classic,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary.dns_transport = Some("both".to_owned());
        for result in &mut summary.results {
            result.dns_transport = Some("both".to_owned());
        }
        let group = root.join("both");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error.to_string().contains("dns_transport=both"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_duplicate_semantic_inputs() {
        let root = temp_root("dns-duplicate");
        let mut groups = write_dns_matrix(&root);
        groups.push(groups[0].clone());

        let error = load_dns_summaries(&groups).unwrap_err();

        assert!(error.to_string().contains("duplicate DNS chart input"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_partial_matrix() {
        let root = temp_root("dns-partial");
        let mut groups = write_dns_matrix(&root);
        groups.pop();

        let error = load_dns_summaries(&groups).unwrap_err();

        assert!(error.to_string().contains("missing DNS chart summaries"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_non_ok_status() {
        let root = temp_root("dns-status");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary.status = "mixed".to_owned();
        let group = root.join("mixed");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error.to_string().contains("DNS charts require status `ok`"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_debug_harness_profile() {
        let root = temp_root("dns-debug-profile");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary.provenance.harness_profile = "debug".to_owned();
        let group = root.join("debug");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error.to_string().contains(
            "provenance.harness_profile=`debug`; published DNS charts require `release`"
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_missing_harness_binary_hash() {
        let root = temp_root("dns-missing-harness-hash");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary.provenance.harness_binary_sha256 = None;
        for result in &mut summary.results {
            result.provenance.harness_binary_sha256 = None;
        }
        let group = root.join("missing-harness-hash");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error.to_string().contains(
            "missing provenance.harness_binary_sha256; published DNS charts require measured binary SHA-256 provenance"
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_missing_engine_binary_hash() {
        let root = temp_root("dns-missing-engine-hash");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary.provenance.engine_binary_sha256 = None;
        for result in &mut summary.results {
            result.provenance.engine_binary_sha256 = None;
        }
        let group = root.join("missing-engine-hash");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error.to_string().contains(
            "missing provenance.engine_binary_sha256; published DNS charts require measured binary SHA-256 provenance"
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_short_binary_hash() {
        let root = temp_root("dns-short-hash");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary.provenance.harness_binary_sha256 = Some("abc123".to_owned());
        for result in &mut summary.results {
            result.provenance.harness_binary_sha256 = Some("abc123".to_owned());
        }
        let group = root.join("short-hash");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error.to_string().contains(
            "invalid provenance.harness_binary_sha256 `abc123`; expected exactly 64 lowercase hexadecimal characters"
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_uppercase_binary_hash() {
        let root = temp_root("dns-uppercase-hash");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        let uppercase_hash = "AB".repeat(32);
        summary.provenance.engine_binary_sha256 = Some(uppercase_hash.clone());
        for result in &mut summary.results {
            result.provenance.engine_binary_sha256 = Some(uppercase_hash.clone());
        }
        let group = root.join("uppercase-hash");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error
            .to_string()
            .contains("expected exactly 64 lowercase hexadecimal characters"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_empty_invocation_args() {
        let root = temp_root("dns-empty-invocation");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary.provenance.invocation_args.clear();
        for result in &mut summary.results {
            result.provenance.invocation_args.clear();
        }
        let group = root.join("empty-invocation");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error
            .to_string()
            .contains("empty provenance.invocation_args; published DNS charts require canonical replay arguments"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_non_canonical_invocation_args() {
        let root = temp_root("dns-non-canonical-invocation");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary
            .provenance
            .invocation_args
            .retain(|argument| argument != "--dns-upstream-transport" && argument != "classic");
        for result in &mut summary.results {
            result.provenance = summary.provenance.clone();
        }
        let group = root.join("non-canonical-invocation");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error.to_string().contains(
            "missing `--dns-upstream-transport` from canonical provenance.invocation_args"
        ));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_too_few_iterations() {
        let root = temp_root("dns-short-latency");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary.iterations = MIN_CHARTED_LATENCY_ITERATIONS - 1;
        for result in &mut summary.results {
            result.iterations = summary.iterations;
        }
        let group = root.join("short-latency");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error.to_string().contains(&format!(
            "has {} iterations; published DNS charts require at least {MIN_CHARTED_LATENCY_ITERATIONS}",
            MIN_CHARTED_LATENCY_ITERATIONS - 1
        )));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_mixed_binary_provenance() {
        let root = temp_root("dns-provenance");
        let groups = write_dns_matrix(&root);
        let summary_path = groups
            .last()
            .unwrap()
            .join("xray-rust/tun-dns-proxy/summary.json");
        let data = fs::read_to_string(&summary_path).unwrap();
        let mut summary: BenchSummary = serde_json::from_str(&data).unwrap();
        let other_binary = Some(PathBuf::from("/bench/other-xray-rust"));
        summary.provenance.engine_binary_path = other_binary.clone();
        for result in &mut summary.results {
            result.provenance.engine_binary_path = other_binary.clone();
        }
        write_summary_json(&summary_path, &summary).unwrap();

        let error = load_dns_summaries(&groups).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("provenance mismatch for provenance.engine_binary_path"));
        assert!(message.contains("/bench/xray-rust"));
        assert!(message.contains("/bench/other-xray-rust"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_mixed_binary_hash_provenance() {
        let root = temp_root("dns-hash-provenance");
        let groups = write_dns_matrix(&root);
        let summary_path = groups
            .last()
            .unwrap()
            .join("xray-rust/tun-dns-proxy/summary.json");
        let data = fs::read_to_string(&summary_path).unwrap();
        let mut summary: BenchSummary = serde_json::from_str(&data).unwrap();
        let other_hash = Some("33".repeat(32));
        summary.provenance.engine_binary_sha256 = other_hash.clone();
        for result in &mut summary.results {
            result.provenance.engine_binary_sha256 = other_hash.clone();
        }
        write_summary_json(&summary_path, &summary).unwrap();

        let error = load_dns_summaries(&groups).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("provenance.engine_binary_sha256"));
        assert!(message.contains(&"22".repeat(32)));
        assert!(message.contains(&"33".repeat(32)));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_non_scenario_invocation_drift() {
        let root = temp_root("dns-invocation-drift");
        let groups = write_dns_matrix(&root);
        let summary_path = groups
            .last()
            .unwrap()
            .join("xray-rust/tun-dns-proxy/summary.json");
        let data = fs::read_to_string(&summary_path).unwrap();
        let mut summary: BenchSummary = serde_json::from_str(&data).unwrap();
        let sample_interval = summary
            .provenance
            .invocation_args
            .iter()
            .position(|argument| argument == "--sample-interval-ms")
            .unwrap();
        summary.provenance.invocation_args[sample_interval + 1] = "25".to_owned();
        for result in &mut summary.results {
            result.provenance = summary.provenance.clone();
        }
        write_summary_json(&summary_path, &summary).unwrap();

        let error = load_dns_summaries(&groups).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("provenance.invocation_args mismatch"));
        assert!(message.contains("sample-interval-ms"));
        assert!(message.contains("\"10\""));
        assert!(message.contains("\"25\""));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_mixed_run_parameters() {
        let root = temp_root("dns-parameters");
        let groups = write_dns_matrix(&root);
        let summary_path = groups[0].join("xray-rust/tun-fake-dns/summary.json");
        let data = fs::read_to_string(&summary_path).unwrap();
        let mut summary: BenchSummary = serde_json::from_str(&data).unwrap();
        summary.iterations += 1;
        for result in &mut summary.results {
            result.iterations += 1;
        }
        write_summary_json(&summary_path, &summary).unwrap();

        let error = load_dns_summaries(&groups).unwrap_err();

        assert!(error.to_string().contains("mixed run parameters"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_dns_summaries_rejects_raw_result_semantic_mismatch() {
        let root = temp_root("dns-result-semantics");
        let key = DnsSummaryKey {
            scenario: DnsScenario::FakeDns,
            client: DnsClient::Udp,
        };
        let mut summary = dns_summary(key);
        summary.results[0].dns_transport = Some("tcp".to_owned());
        let group = root.join("bad-result");
        write_dns_summary(&group, key, &summary);

        let error = load_dns_summaries(&[group]).unwrap_err();

        assert!(error.to_string().contains("mismatched DNS semantics"));
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn run_chart_writes_fourteen_theme_files() {
        let root = temp_root("e2e");
        let out_dir = root.join("media");
        let mut options = parse_chart_args(&full_args(root.to_str().unwrap())).unwrap();
        options.groups = write_full_group(&root);
        options.out_dir = out_dir.clone();
        options.geodata_version = Some("geodata-test".to_owned());

        run_chart(&options).unwrap();

        for (stem, title_fragment) in [
            ("memory-rss", "Peak resident set size"),
            ("latency", "Round-trip latency"),
            ("throughput", "Bulk TCP throughput"),
            ("reality-throughput", "VLESS + REALITY + Vision"),
            ("cpu-per-gib", "CPU cost"),
            ("geo-setup-latency", "Time to SOCKS CONNECT reply"),
            ("geo-memory", "Routing memory"),
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
        assert!(memory.contains("many-idle-flows ×1000"));
        assert!(!memory.contains("geodata-test"));
        let throughput = fs::read_to_string(out_dir.join("throughput-light.svg")).unwrap();
        assert!(throughput.contains(">4.30<"));
        assert!(throughput.contains("tcp-bulk-throughput"));

        let latency = fs::read_to_string(out_dir.join("latency-light.svg")).unwrap();
        let (tcp, udp, xudp) = (
            latency.find("tcp-freedom").unwrap(),
            latency.find("udp-freedom").unwrap(),
            latency.find("reality-vision-xudp").unwrap(),
        );
        assert!(tcp < udp && udp < xudp, "latency groups out of order");
        let reality = fs::read_to_string(out_dir.join("reality-throughput-light.svg")).unwrap();
        assert!(reality.contains(">4.30<"));
        assert!(reality.contains("reality-vision-bulk-throughput"));

        let cpu = fs::read_to_string(out_dir.join("cpu-per-gib-light.svg")).unwrap();
        assert!(cpu.contains("tcp-bulk-throughput"));
        assert!(cpu.contains(">820<"));

        let geo_setup = fs::read_to_string(out_dir.join("geo-setup-latency-light.svg")).unwrap();
        assert!(geo_setup.contains("Xray-core"));
        assert!(geo_setup.contains(">180<"));
        assert!(geo_setup.contains("(see docs note)"));
        let geo = fs::read_to_string(out_dir.join("geo-memory-light.svg")).unwrap();
        assert!(!geo.contains(">sing-box<"));
        assert!(geo.contains("geodata-test"));

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn run_chart_fails_on_missing_latency() {
        let root = temp_root("no-latency");
        let mut options = parse_chart_args(&full_args(root.to_str().unwrap())).unwrap();
        options.groups = write_full_group(&root);
        let broken = test_summary("xray-rust", "tcp-freedom", "ok");
        write_summary_json(
            &root.join("g-tcp-freedom/xray-rust/tcp-freedom/summary.json"),
            &broken,
        )
        .unwrap();
        options.out_dir = root.join("media");

        let error = run_chart(&options).unwrap_err();

        assert!(error.to_string().contains("no latency data"));
        assert!(!options.out_dir.exists());
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn latency_group_rejects_degenerate_iteration_counts() {
        let workload = WorkloadKind::TcpFreedom;
        let entries = ENGINES
            .iter()
            .map(|engine| {
                let mut summary = test_summary_with(engine.as_str(), workload.as_str(), "ok", 0);
                summary.iterations = 10;
                summary.latency_us = Some(aggregate(90, 130, 200));
                ((*engine, workload, None), summary)
            })
            .collect();
        let loaded = LoadedSummaries { entries };

        let error = latency_group(&loaded, workload, None).unwrap_err();

        let message = error.to_string();
        assert!(message.contains("10 iterations"), "{message}");
        assert!(
            message.contains(&MIN_CHARTED_LATENCY_ITERATIONS.to_string()),
            "{message}"
        );
    }

    fn fixture_spec() -> ChartSpec {
        ChartSpec {
            title: "Peak resident set size — MiB (lower is better)".to_owned(),
            series_labels: &SERIES_LABELS_ALL,
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
            note: None,
        }
    }

    fn fixture_footer() -> Footer {
        Footer {
            date: "2026-07-29".to_owned(),
            hardware: "Apple M4 Pro, 24 GB RAM, macOS 15.5".to_owned(),
            runs_label: "5".to_owned(),
            xray_rust_version: "1659143".to_owned(),
            xray_core_version: "v26.7.28".to_owned(),
            sing_box_version: "v1.12.0".to_owned(),
            geodata: None,
            comparison_versions: true,
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
        assert!(svg.contains("Xray-core v26.7.28"));
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

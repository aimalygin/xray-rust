use std::{
    env, fs,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use thiserror::Error;
use xray_config::{parse_xray_json_with_geodata_dirs, CoreConfig, Diagnostic};
use xray_core_rs::{
    Core, CoreError, TunFdClosePolicy, TunFdConfig, TunFdPacketFormat, TunFdRuntime,
    TunRuntimeOptions, TunRuntimeProfile,
};

const USAGE: &str = "usage: xray-rust run -config <config.json>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliArgs {
    Run { config_path: PathBuf },
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    InvalidArguments(String),
    #[error("failed to read config `{path}`: {source}")]
    ReadConfig {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("config parse failed: {0}")]
    ConfigParse(String),
    #[error("core error: {0}")]
    Core(#[from] CoreError),
    #[error("TUN fd error: {source}")]
    TunFd { source: std::io::Error },
}

pub fn parse_cli_args<I, S>(args: I) -> Result<CliArgs, CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let args = args.into_iter().map(Into::into).collect::<Vec<_>>();

    match args.as_slice() {
        [_program, command, flag, config_path]
            if command == "run" && (flag == "-config" || flag == "--config") =>
        {
            Ok(CliArgs::Run {
                config_path: PathBuf::from(config_path),
            })
        }
        [_program, command, flag] if command == "run" && is_config_flag(flag) => Err(
            CliError::InvalidArguments(format!("missing config path\n{USAGE}")),
        ),
        _ => Err(CliError::InvalidArguments(USAGE.to_owned())),
    }
}

fn is_config_flag(flag: &str) -> bool {
    flag == "-config" || flag == "--config"
}

pub fn load_config(path: &Path) -> Result<CoreConfig, CliError> {
    load_config_with_diagnostics(path).map(|(config, _diagnostics)| config)
}

pub fn load_config_with_diagnostics(
    path: &Path,
) -> Result<(CoreConfig, Vec<Diagnostic>), CliError> {
    let raw = fs::read_to_string(path).map_err(|source| CliError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    let geodata_dirs = geodata_dirs_for_config(path);
    let parsed = parse_xray_json_with_geodata_dirs(&raw, &geodata_dirs)
        .map_err(|error| CliError::ConfigParse(format_diagnostics(&error.diagnostics)))?;

    Ok((parsed.config, parsed.diagnostics))
}

fn geodata_dirs_for_config(path: &Path) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        dirs.push(parent.to_path_buf());
    }
    if let Ok(cwd) = env::current_dir() {
        if !dirs.iter().any(|dir| dir == &cwd) {
            dirs.push(cwd);
        }
    }

    dirs
}

fn format_diagnostics(diagnostics: &[Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(format_diagnostic)
        .collect::<Vec<_>>()
        .join("; ")
}

pub fn format_config_warnings(diagnostics: &[Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| format!("warning: {}", format_diagnostic(diagnostic)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_diagnostic(diagnostic: &Diagnostic) -> String {
    match &diagnostic.path {
        Some(path) => format!("{path}: {}", diagnostic.message),
        None => diagnostic.message.clone(),
    }
}

pub fn format_bound_inbounds(inbounds: &[(Option<String>, SocketAddr)]) -> String {
    inbounds
        .iter()
        .map(|(tag, addr)| {
            let tag = tag.as_deref().unwrap_or("<untagged>");
            format!("bound inbound {tag} at {addr}")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn parse_tun_fd_env_from_pairs<I, K, V>(vars: I) -> Result<Option<TunFdConfig>, CliError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut fd = None;
    let mut packet_format = None;
    let mut close_policy = None;

    for (key, value) in vars {
        match key.as_ref() {
            "XRAY_TUN_FD" | "xray.tun.fd" => fd = Some(value.as_ref().to_owned()),
            "XRAY_TUN_FD_PACKET_FORMAT" => packet_format = Some(value.as_ref().to_owned()),
            "XRAY_TUN_FD_CLOSE_POLICY" => close_policy = Some(value.as_ref().to_owned()),
            _ => {}
        }
    }

    let Some(fd) = fd else {
        return Ok(None);
    };

    let fd = fd.parse::<i32>().map_err(|_| {
        CliError::InvalidArguments(format!("invalid TUN fd value `{fd}` in XRAY_TUN_FD"))
    })?;
    if fd < 0 {
        return Err(CliError::InvalidArguments(
            "XRAY_TUN_FD must be non-negative".to_owned(),
        ));
    }

    Ok(Some(TunFdConfig::new(
        fd,
        parse_tun_fd_packet_format(packet_format.as_deref().unwrap_or("raw-ip"))?,
        parse_tun_fd_close_policy(close_policy.as_deref().unwrap_or("borrowed"))?,
    )))
}

fn parse_tun_fd_env() -> Result<Option<TunFdConfig>, CliError> {
    parse_tun_fd_env_from_pairs(env::vars())
}

pub fn parse_tun_runtime_options_env_from_pairs<I, K, V>(
    vars: I,
) -> Result<TunRuntimeOptions, CliError>
where
    I: IntoIterator<Item = (K, V)>,
    K: AsRef<str>,
    V: AsRef<str>,
{
    let mut options = TunRuntimeOptions::default();

    for (key, value) in vars {
        match key.as_ref() {
            "XRAY_TUN_PROFILE" | "xray.tun.profile" => {
                options.profile = parse_tun_runtime_profile(value.as_ref())?;
            }
            "XRAY_TUN_COLLECT_TCP_TIMINGS" | "xray.tun.collect_tcp_timings" => {
                options.collect_tcp_timings = parse_bool_env(value.as_ref(), key.as_ref())?;
            }
            _ => {}
        }
    }

    Ok(options)
}

fn parse_tun_runtime_options_env() -> Result<TunRuntimeOptions, CliError> {
    parse_tun_runtime_options_env_from_pairs(env::vars())
}

fn parse_tun_runtime_profile(raw: &str) -> Result<TunRuntimeProfile, CliError> {
    match raw {
        "default" => Ok(TunRuntimeProfile::Default),
        "mobile" => Ok(TunRuntimeProfile::Mobile),
        "mobile-plus" | "mobile_plus" | "mobileplus" => Ok(TunRuntimeProfile::MobilePlus),
        "desktop" => Ok(TunRuntimeProfile::Desktop),
        "low-memory" | "low_memory" | "lowmemory" => Ok(TunRuntimeProfile::LowMemory),
        "throughput" => Ok(TunRuntimeProfile::Throughput),
        other => Err(CliError::InvalidArguments(format!(
            "unsupported TUN runtime profile `{other}`"
        ))),
    }
}

fn parse_bool_env(raw: &str, key: &str) -> Result<bool, CliError> {
    match raw {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        other => Err(CliError::InvalidArguments(format!(
            "invalid boolean value `{other}` in {key}"
        ))),
    }
}

fn parse_tun_fd_packet_format(raw: &str) -> Result<TunFdPacketFormat, CliError> {
    match raw {
        "raw-ip" | "raw_ip" | "raw" => Ok(TunFdPacketFormat::RawIp),
        "darwin-utun" | "darwin_utun" | "utun" => Ok(TunFdPacketFormat::DarwinUtun),
        other => Err(CliError::InvalidArguments(format!(
            "unsupported TUN fd packet format `{other}`"
        ))),
    }
}

fn parse_tun_fd_close_policy(raw: &str) -> Result<TunFdClosePolicy, CliError> {
    match raw {
        "borrowed" => Ok(TunFdClosePolicy::Borrowed),
        "owned" => Ok(TunFdClosePolicy::Owned),
        other => Err(CliError::InvalidArguments(format!(
            "unsupported TUN fd close policy `{other}`"
        ))),
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NofileLimits {
    pub soft: u64,
    pub hard: u64,
}

#[cfg(unix)]
#[allow(
    clippy::unnecessary_cast,
    reason = "rlim_t is only u64 on some unix targets"
)]
pub fn nofile_limits() -> Option<NofileLimits> {
    let mut limits = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the provided struct only on success.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limits) } != 0 {
        return None;
    }
    Some(NofileLimits {
        soft: limits.rlim_cur as u64,
        hard: limits.rlim_max as u64,
    })
}

// The Go runtime raises the soft fd limit to the hard limit at startup, so
// Xray-core and sing-box run at the hard limit; without the same lift this
// binary would hit EMFILE orders of magnitude earlier on identical hosts.
#[cfg(unix)]
#[allow(
    clippy::unnecessary_cast,
    reason = "rlim_t is only u64 on some unix targets"
)]
pub fn raise_nofile_limit() -> Option<NofileLimits> {
    let current = nofile_limits()?;
    let target = current.hard;
    // macOS rejects setrlimit above kern.maxfilesperproc even though the
    // hard limit reports unlimited. Shadow rather than mutate so the binding
    // needs no `mut` on the unix targets that skip this clamp.
    #[cfg(target_os = "macos")]
    let target = match darwin_max_files_per_proc() {
        Some(max_files) => target.min(max_files),
        None => target,
    };
    if current.soft >= target {
        return Some(current);
    }
    let desired = libc::rlimit {
        rlim_cur: target as libc::rlim_t,
        rlim_max: current.hard as libc::rlim_t,
    };
    // SAFETY: setrlimit reads the provided struct; failure leaves limits
    // unchanged, so the follow-up getrlimit reports whatever is in effect.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &desired) };
    nofile_limits()
}

#[cfg(target_os = "macos")]
fn darwin_max_files_per_proc() -> Option<u64> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>();
    // SAFETY: sysctlbyname writes at most `len` bytes into `value`.
    let rc = unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            std::ptr::from_mut(&mut value).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && value > 0).then_some(value as u64)
}

pub async fn run_with_shutdown<F>(config: CoreConfig, shutdown: F) -> Result<(), CliError>
where
    F: Future<Output = ()>,
{
    #[cfg(unix)]
    let _ = raise_nofile_limit();
    let configured_inbounds = config.inbounds.clone();
    let tun_fd_config = parse_tun_fd_env()?;
    let tun_runtime_options = parse_tun_runtime_options_env()?;
    let mut core = Core::with_tun_runtime_options(config, tun_runtime_options)?;
    core.start().await?;
    let mut tun_fd_runtime = None;
    if let Some(config) = tun_fd_config {
        match TunFdRuntime::start(config, core.tun_handle()) {
            Ok(runtime) => tun_fd_runtime = Some(runtime),
            Err(source) => {
                let _ = core.stop().await;
                return Err(CliError::TunFd { source });
            }
        }
    }
    let bound = configured_inbounds
        .iter()
        .filter_map(|inbound| {
            core.inbound_addr(inbound.tag.as_deref())
                .map(|addr| (inbound.tag.clone(), addr))
        })
        .collect::<Vec<_>>();
    if !bound.is_empty() {
        eprintln!("{}", format_bound_inbounds(&bound));
    }
    shutdown.await;
    if let Some(runtime) = tun_fd_runtime.take() {
        runtime.stop().await;
    }
    core.stop().await?;

    Ok(())
}

pub async fn run_cli_with_shutdown<I, S, F>(args: I, shutdown: F) -> Result<(), CliError>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
    F: Future<Output = ()>,
{
    match parse_cli_args(args)? {
        CliArgs::Run { config_path } => {
            let (config, diagnostics) = load_config_with_diagnostics(&config_path)?;
            if !diagnostics.is_empty() {
                eprintln!("{}", format_config_warnings(&diagnostics));
            }
            run_with_shutdown(config, shutdown).await
        }
    }
}

use std::{
    fs,
    future::Future,
    net::SocketAddr,
    path::{Path, PathBuf},
};

use thiserror::Error;
use xray_config::{parse_xray_json, CoreConfig, Diagnostic};
use xray_core_rs::{Core, CoreError};

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
        [_program, command, flag] if command == "run" && is_config_flag(flag) => {
            Err(CliError::InvalidArguments(format!(
                "missing config path\n{USAGE}"
            )))
        }
        _ => Err(CliError::InvalidArguments(USAGE.to_owned())),
    }
}

fn is_config_flag(flag: &str) -> bool {
    flag == "-config" || flag == "--config"
}

pub fn load_config(path: &Path) -> Result<CoreConfig, CliError> {
    let raw = fs::read_to_string(path).map_err(|source| CliError::ReadConfig {
        path: path.to_path_buf(),
        source,
    })?;
    let parsed = parse_xray_json(&raw)
        .map_err(|error| CliError::ConfigParse(format_diagnostics(&error.diagnostics)))?;

    Ok(parsed.config)
}

fn format_diagnostics(diagnostics: &[Diagnostic]) -> String {
    diagnostics
        .iter()
        .map(|diagnostic| match &diagnostic.path {
            Some(path) => format!("{path}: {}", diagnostic.message),
            None => diagnostic.message.clone(),
        })
        .collect::<Vec<_>>()
        .join("; ")
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

pub async fn run_with_shutdown<F>(config: CoreConfig, shutdown: F) -> Result<(), CliError>
where
    F: Future<Output = ()>,
{
    let configured_inbounds = config.inbounds.clone();
    let mut core = Core::new(config)?;
    core.start().await?;
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
            let config = load_config(&config_path)?;
            run_with_shutdown(config, shutdown).await
        }
    }
}

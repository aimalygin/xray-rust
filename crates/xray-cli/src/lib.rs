use std::path::PathBuf;

use thiserror::Error;

const USAGE: &str = "usage: xray-rust run -config <config.json>";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliArgs {
    Run { config_path: PathBuf },
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    InvalidArguments(String),
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

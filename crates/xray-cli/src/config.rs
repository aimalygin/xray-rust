use std::{
    fs,
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use xray_config::{
    tooling::{
        configuration_contract, configuration_examples,
        validate_xray_json_with_exclusive_geodata_dirs, validate_xray_json_with_geodata_dirs,
        ValidationReport, CONFIG_TOOLING_VERSION,
    },
    Diagnostic, DiagnosticSeverity,
};

use crate::{geodata_dirs_for_config, CliError};

const HELP: &str =
    "usage: xray-rust config check -config <file|-> [--json] [--geodata-dir <dir>]...
       xray-rust config contract
       xray-rust config example <name>

check validates with the linked parser, without starting the core.
Use -config or --config; - reads UTF-8 JSON from stdin.
Without --geodata-dir, lookup matches run: config directory, working directory,
then executable directory. Repeated --geodata-dir values form an exclusive list.
Exit status: 0 accepted (warnings allowed), 1 rejected, 2 usage or I/O failure.
contract emits the machine-readable executable grammar (not JSON Schema).
example names: socks-direct, vless-tls, xhttp-download, dns-routing.
";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigCommand {
    Check {
        config_path: PathBuf,
        json: bool,
        geodata_dirs: Vec<PathBuf>,
    },
    Contract,
    Example {
        name: String,
    },
    Help,
}

pub(super) fn parse_args(args: &[String]) -> Result<ConfigCommand, CliError> {
    let invalid = || CliError::InvalidArguments(HELP.to_owned());
    match args {
        [command] if command == "--help" || command == "-h" => Ok(ConfigCommand::Help),
        [command] if command == "contract" => Ok(ConfigCommand::Contract),
        [command, name] if command == "example" => {
            if configuration_examples().get(name).is_none() {
                return Err(invalid());
            }
            Ok(ConfigCommand::Example { name: name.clone() })
        }
        [command, rest @ ..] if command == "check" => {
            let mut config_path = None;
            let mut json = false;
            let mut geodata_dirs = Vec::new();
            let mut flags = rest.iter();
            while let Some(flag) = flags.next() {
                match flag.as_str() {
                    "-config" | "--config" if config_path.is_none() => {
                        let path = flags
                            .next()
                            .filter(|path| is_path_argument(path))
                            .ok_or_else(invalid)?;
                        config_path = Some(PathBuf::from(path));
                    }
                    "--json" if !json => json = true,
                    "--geodata-dir" => {
                        let dir = flags
                            .next()
                            .filter(|dir| is_path_argument(dir))
                            .ok_or_else(invalid)?;
                        geodata_dirs.push(PathBuf::from(dir));
                    }
                    _ => return Err(invalid()),
                }
            }
            Ok(ConfigCommand::Check {
                config_path: config_path.ok_or_else(invalid)?,
                json,
                geodata_dirs,
            })
        }
        _ => Err(invalid()),
    }
}

fn is_path_argument(value: &str) -> bool {
    !value.is_empty() && (value == "-" || !value.starts_with('-'))
}

pub(super) fn run(command: ConfigCommand) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match command {
        ConfigCommand::Help => output.write_all(HELP.as_bytes()).map_err(output_error),
        ConfigCommand::Contract => write_json(&mut output, &configuration_contract()),
        ConfigCommand::Example { name } => {
            let examples = configuration_examples();
            let example = examples
                .get(&name)
                .ok_or_else(|| CliError::InvalidArguments(HELP.to_owned()))?;
            write_json(&mut output, example)
        }
        ConfigCommand::Check {
            config_path,
            json,
            geodata_dirs,
        } => {
            let raw = if config_path == Path::new("-") {
                let mut raw = String::new();
                io::stdin().lock().read_to_string(&mut raw).map(|_| raw)
            } else {
                fs::read_to_string(&config_path)
            };
            let (report, code) = match raw {
                Ok(raw) => {
                    let report = if geodata_dirs.is_empty() {
                        validate_xray_json_with_geodata_dirs(
                            &raw,
                            &geodata_dirs_for_config(&config_path),
                        )
                    } else {
                        validate_xray_json_with_exclusive_geodata_dirs(&raw, &geodata_dirs)
                    };
                    let code = u8::from(!report.valid);
                    (report, code)
                }
                Err(error) => (
                    ValidationReport {
                        schema_version: CONFIG_TOOLING_VERSION,
                        core_version: xray_config::version(),
                        scope: "input",
                        valid: false,
                        diagnostics: vec![Diagnostic::error(
                            "$",
                            format!("failed to read UTF-8 configuration: {error}"),
                        )],
                    },
                    2,
                ),
            };
            if json {
                write_json(
                    &mut output,
                    &serde_json::to_value(&report).expect("report is JSON serializable"),
                )?;
            } else {
                writeln!(
                    output,
                    "{}",
                    if report.valid {
                        "configuration accepted by parser"
                    } else {
                        "configuration check failed"
                    }
                )
                .map_err(output_error)?;
                for diagnostic in &report.diagnostics {
                    let severity = match diagnostic.severity {
                        DiagnosticSeverity::Warning => "warning",
                        DiagnosticSeverity::Error => "error",
                    };
                    writeln!(
                        output,
                        "{severity}: {}",
                        crate::format_diagnostic(diagnostic)
                    )
                    .map_err(output_error)?;
                }
            }
            output.flush().map_err(output_error)?;
            if code == 0 {
                Ok(())
            } else {
                Err(CliError::ConfigCheckFailed { code })
            }
        }
    }
}

fn output_error(source: io::Error) -> CliError {
    CliError::Output { source }
}

fn write_json(output: &mut impl Write, value: &serde_json::Value) -> Result<(), CliError> {
    // Serialization to a buffer keeps I/O failures separate from JSON errors.
    let raw = serde_json::to_vec_pretty(value).expect("JSON value is serializable");
    output.write_all(&raw).map_err(output_error)?;
    output.write_all(b"\n").map_err(output_error)?;
    output.flush().map_err(output_error)
}

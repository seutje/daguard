//! Command-line parsing and dispatch.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::adapters::{codex, cursor, opencode};
use crate::audit;
use crate::doctor::{self, DoctorOptions};
use crate::model::CanonicalRequest;
use crate::policy::{self, Policy, PolicyKind};

const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_CONFIG: i32 = 3;
const EXIT_EVALUATION: i32 = 4;
const MAX_REQUEST_BYTES: u64 = 64 * 1024;

pub(crate) fn run() -> i32 {
    match dispatch(env::args_os().skip(1).collect()) {
        Ok(()) => EXIT_OK,
        Err(error) => {
            eprintln!("daguard: {}", error.message);
            error.exit_code
        }
    }
}

fn dispatch(args: Vec<std::ffi::OsString>) -> Result<(), CliError> {
    let mut args = args
        .into_iter()
        .map(|value| {
            value
                .into_string()
                .map_err(|_| CliError::usage("arguments must be valid UTF-8"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if args.is_empty() {
        return Err(CliError::usage(help()));
    }
    match args.remove(0).as_str() {
        "version" | "--version" | "-V" if args.is_empty() => {
            println!("daguard {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        "help" | "--help" | "-h" if args.is_empty() => {
            println!("{}", help());
            Ok(())
        }
        "check" => check(&args),
        "explain" => explain(&args),
        "policy" => policy_command(args),
        "doctor" => doctor(&args),
        "--adapter" => adapter_command(args),
        _ => Err(CliError::usage(help())),
    }
}

fn adapter_command(mut args: Vec<String>) -> Result<(), CliError> {
    let Some(adapter) = args.first().cloned() else {
        return Err(CliError::usage(
            "usage: daguard --adapter <codex|cursor|opencode> --event pre-tool [--policy PATH] [--project-policy PATH] [--audit-log PATH]",
        ));
    };
    args.remove(0);
    match adapter.as_str() {
        "codex" => match evaluate_codex_hook(&args) {
            Ok(response) => write_json(&response),
            Err(error) => {
                eprintln!("daguard: {}", error.message);
                write_json(&codex::error_response())
            }
        },
        "cursor" => match evaluate_cursor_hook(&args) {
            Ok(response) => write_json(&response),
            Err(error) => {
                eprintln!("daguard: {}", error.message);
                write_json(&cursor::error_response())
            }
        },
        "opencode" => match evaluate_opencode_hook(&args) {
            Ok(response) => write_json(&response),
            Err(error) => {
                eprintln!("daguard: {}", error.message);
                write_json(&opencode::error_response())
            }
        },
        _ => Err(CliError::usage(
            "usage: daguard --adapter <codex|cursor|opencode> --event pre-tool [--policy PATH] [--project-policy PATH] [--audit-log PATH]",
        )),
    }
}

fn evaluate_opencode_hook(args: &[String]) -> Result<opencode::Response, CliError> {
    let options = adapter_options(args, "OpenCode")?;
    let bytes = read_bounded(None).map_err(|error| CliError::evaluation(error.to_string()))?;
    let request = opencode::normalize(&bytes)
        .map_err(|error| CliError::evaluation(format!("OpenCode adapter error: {error}")))?;
    let decision = policy::evaluate(
        &request,
        options.organization.as_ref(),
        options.project.as_ref(),
    )
    .map_err(|error| CliError::evaluation(error.to_string()))?;
    write_audit(options.audit_log.as_deref(), &request, &decision, Some(1))?;
    Ok(opencode::render(&decision))
}

fn evaluate_cursor_hook(args: &[String]) -> Result<cursor::Response, CliError> {
    let options = adapter_options(args, "Cursor")?;
    let bytes = read_bounded(None).map_err(|error| CliError::evaluation(error.to_string()))?;
    let request = cursor::normalize(&bytes)
        .map_err(|error| CliError::evaluation(format!("Cursor adapter error: {error}")))?;
    let decision = policy::evaluate(
        &request,
        options.organization.as_ref(),
        options.project.as_ref(),
    )
    .map_err(|error| CliError::evaluation(error.to_string()))?;
    write_audit(options.audit_log.as_deref(), &request, &decision, Some(1))?;
    Ok(cursor::render(&decision))
}

fn evaluate_codex_hook(args: &[String]) -> Result<codex::Response, CliError> {
    let options = adapter_options(args, "Codex")?;
    let bytes = read_bounded(None).map_err(|error| CliError::evaluation(error.to_string()))?;
    let request = codex::normalize(&bytes)
        .map_err(|error| CliError::evaluation(format!("Codex adapter error: {error}")))?;
    let decision = policy::evaluate(
        &request,
        options.organization.as_ref(),
        options.project.as_ref(),
    )
    .map_err(|error| CliError::evaluation(error.to_string()))?;
    write_audit(options.audit_log.as_deref(), &request, &decision, Some(1))?;
    Ok(codex::render(&decision))
}

struct EvaluationOptions {
    organization: Option<Policy>,
    project: Option<Policy>,
    audit_log: Option<PathBuf>,
}

fn adapter_options(args: &[String], adapter_name: &str) -> Result<EvaluationOptions, CliError> {
    let mut event = None;
    let mut organization = None;
    let mut project = None;
    let mut audit_log = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--event" => {
                index += 1;
                event = args.get(index).map(String::as_str);
                if event.is_none() {
                    return Err(CliError::usage("--event requires a value"));
                }
            }
            "--policy" => {
                index += 1;
                organization = Some(required_path(args, index, "--policy")?);
            }
            "--project-policy" => {
                index += 1;
                project = Some(required_path(args, index, "--project-policy")?);
            }
            "--audit-log" => {
                index += 1;
                audit_log = Some(required_path(args, index, "--audit-log")?);
            }
            value => return Err(CliError::usage(format!("unexpected argument: {value}"))),
        }
        index += 1;
    }
    if event != Some("pre-tool") {
        return Err(CliError::usage(format!(
            "{adapter_name} adapter requires --event pre-tool"
        )));
    }

    let organization = organization
        .as_deref()
        .map(|path| Policy::load(path, PolicyKind::Organization))
        .transpose()
        .map_err(|error| CliError::config(error.to_string()))?;
    let project = project
        .as_deref()
        .map(|path| Policy::load(path, PolicyKind::Project))
        .transpose()
        .map_err(|error| CliError::config(error.to_string()))?;
    Ok(EvaluationOptions {
        organization,
        project,
        audit_log,
    })
}

fn write_json(value: &impl Serialize) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value)
        .map_err(|error| CliError::evaluation(error.to_string()))?;
    writeln!(output).map_err(|error| CliError::evaluation(error.to_string()))?;
    Ok(())
}

fn check(args: &[String]) -> Result<(), CliError> {
    let mut organization = None;
    let mut project = None;
    let mut input = None;
    let mut audit_log = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--policy" => {
                index += 1;
                organization = Some(required_path(args, index, "--policy")?);
            }
            "--project-policy" => {
                index += 1;
                project = Some(required_path(args, index, "--project-policy")?);
            }
            "--audit-log" => {
                index += 1;
                audit_log = Some(required_path(args, index, "--audit-log")?);
            }
            "-" if input.is_none() => input = Some(PathBuf::from("-")),
            value if !value.starts_with('-') && input.is_none() => {
                input = Some(PathBuf::from(value));
            }
            value => return Err(CliError::usage(format!("unexpected argument: {value}"))),
        }
        index += 1;
    }

    let organization = organization
        .as_deref()
        .map(|path| Policy::load(path, PolicyKind::Organization))
        .transpose()
        .map_err(|error| CliError::config(error.to_string()))?;
    let project = project
        .as_deref()
        .map(|path| Policy::load(path, PolicyKind::Project))
        .transpose()
        .map_err(|error| CliError::config(error.to_string()))?;
    let bytes =
        read_bounded(input.as_deref()).map_err(|error| CliError::evaluation(error.to_string()))?;
    let request = CanonicalRequest::from_slice(&bytes)
        .map_err(|error| CliError::evaluation(error.to_string()))?;
    let decision = policy::evaluate(&request, organization.as_ref(), project.as_ref())
        .map_err(|error| CliError::evaluation(error.to_string()))?;
    write_audit(audit_log.as_deref(), &request, &decision, None)?;
    write_json(&decision)
}

fn write_audit(
    path: Option<&Path>,
    request: &CanonicalRequest,
    decision: &crate::model::Decision,
    adapter_schema: Option<u16>,
) -> Result<(), CliError> {
    if let Some(path) = path {
        audit::append(path, request, decision, None, adapter_schema).map_err(|error| {
            CliError::evaluation(format!("could not append audit log: {error}"))
        })?;
    }
    Ok(())
}

fn required_path(args: &[String], index: usize, flag: &str) -> Result<PathBuf, CliError> {
    args.get(index)
        .filter(|value| !value.starts_with('-'))
        .map(PathBuf::from)
        .ok_or_else(|| CliError::usage(format!("{flag} requires a path")))
}

fn read_bounded(path: Option<&Path>) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    match path {
        None => {
            io::stdin()
                .take(MAX_REQUEST_BYTES + 1)
                .read_to_end(&mut bytes)?;
        }
        Some(path) if path == Path::new("-") => {
            io::stdin()
                .take(MAX_REQUEST_BYTES + 1)
                .read_to_end(&mut bytes)?;
        }
        Some(path) => {
            let metadata = fs::metadata(path)?;
            if metadata.len() > MAX_REQUEST_BYTES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request exceeds 64 KiB",
                ));
            }
            fs::File::open(path)?
                .take(MAX_REQUEST_BYTES + 1)
                .read_to_end(&mut bytes)?;
        }
    }
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "request exceeds 64 KiB",
        ));
    }
    Ok(bytes)
}

fn explain(args: &[String]) -> Result<(), CliError> {
    if args.len() != 1 {
        return Err(CliError::usage("usage: daguard explain <rule-id>"));
    }
    let explanation = policy::explain(&args[0])
        .ok_or_else(|| CliError::usage(format!("unknown built-in rule: {}", args[0])))?;
    println!("{explanation}");
    Ok(())
}

fn policy_command(mut args: Vec<String>) -> Result<(), CliError> {
    if args.first().map(String::as_str) != Some("lint") {
        return Err(CliError::usage(
            "usage: daguard policy lint [--layer organization|project] <path>",
        ));
    }
    args.remove(0);
    let mut kind = PolicyKind::Organization;
    if args.first().map(String::as_str) == Some("--layer") {
        if args.len() < 2 {
            return Err(CliError::usage("--layer requires a value"));
        }
        kind = match args[1].as_str() {
            "organization" => PolicyKind::Organization,
            "project" => PolicyKind::Project,
            _ => return Err(CliError::usage("layer must be organization or project")),
        };
        args.drain(0..2);
    }
    if args.len() != 1 {
        return Err(CliError::usage(
            "usage: daguard policy lint [--layer organization|project] <path>",
        ));
    }
    Policy::load(Path::new(&args[0]), kind).map_err(|error| CliError::config(error.to_string()))?;
    println!("policy is valid");
    Ok(())
}

fn doctor(args: &[String]) -> Result<(), CliError> {
    if args.len() == 2 && matches!(args[0].as_str(), "codex" | "cursor" | "opencode") {
        let bytes = read_bounded(Some(Path::new(&args[1])))
            .map_err(|error| CliError::config(error.to_string()))?;
        match args[0].as_str() {
            "codex" => codex::validate_hooks_config(&bytes)
                .map_err(|error| CliError::config(error.to_string()))?,
            "cursor" => cursor::validate_hooks_config(&bytes)
                .map_err(|error| CliError::config(error.to_string()))?,
            "opencode" => opencode::validate_config(&bytes)
                .map_err(|error| CliError::config(error.to_string()))?,
            _ => unreachable!(),
        }
        println!("{} hook configuration is valid for daguard", args[0]);
        return Ok(());
    }

    let mut options = DoctorOptions::default();
    let mut index = 0;
    while index < args.len() {
        let destination = match args[index].as_str() {
            "--policy" => &mut options.policy,
            "--audit-log" => &mut options.audit_log,
            "--codex-hooks" => &mut options.codex_hooks,
            "--cursor-hooks" => &mut options.cursor_hooks,
            "--opencode-config" => &mut options.opencode_config,
            value => return Err(CliError::usage(format!("unexpected argument: {value}"))),
        };
        index += 1;
        *destination = Some(required_path(args, index, &args[index - 1])?);
        index += 1;
    }
    let report = doctor::diagnose(&options);
    for line in report.lines {
        println!("{line}");
    }
    if report.has_errors {
        return Err(CliError::config("doctor found installation errors"));
    }
    Ok(())
}

fn help() -> &'static str {
    "Usage:\n  daguard version\n  daguard check [--policy PATH] [--project-policy PATH] [--audit-log PATH] [FILE|-]\n  daguard explain <rule-id>\n  daguard policy lint [--layer organization|project] <path>\n  daguard doctor [--policy PATH] [--audit-log PATH] [--codex-hooks PATH] [--cursor-hooks PATH] [--opencode-config PATH]\n  daguard doctor <codex|cursor|opencode> <config.json>\n  daguard --adapter <codex|cursor|opencode> --event pre-tool [--policy PATH] [--project-policy PATH] [--audit-log PATH]\n\nPolicy precedence: built-in invariants, organization policy, project tightening, default.\nA lower layer can never override a higher-layer deny."
}

struct CliError {
    exit_code: i32,
    message: String,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_USAGE,
            message: message.into(),
        }
    }

    fn config(message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_CONFIG,
            message: message.into(),
        }
    }

    fn evaluation(message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_EVALUATION,
            message: message.into(),
        }
    }
}

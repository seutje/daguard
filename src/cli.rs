//! Command-line parsing and dispatch.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Serialize;

use crate::adapters::{codex, cursor, opencode};
use crate::audit;
use crate::doctor::{self, DoctorOptions};
use crate::model::{
    CanonicalPostToolEvent, CanonicalRequest, Capability, DecisionEffect, Facts, PROTOCOL_VERSION,
    Tool,
};
use crate::policy::{self, Policy, PolicyKind};
use crate::state::StateStore;

const EXIT_OK: i32 = 0;
const EXIT_USAGE: i32 = 2;
const EXIT_CONFIG: i32 = 3;
const EXIT_EVALUATION: i32 = 4;
const MAX_REQUEST_BYTES: u64 = crate::json::MAX_REQUEST_BYTES as u64;

pub(crate) fn run() -> i32 {
    // The default panic hook can expose tool content via a panic payload.
    std::panic::set_hook(Box::new(|_| {
        let _ = writeln!(io::stderr(), "daguard: internal panic; operation blocked");
    }));
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    handle_result(&args, std::panic::catch_unwind(|| dispatch(args.clone())))
}

fn handle_result(
    args: &[std::ffi::OsString],
    result: std::thread::Result<Result<i32, CliError>>,
) -> i32 {
    match result {
        Ok(Ok(code)) => code,
        Ok(Err(error)) => {
            eprintln!("daguard: {}", error.message);
            error.exit_code
        }
        Err(_) => {
            // Evaluation completes before any response is written. Never reuse a
            // partial decision or include the untrusted panic payload.
            let Some(response) = panic_response(args) else {
                return EXIT_EVALUATION;
            };
            if write_json(&response).is_ok() {
                EXIT_OK
            } else {
                EXIT_EVALUATION
            }
        }
    }
}

fn panic_response(args: &[std::ffi::OsString]) -> Option<serde_json::Value> {
    if args.first().is_none_or(|arg| arg != "--adapter") {
        return None;
    }
    let post = args.windows(2).any(|pair| {
        pair[0] == "--event" && pair[1].to_str().is_some_and(|value| value == "post-tool")
    });
    match args.get(1).and_then(|arg| arg.to_str()) {
        Some("codex") if post => Some(codex::post_error_response()),
        Some("cursor") if post => Some(cursor::post_error_response()),
        Some("opencode") if post => Some(opencode::post_error_response()),
        Some("codex") => serde_json::to_value(codex::error_response()).ok(),
        Some("cursor") => serde_json::to_value(cursor::error_response()).ok(),
        Some("opencode") => serde_json::to_value(opencode::error_response()).ok(),
        _ => None,
    }
}

fn dispatch(args: Vec<std::ffi::OsString>) -> Result<i32, CliError> {
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
            println!("{}", crate::version::details());
            Ok(EXIT_OK)
        }
        "help" | "--help" | "-h" if args.is_empty() => {
            println!("{}", help());
            Ok(EXIT_OK)
        }
        "check" => check(&args).map(|()| EXIT_OK),
        "inspect-result" => inspect_result(&args),
        "exec" => guarded_exec(&args),
        "mcp-proxy" => mcp_proxy(&args),
        "capabilities" if args.is_empty() => {
            write_json(crate::capabilities::ADAPTER_CAPABILITIES).map(|()| EXIT_OK)
        }
        "explain" => explain(&args).map(|()| EXIT_OK),
        "policy" => policy_command(args).map(|()| EXIT_OK),
        "doctor" => doctor(&args).map(|()| EXIT_OK),
        "--adapter" => adapter_command(args).map(|()| EXIT_OK),
        _ => Err(CliError::usage(help())),
    }
}

fn inspect_result(args: &[String]) -> Result<i32, CliError> {
    let mut organization = None;
    let mut project = None;
    let mut input = None;
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
            "-" if input.is_none() => input = Some(PathBuf::from("-")),
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
    let bytes = read_result_bounded(input.as_deref())
        .map_err(|error| CliError::evaluation(error.to_string()))?;
    let decision = crate::scanner::inspect(
        &bytes,
        &policy::scan_config(organization.as_ref(), project.as_ref()),
    );
    let blocked = matches!(decision.decision, crate::model::ResultEffect::Block);
    write_json(&decision)?;
    Ok(if blocked {
        crate::guarded::BLOCKED_EXIT_CODE
    } else {
        EXIT_OK
    })
}

fn guarded_exec(args: &[String]) -> Result<i32, CliError> {
    let (options, command) = execution_options(args, "exec")?;
    let cwd_path = options
        .cwd
        .clone()
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));
    let cwd = cwd_path
        .to_str()
        .ok_or_else(|| CliError::evaluation("working directory must be valid UTF-8"))?;
    let command_text = shell_join(command);
    let request = CanonicalRequest {
        protocol: PROTOCOL_VERSION,
        agent: "guarded_execution".to_owned(),
        event: "pre_tool_use".to_owned(),
        session_id: options.session_id.clone(),
        call_id: None,
        cwd: cwd.to_owned(),
        tool: Tool {
            native_name: command[0].clone(),
            capability: Capability::ShellExecute,
        },
        input: serde_json::json!({"argv": command}),
        facts: Facts {
            command: Some(command_text),
            argv: command.to_vec(),
            ..Facts::default()
        },
    };
    request
        .validate()
        .map_err(|error| CliError::evaluation(error.to_string()))?;
    let evaluation = EvaluationOptions {
        event: AdapterEvent::PreTool,
        organization: options.organization,
        project: options.project,
        audit_log: options.audit_log.clone(),
        state_dir: options.state_dir.clone(),
        session_state: options.session_id.is_some(),
    };
    let decision = evaluate_and_audit(&evaluation, &request, None)?;
    if decision.effect != DecisionEffect::Allow {
        eprintln!(
            "daguard blocked guarded command [{}]: {}",
            decision.rule_id, decision.reason
        );
        return Ok(crate::guarded::BLOCKED_EXIT_CODE);
    }
    let scan_config = policy::scan_config(
        evaluation.organization.as_ref(),
        evaluation.project.as_ref(),
    );
    let source_classifications = crate::sensitivity::classify_request(
        &request,
        evaluation.organization.as_ref(),
        evaluation.project.as_ref(),
    )
    .map_err(|error| CliError::evaluation(error.to_string()))?;
    let protect_stdout = source_classifications
        .iter()
        .any(|classification| classification.resource_kind == "sql_table");
    let mut execution = crate::guarded::execute(&crate::guarded::ExecutionOptions {
        program: &command[0],
        arguments: &command[1..],
        cwd: &cwd_path,
        timeout: options.timeout,
        config: &scan_config,
        protect_stdout,
    })
    .map_err(|error| CliError::evaluation(format!("guarded execution failed: {error}")))?;
    execution.classifications.extend(source_classifications);
    if let Some(session_id) = options.session_id.as_deref()
        && !execution.classifications.is_empty()
    {
        StateStore::open(options.state_dir.as_deref())
            .and_then(|store| {
                store.merge("guarded_execution", session_id, &execution.classifications)
            })
            .map_err(|error| CliError::evaluation(error.to_string()))?;
    }
    if let Some(path) = options.audit_log.as_deref() {
        audit::append_result(
            path,
            "guarded_execution",
            options.session_id.as_deref(),
            &execution.classifications,
            execution.effect,
            execution.exit_code,
        )
        .map_err(|error| CliError::evaluation(format!("could not append audit log: {error}")))?;
    }
    execution
        .release()
        .map_err(|error| CliError::evaluation(format!("could not release guarded output: {error}")))
}

fn mcp_proxy(args: &[String]) -> Result<i32, CliError> {
    let (options, command) = execution_options(args, "mcp-proxy")?;
    let cwd_path = options
        .cwd
        .clone()
        .unwrap_or_else(|| env::current_dir().unwrap_or_else(|_| PathBuf::from("/")));
    let cwd = cwd_path
        .to_str()
        .ok_or_else(|| CliError::evaluation("working directory must be valid UTF-8"))?
        .to_owned();
    let scan_config = policy::scan_config(options.organization.as_ref(), options.project.as_ref());
    let evaluation = EvaluationOptions {
        event: AdapterEvent::PreTool,
        organization: options.organization,
        project: options.project,
        audit_log: options.audit_log.clone(),
        state_dir: options.state_dir.clone(),
        session_state: options.session_id.is_some(),
    };
    let upstream_request = CanonicalRequest {
        protocol: PROTOCOL_VERSION,
        agent: "mcp_proxy".to_owned(),
        event: "pre_tool_use".to_owned(),
        session_id: options.session_id.clone(),
        call_id: None,
        cwd: cwd.clone(),
        tool: Tool {
            native_name: command[0].clone(),
            capability: Capability::ShellExecute,
        },
        input: serde_json::json!({"argv": command}),
        facts: Facts {
            command: Some(shell_join(command)),
            argv: command.to_vec(),
            ..Facts::default()
        },
    };
    upstream_request
        .validate()
        .map_err(|error| CliError::evaluation(error.to_string()))?;
    let upstream_decision = evaluate_and_audit(&evaluation, &upstream_request, None)?;
    if upstream_decision.effect != DecisionEffect::Allow {
        eprintln!(
            "daguard blocked MCP upstream [{}]: {}",
            upstream_decision.rule_id, upstream_decision.reason
        );
        return Ok(crate::guarded::BLOCKED_EXIT_CODE);
    }
    crate::mcp::proxy(
        &crate::mcp::ProxyOptions {
            command,
            cwd: &cwd_path,
            config: &scan_config,
            state_dir: options.state_dir.as_deref(),
            session_id: options.session_id.as_deref(),
            audit_log: options.audit_log.as_deref(),
        },
        |value| {
            let method = value
                .get("method")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("unknown");
            let native_name = value
                .pointer("/params/name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or(method);
            let request = CanonicalRequest {
                protocol: PROTOCOL_VERSION,
                agent: "mcp_proxy".to_owned(),
                event: "pre_tool_use".to_owned(),
                session_id: options.session_id.clone(),
                call_id: value.get("id").map(ToString::to_string),
                cwd: cwd.clone(),
                tool: Tool {
                    native_name: native_name.to_owned(),
                    capability: Capability::McpCall,
                },
                input: value
                    .get("params")
                    .cloned()
                    .unwrap_or(serde_json::Value::Null),
                facts: Facts::default(),
            };
            request
                .validate()
                .map_err(|error| io::Error::other(error.to_string()))?;
            let decision = evaluate_and_audit(&evaluation, &request, None)
                .map_err(|error| io::Error::other(error.message))?;
            Ok((decision.effect != DecisionEffect::Allow).then_some(decision.rule_id))
        },
    )
    .map_err(|error| CliError::evaluation(format!("MCP gateway failed: {error}")))
}
struct CommandOptions {
    organization: Option<Policy>,
    project: Option<Policy>,
    audit_log: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    session_id: Option<String>,
    cwd: Option<PathBuf>,
    timeout: Duration,
}

fn execution_options<'a>(
    args: &'a [String],
    command_name: &str,
) -> Result<(CommandOptions, &'a [String]), CliError> {
    let mut organization_path = None;
    let mut project_path = None;
    let mut audit_log = None;
    let mut state_dir = None;
    let mut session_id = None;
    let mut cwd = None;
    let mut timeout = Duration::from_secs(30);
    let mut managed = false;
    let mut index = 0;
    while index < args.len() && args[index] != "--" {
        let flag = args[index].as_str();
        if flag == "--managed" {
            managed = true;
            index += 1;
            continue;
        }
        index += 1;
        match flag {
            "--policy" => organization_path = Some(required_path(args, index, flag)?),
            "--project-policy" => project_path = Some(required_path(args, index, flag)?),
            "--audit-log" => audit_log = Some(required_path(args, index, flag)?),
            "--state-dir" => state_dir = Some(required_path(args, index, flag)?),
            "--cwd" => cwd = Some(required_path(args, index, flag)?),
            "--session-id" => {
                session_id = Some(
                    args.get(index)
                        .filter(|value| !value.is_empty())
                        .cloned()
                        .ok_or_else(|| CliError::usage("--session-id requires a value"))?,
                );
            }
            "--timeout-seconds" => {
                if command_name != "exec" {
                    return Err(CliError::usage(
                        "--timeout-seconds is supported only by daguard exec",
                    ));
                }
                let seconds = args
                    .get(index)
                    .and_then(|value| value.parse::<u64>().ok())
                    .filter(|seconds| (1..=3600).contains(seconds))
                    .ok_or_else(|| {
                        CliError::usage("--timeout-seconds must be between 1 and 3600")
                    })?;
                timeout = Duration::from_secs(seconds);
            }
            value => return Err(CliError::usage(format!("unexpected argument: {value}"))),
        }
        index += 1;
    }
    if args.get(index).map(String::as_str) != Some("--") || index + 1 >= args.len() {
        return Err(CliError::usage(format!(
            "usage: daguard {command_name} [OPTIONS] -- COMMAND [ARG ...]"
        )));
    }
    validate_managed(managed, organization_path.as_deref())?;
    let organization = organization_path
        .as_deref()
        .map(|path| Policy::load(path, PolicyKind::Organization))
        .transpose()
        .map_err(|error| CliError::config(error.to_string()))?;
    let project = project_path
        .as_deref()
        .map(|path| Policy::load(path, PolicyKind::Project))
        .transpose()
        .map_err(|error| CliError::config(error.to_string()))?;
    Ok((
        CommandOptions {
            organization,
            project,
            audit_log,
            state_dir,
            session_id,
            cwd,
            timeout,
        },
        &args[index + 1..],
    ))
}

fn shell_join(command: &[String]) -> String {
    command
        .iter()
        .map(|argument| {
            if argument.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-' | b'.' | b'/' | b':' | b'@' | b'=' | b'+')
            }) {
                argument.clone()
            } else {
                format!("'{}'", argument.replace('\'', "'\\''"))
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_result_bounded(path: Option<&Path>) -> io::Result<Vec<u8>> {
    let limit = crate::scanner::MAX_SCAN_BYTES as u64;
    let mut bytes = Vec::new();
    match path {
        None => io::stdin().take(limit + 1).read_to_end(&mut bytes)?,
        Some(path) if path == Path::new("-") => {
            io::stdin().take(limit + 1).read_to_end(&mut bytes)?
        }
        Some(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "inspect-result accepts stdin only",
            ));
        }
    };
    if bytes.len() as u64 > limit {
        return Ok(bytes);
    }
    Ok(bytes)
}

fn adapter_command(mut args: Vec<String>) -> Result<(), CliError> {
    let Some(adapter) = args.first().cloned() else {
        return Err(CliError::usage(
            "usage: daguard --adapter <codex|cursor|opencode> --event <pre-tool|post-tool> [--managed] [--policy PATH] [--project-policy PATH] [--audit-log PATH] [--state-dir PATH] [--no-session-state]",
        ));
    };
    args.remove(0);
    match adapter.as_str() {
        "codex" => match evaluate_codex_hook(&args) {
            Ok(response) => write_json(&response),
            Err(error) => {
                eprintln!("daguard: {}", error.message);
                write_json(&adapter_error_response("codex", &args))
            }
        },
        "cursor" => match evaluate_cursor_hook(&args) {
            Ok(response) => write_json(&response),
            Err(error) => {
                eprintln!("daguard: {}", error.message);
                write_json(&adapter_error_response("cursor", &args))
            }
        },
        "opencode" => match evaluate_opencode_hook(&args) {
            Ok(response) => write_json(&response),
            Err(error) => {
                eprintln!("daguard: {}", error.message);
                write_json(&adapter_error_response("opencode", &args))
            }
        },
        _ => Err(CliError::usage(
            "usage: daguard --adapter <codex|cursor|opencode> --event <pre-tool|post-tool> [--managed] [--policy PATH] [--project-policy PATH] [--audit-log PATH] [--state-dir PATH] [--no-session-state]",
        )),
    }
}

fn adapter_error_response(adapter: &str, args: &[String]) -> serde_json::Value {
    let post = args.windows(2).any(|pair| pair == ["--event", "post-tool"]);
    match (adapter, post) {
        ("codex", true) => codex::post_error_response(),
        ("cursor", true) => cursor::post_error_response(),
        ("opencode", true) => opencode::post_error_response(),
        ("codex", false) => serde_json::to_value(codex::error_response()).unwrap_or_default(),
        ("cursor", false) => serde_json::to_value(cursor::error_response()).unwrap_or_default(),
        ("opencode", false) => serde_json::to_value(opencode::error_response()).unwrap_or_default(),
        _ => serde_json::json!({}),
    }
}

fn evaluate_opencode_hook(args: &[String]) -> Result<serde_json::Value, CliError> {
    let options = adapter_options(args, "OpenCode")?;
    let bytes = read_bounded(None).map_err(|error| CliError::evaluation(error.to_string()))?;
    match options.event {
        AdapterEvent::PreTool => {
            let request = opencode::normalize(&bytes).map_err(|error| {
                CliError::evaluation(format!("OpenCode adapter error: {error}"))
            })?;
            let decision = evaluate_and_audit(&options, &request, Some(1))?;
            serde_json::to_value(opencode::render(&decision))
                .map_err(|error| CliError::evaluation(error.to_string()))
        }
        AdapterEvent::PostTool => {
            let event = opencode::normalize_post(&bytes).map_err(|error| {
                CliError::evaluation(format!("OpenCode adapter error: {error}"))
            })?;
            observe_and_audit(&options, &event, Some(1))?;
            Ok(opencode::post_response())
        }
    }
}

fn evaluate_cursor_hook(args: &[String]) -> Result<serde_json::Value, CliError> {
    let options = adapter_options(args, "Cursor")?;
    let bytes = read_bounded(None).map_err(|error| CliError::evaluation(error.to_string()))?;
    match options.event {
        AdapterEvent::PreTool => {
            let request = cursor::normalize(&bytes)
                .map_err(|error| CliError::evaluation(format!("Cursor adapter error: {error}")))?;
            let decision = evaluate_and_audit(&options, &request, Some(1))?;
            serde_json::to_value(cursor::render(&decision))
                .map_err(|error| CliError::evaluation(error.to_string()))
        }
        AdapterEvent::PostTool => {
            let event = cursor::normalize_post(&bytes)
                .map_err(|error| CliError::evaluation(format!("Cursor adapter error: {error}")))?;
            observe_and_audit(&options, &event, Some(1))?;
            Ok(cursor::post_response())
        }
    }
}

fn evaluate_codex_hook(args: &[String]) -> Result<serde_json::Value, CliError> {
    let options = adapter_options(args, "Codex")?;
    let bytes = read_bounded(None).map_err(|error| CliError::evaluation(error.to_string()))?;
    match options.event {
        AdapterEvent::PreTool => {
            let request = codex::normalize(&bytes)
                .map_err(|error| CliError::evaluation(format!("Codex adapter error: {error}")))?;
            let decision = evaluate_and_audit(&options, &request, Some(1))?;
            serde_json::to_value(codex::render(&decision))
                .map_err(|error| CliError::evaluation(error.to_string()))
        }
        AdapterEvent::PostTool => {
            let event = codex::normalize_post(&bytes)
                .map_err(|error| CliError::evaluation(format!("Codex adapter error: {error}")))?;
            observe_and_audit(&options, &event, Some(1))?;
            Ok(codex::post_response())
        }
    }
}

#[derive(Clone, Copy)]
enum AdapterEvent {
    PreTool,
    PostTool,
}

struct EvaluationOptions {
    event: AdapterEvent,
    organization: Option<Policy>,
    project: Option<Policy>,
    audit_log: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    session_state: bool,
}

fn adapter_options(args: &[String], adapter_name: &str) -> Result<EvaluationOptions, CliError> {
    let mut event = None;
    let mut managed = false;
    let mut organization = None;
    let mut project = None;
    let mut audit_log = None;
    let mut state_dir = None;
    let mut session_state = true;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--managed" => managed = true,
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
            "--state-dir" => {
                index += 1;
                state_dir = Some(required_path(args, index, "--state-dir")?);
            }
            "--no-session-state" => session_state = false,
            value => return Err(CliError::usage(format!("unexpected argument: {value}"))),
        }
        index += 1;
    }
    let event = match event {
        Some("pre-tool") => AdapterEvent::PreTool,
        Some("post-tool") => AdapterEvent::PostTool,
        _ => {
            return Err(CliError::usage(format!(
                "{adapter_name} adapter requires --event pre-tool or post-tool"
            )));
        }
    };

    validate_managed(managed, organization.as_deref())?;
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
        event,
        organization,
        project,
        audit_log,
        state_dir,
        session_state,
    })
}

fn write_json(value: &(impl Serialize + ?Sized)) -> Result<(), CliError> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, value)
        .map_err(|error| CliError::evaluation(error.to_string()))?;
    writeln!(output).map_err(|error| CliError::evaluation(error.to_string()))?;
    Ok(())
}

fn check(args: &[String]) -> Result<(), CliError> {
    let mut managed = false;
    let mut organization = None;
    let mut project = None;
    let mut input = None;
    let mut audit_log = None;
    let mut state_dir = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--managed" => managed = true,
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
            "--state-dir" => {
                index += 1;
                state_dir = Some(required_path(args, index, "--state-dir")?);
            }
            "-" if input.is_none() => input = Some(PathBuf::from("-")),
            value if !value.starts_with('-') && input.is_none() => {
                input = Some(PathBuf::from(value));
            }
            value => return Err(CliError::usage(format!("unexpected argument: {value}"))),
        }
        index += 1;
    }

    validate_managed(managed, organization.as_deref())?;
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
    let options = EvaluationOptions {
        event: AdapterEvent::PreTool,
        organization,
        project,
        audit_log,
        session_state: state_dir.is_some(),
        state_dir,
    };
    let decision = evaluate_and_audit(&options, &request, None)?;
    write_json(&decision)
}

fn validate_managed(managed: bool, policy_path: Option<&Path>) -> Result<(), CliError> {
    if managed {
        let path =
            policy_path.ok_or_else(|| CliError::config("--managed requires --policy PATH"))?;
        crate::integrity::managed_path(path)
            .map_err(|error| CliError::config(error.to_string()))?;
        let binary = env::current_exe().map_err(|error| CliError::config(error.to_string()))?;
        crate::integrity::managed_path(&binary)
            .map_err(|error| CliError::config(error.to_string()))?;
    }
    Ok(())
}

fn evaluate_and_audit(
    options: &EvaluationOptions,
    request: &CanonicalRequest,
    adapter_schema: Option<u16>,
) -> Result<crate::model::Decision, CliError> {
    let audit_only = options
        .organization
        .as_ref()
        .is_some_and(Policy::audit_only);
    if audit_only && options.audit_log.is_none() {
        return Err(CliError::config(
            "audit-only evaluation requires --audit-log PATH",
        ));
    }
    let evaluated = policy::evaluate(
        request,
        options.organization.as_ref(),
        options.project.as_ref(),
    )
    .map_err(|error| CliError::evaluation(error.to_string()))?;
    let mut enforced = if audit_only {
        eprintln!(
            "daguard: audit-only candidate evaluation; mandatory protections remain enforced"
        );
        policy::enforce(
            request,
            options.organization.as_ref(),
            options.project.as_ref(),
        )
        .map_err(|error| CliError::evaluation(error.to_string()))?
    } else {
        evaluated.clone()
    };
    let mut security_context = None;
    if options.session_state
        && let Some(session_id) = request.session_id.as_deref()
    {
        let store = StateStore::open(options.state_dir.as_deref())
            .map_err(|error| CliError::evaluation(error.to_string()))?;
        if let Some(taint) = store
            .load(&request.agent, session_id)
            .map_err(|error| CliError::evaluation(error.to_string()))?
            && let Some(taint_decision) = crate::sink::enforce(request, &taint)
        {
            if effect_rank(taint_decision.decision.effect) >= effect_rank(enforced.effect) {
                enforced = taint_decision.decision.clone();
            }
            security_context = Some(audit::SecurityContext {
                sensitivity_categories: taint_decision.categories,
                sink: Some(taint_decision.sink),
            });
        }
    }
    if let Some(path) = options.audit_log.as_deref() {
        audit::append(
            path,
            request,
            &evaluated,
            &enforced,
            &audit::AppendContext {
                audit_only,
                agent_version: None,
                adapter_schema,
                security: security_context.as_ref(),
            },
        )
        .map_err(|error| CliError::evaluation(format!("could not append audit log: {error}")))?;
    }
    Ok(enforced)
}

fn observe_and_audit(
    options: &EvaluationOptions,
    event: &CanonicalPostToolEvent,
    adapter_schema: Option<u16>,
) -> Result<(), CliError> {
    let classifications = crate::sensitivity::classify(
        event,
        options.organization.as_ref(),
        options.project.as_ref(),
    )
    .map_err(|error| CliError::evaluation(error.to_string()))?;
    if options.session_state
        && let Some(session_id) = event.session_id.as_deref()
    {
        StateStore::open(options.state_dir.as_deref())
            .and_then(|store| store.merge(&event.agent, session_id, &classifications))
            .map_err(|error| CliError::evaluation(error.to_string()))?;
    }
    if let Some(path) = options.audit_log.as_deref() {
        audit::append_post(path, event, &classifications, adapter_schema).map_err(|error| {
            CliError::evaluation(format!("could not append audit log: {error}"))
        })?;
    }
    Ok(())
}

const fn effect_rank(effect: DecisionEffect) -> u8 {
    match effect {
        DecisionEffect::Allow => 0,
        DecisionEffect::Ask => 1,
        DecisionEffect::Deny => 2,
    }
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
            "opencode" => opencode::validate_installed_config(&bytes)
                .map_err(|error| CliError::config(error.to_string()))?,
            _ => return Err(CliError::usage("unsupported doctor adapter")),
        }
        println!("{} hook configuration is valid for daguard", args[0]);
        return Ok(());
    }

    let mut options = DoctorOptions::default();
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--managed" {
            options.managed = true;
            index += 1;
            continue;
        }
        let destination = match args[index].as_str() {
            "--policy" => &mut options.policy,
            "--integrity-manifest" => &mut options.integrity_manifest,
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
    "Usage:\n  daguard version\n  daguard capabilities\n  daguard check [--managed] [--policy PATH] [--project-policy PATH] [--audit-log PATH] [--state-dir PATH] [FILE|-]\n  daguard inspect-result [--policy PATH] [--project-policy PATH] [-]\n  daguard exec [--managed] [--policy PATH] [--project-policy PATH] [--audit-log PATH] [--state-dir PATH] [--session-id ID] [--cwd PATH] [--timeout-seconds N] -- COMMAND [ARG ...]\n  daguard mcp-proxy [--managed] [--policy PATH] [--project-policy PATH] [--audit-log PATH] [--state-dir PATH] [--session-id ID] [--cwd PATH] -- SERVER [ARG ...]\n  daguard explain <rule-id>\n  daguard policy lint [--layer organization|project] <path>\n  daguard doctor [--managed] [--integrity-manifest PATH] [--policy PATH] [--audit-log PATH] [--codex-hooks PATH] [--cursor-hooks PATH] [--opencode-config PATH]\n  daguard doctor <codex|cursor|opencode> <config.json>\n  daguard --adapter <codex|cursor|opencode> --event <pre-tool|post-tool> [--managed] [--policy PATH] [--project-policy PATH] [--audit-log PATH] [--state-dir PATH] [--no-session-state]\n\nPolicy precedence: built-in invariants, organization policy, project tightening, default.\nA lower layer can never override a higher-layer deny."
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

#[cfg(test)]
mod tests {
    #[test]
    fn panic_boundary_returns_failure_or_a_native_deny() {
        let result = std::panic::catch_unwind(|| panic!("synthetic-sensitive-panic-payload"));
        assert!(result.is_err());
        for adapter in ["codex", "cursor", "opencode"] {
            let args = ["--adapter".into(), adapter.into()];
            let response = super::panic_response(&args).unwrap();
            let value = serde_json::to_value(response).unwrap();
            let effect = match adapter {
                "codex" => &value["hookSpecificOutput"]["permissionDecision"],
                "cursor" => &value["permission"],
                _ => &value["decision"],
            };
            assert_eq!(effect, "deny");
            assert!(
                !value
                    .to_string()
                    .contains("synthetic-sensitive-panic-payload")
            );
            assert_eq!(
                super::handle_result(&args, Err(Box::new("synthetic-sensitive-panic-payload"))),
                super::EXIT_OK
            );
        }
        assert_eq!(
            super::handle_result(&["check".into()], result),
            super::EXIT_EVALUATION
        );
    }
}

//! Codex `PreToolUse` request normalization and response rendering.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

use crate::model::{
    CanonicalPostToolEvent, CanonicalRequest, Capability, Decision, DecisionEffect, Facts,
    PROTOCOL_VERSION, ResultMetadata, ResultStatus, Tool,
};

const PRE_TOOL_USE: &str = "PreToolUse";

#[derive(Debug, Deserialize)]
struct PreToolUseInput {
    session_id: String,
    cwd: String,
    hook_event_name: String,
    tool_name: String,
    tool_use_id: String,
    tool_input: Value,
}

#[derive(Debug, Deserialize)]
struct PostToolUseInput {
    session_id: String,
    cwd: String,
    hook_event_name: String,
    tool_name: String,
    tool_use_id: String,
    tool_input: Value,
    tool_response: Value,
}

pub(crate) fn normalize(input: &[u8]) -> Result<CanonicalRequest, CodexError> {
    crate::json::preflight(input, crate::json::MAX_REQUEST_BYTES).map_err(CodexError::Json)?;
    let input: PreToolUseInput = serde_json::from_slice(input).map_err(CodexError::Json)?;
    if input.hook_event_name != PRE_TOOL_USE {
        return Err(CodexError::Invalid("expected a PreToolUse event"));
    }

    let (capability, facts) = normalize_tool(&input.tool_name, &input.tool_input)?;
    let request = CanonicalRequest {
        protocol: PROTOCOL_VERSION,
        agent: "codex".to_owned(),
        event: "pre_tool_use".to_owned(),
        session_id: Some(input.session_id),
        call_id: Some(input.tool_use_id),
        cwd: input.cwd,
        tool: Tool {
            native_name: input.tool_name,
            capability,
        },
        input: input.tool_input,
        facts,
    };
    request.validate().map_err(CodexError::Model)?;
    Ok(request)
}

pub(crate) fn normalize_post(input: &[u8]) -> Result<CanonicalPostToolEvent, CodexError> {
    crate::json::preflight(input, crate::json::MAX_REQUEST_BYTES).map_err(CodexError::Json)?;
    let input: PostToolUseInput = serde_json::from_slice(input).map_err(CodexError::Json)?;
    if input.hook_event_name != "PostToolUse" {
        return Err(CodexError::Invalid("expected a PostToolUse event"));
    }
    let (capability, facts) = normalize_tool(&input.tool_name, &input.tool_input)?;
    let byte_size = serde_json::to_vec(&input.tool_response)
        .map_err(CodexError::Json)?
        .len() as u64;
    let event = CanonicalPostToolEvent {
        protocol: PROTOCOL_VERSION,
        agent: "codex".to_owned(),
        event: "post_tool_use".to_owned(),
        session_id: Some(input.session_id),
        call_id: Some(input.tool_use_id),
        cwd: input.cwd,
        tool: Tool {
            native_name: input.tool_name,
            capability,
        },
        input: input.tool_input,
        facts,
        result: ResultMetadata {
            status: ResultStatus::Completed,
            content_type: Some("application/json".to_owned()),
            byte_size: Some(byte_size),
        },
    };
    event.validate().map_err(CodexError::Model)?;
    Ok(event)
}

pub(crate) fn post_response() -> Value {
    serde_json::json!({})
}

pub(crate) fn post_error_response() -> Value {
    serde_json::json!({
        "decision": "block",
        "reason": "Blocked by team policy: guard.evaluation_error"
    })
}

fn normalize_tool(tool_name: &str, input: &Value) -> Result<(Capability, Facts), CodexError> {
    if tool_name == "Bash" {
        let command = input
            .get("command")
            .and_then(Value::as_str)
            .ok_or(CodexError::Invalid(
                "Bash tool input requires a command string",
            ))?;
        return Ok((
            Capability::ShellExecute,
            Facts {
                command: Some(command.to_owned()),
                ..Facts::default()
            },
        ));
    }
    if tool_name == "apply_patch" {
        let command = input
            .get("command")
            .and_then(Value::as_str)
            .ok_or(CodexError::Invalid(
                "apply_patch tool input requires a command string",
            ))?;
        let paths = patch_paths(command);
        if paths.is_empty() {
            return Err(CodexError::Invalid(
                "apply_patch input contains no recognized file operation",
            ));
        }
        return Ok((
            Capability::FileWrite,
            Facts {
                paths,
                ..Facts::default()
            },
        ));
    }

    let capability = capability_for_tool(tool_name);
    let paths = if matches!(
        capability,
        Capability::FileRead | Capability::FileWrite | Capability::FileDelete | Capability::McpCall
    ) {
        input_paths(input)
    } else {
        Vec::new()
    };
    if matches!(
        capability,
        Capability::FileRead | Capability::FileWrite | Capability::FileDelete
    ) && paths.is_empty()
    {
        return Err(CodexError::Invalid(
            "file tool input contains no recognized path",
        ));
    }
    Ok((
        capability,
        Facts {
            paths,
            ..Facts::default()
        },
    ))
}

fn capability_for_tool(tool_name: &str) -> Capability {
    let lower = tool_name.to_ascii_lowercase();
    let operation = lower.rsplit("__").next().unwrap_or(&lower);
    match operation {
        "read" | "read_file" | "read_text_file" | "get_file" => Capability::FileRead,
        "write" | "write_file" | "write_text_file" | "create_file" | "edit_file" => {
            Capability::FileWrite
        }
        "delete" | "delete_file" | "remove_file" => Capability::FileDelete,
        _ if lower.starts_with("mcp__") => Capability::McpCall,
        _ => Capability::Unknown,
    }
}

fn input_paths(input: &Value) -> Vec<String> {
    let mut paths = Vec::new();
    collect_input_paths(input, None, &mut paths);
    paths
}

fn collect_input_paths(input: &Value, key: Option<&str>, paths: &mut Vec<String>) {
    match input {
        Value::String(value) if key.is_some_and(is_path_key) => paths.push(value.clone()),
        Value::Array(values) => {
            for value in values {
                collect_input_paths(value, key, paths);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                collect_input_paths(value, Some(key), paths);
            }
        }
        _ => {}
    }
}

fn is_path_key(key: &str) -> bool {
    [
        "path",
        "paths",
        "file",
        "files",
        "file_path",
        "file_paths",
        "filepath",
        "filename",
        "target",
        "destination",
    ]
    .iter()
    .any(|candidate| key.eq_ignore_ascii_case(candidate))
}

fn patch_paths(command: &str) -> Vec<String> {
    const HEADERS: &[&str] = &[
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    command
        .lines()
        .filter_map(|line| {
            HEADERS
                .iter()
                .find_map(|header| line.strip_prefix(header))
                .map(str::trim)
                .filter(|path| !path.is_empty())
                .map(str::to_owned)
        })
        .collect()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HookSpecificOutput {
    hook_event_name: &'static str,
    permission_decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    permission_decision_reason: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    hook_specific_output: Option<HookSpecificOutput>,
}

pub(crate) fn render(decision: &Decision) -> Response {
    let deny = matches!(decision.effect, DecisionEffect::Deny | DecisionEffect::Ask);
    Response {
        // A bare permissionDecision: allow is unsupported on tested hosts.
        // An empty JSON object leaves the host's normal permission checks intact.
        hook_specific_output: deny.then(|| HookSpecificOutput {
            hook_event_name: PRE_TOOL_USE,
            permission_decision: "deny",
            permission_decision_reason: deny
                .then(|| format!("Blocked by team policy: {}", decision.rule_id)),
        }),
    }
}

pub(crate) fn error_response() -> Response {
    Response {
        hook_specific_output: Some(HookSpecificOutput {
            hook_event_name: PRE_TOOL_USE,
            permission_decision: "deny",
            permission_decision_reason: Some(
                "Blocked by team policy: guard.evaluation_error".to_owned(),
            ),
        }),
    }
}

/// Performs advisory checks on a Codex `hooks.json` deployment.
pub(crate) fn validate_hooks_config(input: &[u8]) -> Result<(), CodexError> {
    let root: Value = serde_json::from_slice(input).map_err(CodexError::Json)?;
    if !configured_event(&root, "PreToolUse", "pre-tool") {
        return Err(CodexError::Invalid(
            "no all-tools PreToolUse command uses absolute guard and policy paths",
        ));
    }
    if !configured_event(&root, "PostToolUse", "post-tool") {
        return Err(CodexError::Invalid(
            "no all-tools PostToolUse command records session taint",
        ));
    }
    Ok(())
}

fn configured_event(root: &Value, event: &str, cli_event: &str) -> bool {
    root.pointer(&format!("/hooks/{event}"))
        .and_then(Value::as_array)
        .is_some_and(|groups| {
            groups.iter().any(|group| {
                let matcher_covers_all = group
                    .get("matcher")
                    .and_then(Value::as_str)
                    .is_none_or(|matcher| matcher.is_empty() || matcher == "*");
                matcher_covers_all
                    && group
                        .get("hooks")
                        .and_then(Value::as_array)
                        .is_some_and(|hooks| {
                            hooks
                                .iter()
                                .any(|hook| valid_guard_command(hook, cli_event))
                        })
            })
        })
}

fn valid_guard_command(hook: &Value, event: &str) -> bool {
    if hook.get("type").and_then(Value::as_str) != Some("command") {
        return false;
    }
    let Some(command) = hook.get("command").and_then(Value::as_str) else {
        return false;
    };
    let Some(tokens) = super::command_tokens(command) else {
        return false;
    };
    let tokens = tokens.iter().map(String::as_str).collect::<Vec<_>>();
    let executable_is_absolute = tokens
        .first()
        .is_some_and(|executable| super::is_daguard_executable(executable));
    executable_is_absolute
        && has_pair(&tokens, "--adapter", "codex")
        && has_pair(&tokens, "--event", event)
        && tokens
            .windows(2)
            .any(|pair| pair[0] == "--policy" && crate::paths::is_absolute(pair[1]))
}

fn has_pair(tokens: &[&str], flag: &str, value: &str) -> bool {
    tokens.windows(2).any(|pair| pair == [flag, value])
}

#[derive(Debug)]
pub(crate) enum CodexError {
    Json(serde_json::Error),
    Invalid(&'static str),
    Model(crate::model::ModelError),
}

impl fmt::Display for CodexError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(
                formatter,
                "invalid Codex hook JSON at line {} column {}",
                error.line(),
                error.column()
            ),
            Self::Invalid(message) => formatter.write_str(message),
            Self::Model(error) => error.fmt(formatter),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::{normalize, normalize_post, render, validate_hooks_config};
    use crate::model::{
        Capability, Decision, DecisionEffect, Evidence, PROTOCOL_VERSION, PolicyLayer, Severity,
    };

    const BASH: &[u8] = include_bytes!("../../tests/fixtures/codex/pre_tool_use/bash.json");
    const FILE_READ: &[u8] =
        include_bytes!("../../tests/fixtures/codex/pre_tool_use/file_read.json");
    const APPLY_PATCH: &[u8] =
        include_bytes!("../../tests/fixtures/codex/pre_tool_use/apply_patch.json");
    const MCP: &[u8] = include_bytes!("../../tests/fixtures/codex/pre_tool_use/mcp.json");
    const POST: &[u8] = include_bytes!("../../tests/fixtures/codex/post_tool_use/file_read.json");

    #[test]
    fn normalizes_bash_fixture() {
        let request = normalize(BASH).unwrap();
        assert_eq!(request.agent, "codex");
        assert_eq!(request.tool.capability, Capability::ShellExecute);
        assert_eq!(request.facts.command.as_deref(), Some("git status"));
        assert_eq!(request.session_id.as_deref(), Some("thr_fixture_shell"));
        assert_eq!(request.call_id.as_deref(), Some("call_fixture_shell"));
    }

    #[test]
    fn normalizes_file_read_fixture() {
        let request = normalize(FILE_READ).unwrap();
        assert_eq!(request.tool.capability, Capability::FileRead);
        assert_eq!(
            request.facts.paths,
            ["web/modules/custom/example/example.module"]
        );
    }

    #[test]
    fn normalizes_apply_patch_fixture() {
        let request = normalize(APPLY_PATCH).unwrap();
        assert_eq!(request.tool.capability, Capability::FileWrite);
        assert_eq!(
            request.facts.paths,
            ["web/modules/custom/example/example.module"]
        );
    }

    #[test]
    fn normalizes_mcp_fixture() {
        let request = normalize(MCP).unwrap();
        assert_eq!(request.tool.capability, Capability::McpCall);
        assert_eq!(request.facts.paths, ["README.md"]);
    }

    #[test]
    fn normalizes_post_fixture_without_retaining_result() {
        let event = normalize_post(POST).unwrap();
        assert_eq!(event.event, "post_tool_use");
        assert_eq!(event.session_id.as_deref(), Some("thr_phase14"));
        assert_eq!(event.facts.paths, ["web/sites/default/settings.php"]);
        let encoded = serde_json::to_string(&event).unwrap();
        assert!(!encoded.contains("SYNTHETIC_PHASE14_SECRET_CANARY"));
    }

    #[test]
    fn post_fixture_rejects_missing_or_empty_identifiers() {
        let mut value: Value = serde_json::from_slice(POST).unwrap();
        value.as_object_mut().unwrap().remove("tool_use_id");
        assert!(normalize_post(&serde_json::to_vec(&value).unwrap()).is_err());
        value["tool_use_id"] = Value::String("call".to_owned());
        value["session_id"] = Value::String(String::new());
        assert!(normalize_post(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn maps_unrecognized_local_tools_to_unknown() {
        let input = br#"{
            "session_id":"thr_unknown",
            "cwd":"/workspace/example",
            "hook_event_name":"PreToolUse",
            "tool_name":"future_local_tool",
            "tool_use_id":"call_unknown",
            "tool_input":{"path":"README.md"}
        }"#;
        let request = normalize(input).unwrap();
        assert_eq!(request.tool.capability, Capability::Unknown);
        assert_eq!(request.input["path"], "README.md");
    }

    #[test]
    fn renders_allow_and_deny_golden_responses() {
        let mut decision = Decision {
            protocol: PROTOCOL_VERSION,
            effect: DecisionEffect::Allow,
            rule_id: "default.no_matching_rule".to_owned(),
            severity: Severity::Info,
            category: "default".to_owned(),
            reason: "Synthetic allow.".to_owned(),
            policy_layer: PolicyLayer::Default,
            details: Evidence { matched_path: None },
        };
        let allow: Value = serde_json::to_value(render(&decision)).unwrap();
        let expected_allow: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/codex/responses/allow.json"
        ))
        .unwrap();
        assert_eq!(allow, expected_allow);

        decision.effect = DecisionEffect::Deny;
        decision.rule_id = "drupal.secret.settings_php".to_owned();
        let deny: Value = serde_json::to_value(render(&decision)).unwrap();
        let expected_deny: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/codex/responses/deny.json"
        ))
        .unwrap();
        assert_eq!(deny, expected_deny);
    }

    #[test]
    fn maps_unsupported_ask_to_deny() {
        let decision = Decision {
            protocol: PROTOCOL_VERSION,
            effect: DecisionEffect::Ask,
            rule_id: "organization.ask.review".to_owned(),
            severity: Severity::Medium,
            category: "policy".to_owned(),
            reason: "Synthetic ask.".to_owned(),
            policy_layer: PolicyLayer::Organization,
            details: Evidence { matched_path: None },
        };
        let response = serde_json::to_value(render(&decision)).unwrap();
        assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn validates_secure_hook_configuration() {
        let valid = include_bytes!("../../config/codex/hooks.json");
        assert!(validate_hooks_config(valid).is_ok());

        let relative = br#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"./daguard --adapter codex --event pre-tool --policy ./policy.json"}]}]}}"#;
        assert!(validate_hooks_config(relative).is_err());

        let windows = br#"{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"\"C:\\Program Files\\Daguard\\daguard.exe\" --adapter codex --event pre-tool --policy \"C:\\ProgramData\\Daguard\\policy.json\""}]}],"PostToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"\"C:\\Program Files\\Daguard\\daguard.exe\" --adapter codex --event post-tool --policy \"C:\\ProgramData\\Daguard\\policy.json\""}]}]}}"#;
        assert!(validate_hooks_config(windows).is_ok());
    }
}

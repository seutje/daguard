//! Cursor `preToolUse` request normalization and response rendering.

use std::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{
    CanonicalRequest, Capability, Decision, DecisionEffect, Facts, PROTOCOL_VERSION, Tool,
};

#[derive(Debug, Deserialize)]
struct PreToolUseInput {
    tool_name: String,
    tool_input: Value,
    tool_use_id: String,
    cwd: String,
    #[serde(default, alias = "conversation_id")]
    session_id: Option<String>,
}

pub(crate) fn normalize(input: &[u8]) -> Result<CanonicalRequest, CursorError> {
    crate::json::preflight(input, crate::json::MAX_REQUEST_BYTES).map_err(CursorError::Json)?;
    let input: PreToolUseInput = serde_json::from_slice(input).map_err(CursorError::Json)?;
    let (capability, facts) = normalize_tool(&input.tool_name, &input.tool_input)?;
    let request = CanonicalRequest {
        protocol: PROTOCOL_VERSION,
        agent: "cursor".to_owned(),
        event: "pre_tool_use".to_owned(),
        session_id: input.session_id,
        call_id: Some(input.tool_use_id),
        cwd: input.cwd,
        tool: Tool {
            native_name: input.tool_name,
            capability,
        },
        input: input.tool_input,
        facts,
    };
    request.validate().map_err(CursorError::Model)?;
    Ok(request)
}

fn normalize_tool(tool_name: &str, input: &Value) -> Result<(Capability, Facts), CursorError> {
    let lower = tool_name.to_ascii_lowercase();
    let capability = match lower.as_str() {
        "shell" => Capability::ShellExecute,
        "read" => Capability::FileRead,
        "write" | "edit" => Capability::FileWrite,
        "delete" => Capability::FileDelete,
        _ if lower.starts_with("mcp:") => Capability::McpCall,
        _ => Capability::Unknown,
    };
    if capability == Capability::ShellExecute {
        let command = input
            .get("command")
            .and_then(Value::as_str)
            .ok_or(CursorError::Invalid(
                "Shell tool input requires a command string",
            ))?;
        return Ok((
            capability,
            Facts {
                command: Some(command.to_owned()),
                ..Facts::default()
            },
        ));
    }
    let paths = input_paths(input);
    if matches!(
        capability,
        Capability::FileRead | Capability::FileWrite | Capability::FileDelete
    ) && paths.is_empty()
    {
        return Err(CursorError::Invalid(
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

#[derive(Debug, Serialize)]
pub(crate) struct Response {
    permission: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_message: Option<String>,
}

pub(crate) fn render(decision: &Decision) -> Response {
    let deny = matches!(decision.effect, DecisionEffect::Deny | DecisionEffect::Ask);
    let message = deny.then(|| format!("Blocked by team policy: {}", decision.rule_id));
    Response {
        permission: if deny { "deny" } else { "allow" },
        user_message: message.clone(),
        agent_message: message,
    }
}

pub(crate) fn error_response() -> Response {
    let message = "Blocked by team policy: guard.evaluation_error".to_owned();
    Response {
        permission: "deny",
        user_message: Some(message.clone()),
        agent_message: Some(message),
    }
}

/// Performs advisory checks on a native Cursor `hooks.json` deployment.
pub(crate) fn validate_hooks_config(input: &[u8]) -> Result<(), CursorError> {
    let root: Value = serde_json::from_slice(input).map_err(CursorError::Json)?;
    if root.get("version").and_then(Value::as_u64) != Some(1) {
        return Err(CursorError::Invalid("hooks.json must use version 1"));
    }
    let hooks = root
        .pointer("/hooks/preToolUse")
        .and_then(Value::as_array)
        .ok_or(CursorError::Invalid(
            "hooks.json must define hooks.preToolUse as an array",
        ))?;
    let configured = hooks.iter().any(|hook| {
        let matcher_covers_all = hook
            .get("matcher")
            .and_then(Value::as_str)
            .is_none_or(|matcher| matcher.is_empty() || matcher == "*");
        matcher_covers_all
            && hook.get("failClosed").and_then(Value::as_bool) == Some(true)
            && hook
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(valid_guard_command)
    });
    if !configured {
        return Err(CursorError::Invalid(
            "no all-tools fail-closed preToolUse hook uses absolute guard and policy paths",
        ));
    }
    Ok(())
}

fn valid_guard_command(command: &str) -> bool {
    let tokens = command.split_whitespace().collect::<Vec<_>>();
    let executable_is_absolute = tokens.first().is_some_and(|executable| {
        let path = Path::new(executable);
        path.is_absolute() && path.file_name().is_some_and(|name| name == "daguard")
    });
    executable_is_absolute
        && has_pair(&tokens, "--adapter", "cursor")
        && has_pair(&tokens, "--event", "pre-tool")
        && tokens
            .windows(2)
            .any(|pair| pair[0] == "--policy" && Path::new(pair[1]).is_absolute())
}

fn has_pair(tokens: &[&str], flag: &str, value: &str) -> bool {
    tokens.windows(2).any(|pair| pair == [flag, value])
}

#[derive(Debug)]
pub(crate) enum CursorError {
    Json(serde_json::Error),
    Invalid(&'static str),
    Model(crate::model::ModelError),
}

impl fmt::Display for CursorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(
                formatter,
                "invalid Cursor hook JSON at line {} column {}",
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
    use super::{normalize, render, validate_hooks_config};
    use crate::adapters::codex;
    use crate::model::{
        Capability, Decision, DecisionEffect, Evidence, PROTOCOL_VERSION, PolicyLayer, Severity,
    };
    use crate::policy;
    use serde_json::Value;

    const SHELL: &[u8] = include_bytes!("../../tests/fixtures/cursor/pre_tool_use/shell.json");
    const FILE_READ: &[u8] =
        include_bytes!("../../tests/fixtures/cursor/pre_tool_use/file_read.json");
    const FILE_WRITE: &[u8] =
        include_bytes!("../../tests/fixtures/cursor/pre_tool_use/file_write.json");
    const MCP: &[u8] = include_bytes!("../../tests/fixtures/cursor/pre_tool_use/mcp.json");

    #[test]
    fn normalizes_golden_fixtures() {
        let shell = normalize(SHELL).unwrap();
        assert_eq!(shell.agent, "cursor");
        assert_eq!(shell.tool.capability, Capability::ShellExecute);
        assert_eq!(shell.facts.command.as_deref(), Some("git status"));
        assert_eq!(shell.call_id.as_deref(), Some("call_cursor_shell"));
        let read = normalize(FILE_READ).unwrap();
        assert_eq!(read.tool.capability, Capability::FileRead);
        assert_eq!(
            read.facts.paths,
            ["web/modules/custom/example/example.module"]
        );
        let write = normalize(FILE_WRITE).unwrap();
        assert_eq!(write.tool.capability, Capability::FileWrite);
        assert_eq!(
            write.facts.paths,
            ["web/modules/custom/example/example.module"]
        );
        let mcp = normalize(MCP).unwrap();
        assert_eq!(mcp.tool.capability, Capability::McpCall);
        assert_eq!(mcp.facts.paths, ["README.md"]);
    }

    #[test]
    fn renders_golden_responses_and_maps_ask_to_deny() {
        let mut decision = synthetic_decision(DecisionEffect::Allow, "default.no_matching_rule");
        let actual: Value = serde_json::to_value(render(&decision)).unwrap();
        let expected: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/cursor/responses/allow.json"
        ))
        .unwrap();
        assert_eq!(actual, expected);
        decision.effect = DecisionEffect::Deny;
        decision.rule_id = "drupal.secret.settings_php".to_owned();
        let actual: Value = serde_json::to_value(render(&decision)).unwrap();
        let expected: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/cursor/responses/deny.json"
        ))
        .unwrap();
        assert_eq!(actual, expected);
        decision.effect = DecisionEffect::Ask;
        assert_eq!(
            serde_json::to_value(render(&decision)).unwrap()["permission"],
            "deny"
        );
    }

    #[test]
    fn codex_and_cursor_have_identical_mandatory_decisions() {
        let scenarios = [
            (
                "Read",
                r#"{"file_path":"web/sites/default/settings.php"}"#,
                "Read",
                "drupal.secret.settings_php",
            ),
            (
                "Shell",
                r#"{"command":"ddev drush ev 'print(1)'"}"#,
                "Bash",
                "shell.drush.eval",
            ),
            (
                "Shell",
                r#"{"command":"ddev mysql -e 'DELETE FROM node'"}"#,
                "Bash",
                "sql.mutation.delete",
            ),
        ];
        for (cursor_tool, tool_input, codex_tool, expected_rule) in scenarios {
            let cursor_input = format!(
                r#"{{"tool_name":"{cursor_tool}","tool_input":{tool_input},"tool_use_id":"cursor_call","cwd":"/workspace/example"}}"#
            );
            let codex_input = format!(
                r#"{{"session_id":"codex_session","cwd":"/workspace/example","hook_event_name":"PreToolUse","tool_name":"{codex_tool}","tool_use_id":"codex_call","tool_input":{tool_input}}}"#
            );
            let cursor_decision =
                policy::evaluate(&normalize(cursor_input.as_bytes()).unwrap(), None, None).unwrap();
            let codex_decision = policy::evaluate(
                &codex::normalize(codex_input.as_bytes()).unwrap(),
                None,
                None,
            )
            .unwrap();
            assert_eq!(cursor_decision.effect, DecisionEffect::Deny);
            assert_eq!(cursor_decision.effect, codex_decision.effect);
            assert_eq!(cursor_decision.rule_id, expected_rule);
            assert_eq!(cursor_decision.rule_id, codex_decision.rule_id);
        }
    }

    #[test]
    fn requires_fail_closed_all_tools_configuration() {
        let fixture = include_bytes!("../../config/cursor/hooks.json");
        assert!(validate_hooks_config(fixture).is_ok());
        let fail_open = br#"{"version":1,"hooks":{"preToolUse":[{"command":"/usr/local/bin/daguard --adapter cursor --event pre-tool --policy /etc/daguard/policy.json","matcher":"*","failClosed":false}]}}"#;
        assert!(validate_hooks_config(fail_open).is_err());
    }

    fn synthetic_decision(effect: DecisionEffect, rule_id: &str) -> Decision {
        Decision {
            protocol: PROTOCOL_VERSION,
            effect,
            rule_id: rule_id.to_owned(),
            severity: Severity::Info,
            category: "test".to_owned(),
            reason: "Synthetic decision.".to_owned(),
            policy_layer: PolicyLayer::Default,
            details: Evidence { matched_path: None },
        }
    }
}

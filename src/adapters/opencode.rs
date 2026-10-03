//! `OpenCode` v2 tool-hook request normalization and response rendering.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{
    CanonicalRequest, Capability, Decision, DecisionEffect, Facts, PROTOCOL_VERSION, Tool,
};

const ADAPTER_SCHEMA_VERSION: u16 = 1;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolExecuteBeforeInput {
    schema: u16,
    session_id: String,
    call_id: String,
    cwd: String,
    tool_name: String,
    tool_input: Value,
}

pub(crate) fn normalize(input: &[u8]) -> Result<CanonicalRequest, OpenCodeError> {
    crate::json::preflight(input, crate::json::MAX_REQUEST_BYTES).map_err(OpenCodeError::Json)?;
    let input: ToolExecuteBeforeInput =
        serde_json::from_slice(input).map_err(OpenCodeError::Json)?;
    if input.schema != ADAPTER_SCHEMA_VERSION {
        return Err(OpenCodeError::Invalid(
            "unsupported OpenCode adapter schema version",
        ));
    }
    let (capability, facts) = normalize_tool(&input.tool_name, &input.tool_input)?;
    let request = CanonicalRequest {
        protocol: PROTOCOL_VERSION,
        agent: "opencode".to_owned(),
        event: "pre_tool_use".to_owned(),
        session_id: Some(input.session_id),
        call_id: Some(input.call_id),
        cwd: input.cwd,
        tool: Tool {
            native_name: input.tool_name,
            capability,
        },
        input: input.tool_input,
        facts,
    };
    request.validate().map_err(OpenCodeError::Model)?;
    Ok(request)
}

fn normalize_tool(tool_name: &str, input: &Value) -> Result<(Capability, Facts), OpenCodeError> {
    let lower = tool_name.to_ascii_lowercase();
    if lower == "bash" {
        let command =
            input
                .get("command")
                .and_then(Value::as_str)
                .ok_or(OpenCodeError::Invalid(
                    "bash tool input requires a command string",
                ))?;
        return Ok((
            Capability::ShellExecute,
            Facts {
                command: Some(command.to_owned()),
                ..Facts::default()
            },
        ));
    }
    if lower == "apply_patch" {
        let patch = input
            .get("patchText")
            .or_else(|| input.get("patch_text"))
            .and_then(Value::as_str)
            .ok_or(OpenCodeError::Invalid(
                "apply_patch tool input requires a patchText string",
            ))?;
        let paths = patch_paths(patch);
        if paths.is_empty() {
            return Err(OpenCodeError::Invalid(
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

    let capability = match lower.as_str() {
        "read" => Capability::FileRead,
        "write" | "edit" => Capability::FileWrite,
        "webfetch" | "websearch" => Capability::NetworkRead,
        _ => Capability::Unknown,
    };
    let paths = input_paths(input);
    if matches!(capability, Capability::FileRead | Capability::FileWrite) && paths.is_empty() {
        return Err(OpenCodeError::Invalid(
            "file tool input contains no recognized path",
        ));
    }
    let urls = if capability == Capability::NetworkRead {
        input
            .get("url")
            .and_then(Value::as_str)
            .map(|url| vec![url.to_owned()])
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    Ok((
        capability,
        Facts {
            paths,
            urls,
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

fn patch_paths(patch: &str) -> Vec<String> {
    const HEADERS: &[&str] = &[
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    patch
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
pub(crate) struct Response {
    schema: u16,
    decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule_id: Option<String>,
}

pub(crate) fn render(decision: &Decision) -> Response {
    let deny = matches!(decision.effect, DecisionEffect::Deny | DecisionEffect::Ask);
    Response {
        schema: ADAPTER_SCHEMA_VERSION,
        decision: if deny { "deny" } else { "allow" },
        rule_id: deny.then(|| decision.rule_id.clone()),
    }
}

pub(crate) fn error_response() -> Response {
    Response {
        schema: ADAPTER_SCHEMA_VERSION,
        decision: "deny",
        rule_id: Some("guard.evaluation_error".to_owned()),
    }
}

/// Checks that an `OpenCode` v2 configuration loads the bridge from an absolute
/// location and supplies absolute trusted guard and organization-policy paths.
#[cfg(test)]
pub(crate) fn validate_config(input: &[u8]) -> Result<(), OpenCodeError> {
    configured_plugin_paths(input).map(|_| ())
}

/// Validates the configuration and confirms that `OpenCode`'s v2.0.22 local
/// directory resolver can find the installed server entrypoint.
pub(crate) fn validate_installed_config(input: &[u8]) -> Result<(), OpenCodeError> {
    let plugins = configured_plugin_paths(input)?;
    if plugins
        .iter()
        .any(|package| package.join("index.js").is_file())
    {
        return Ok(());
    }
    Err(OpenCodeError::Invalid(
        "OpenCode plugin directory does not contain the required index.js entrypoint",
    ))
}

fn configured_plugin_paths(input: &[u8]) -> Result<Vec<PathBuf>, OpenCodeError> {
    let root: Value = serde_json::from_slice(input).map_err(OpenCodeError::Json)?;
    let plugins = root
        .get("plugins")
        .and_then(Value::as_array)
        .ok_or(OpenCodeError::Invalid(
            "opencode.json must define plugins as an array",
        ))?;
    let configured = plugins
        .iter()
        .filter_map(|plugin| {
            let plugin = plugin.as_object()?;
            let package = plugin.get("package").and_then(Value::as_str)?;
            let options = plugin.get("options").and_then(Value::as_object)?;
            (Path::new(package).is_absolute()
                && options
                    .get("guard")
                    .and_then(Value::as_str)
                    .is_some_and(|path| {
                        let path = Path::new(path);
                        path.is_absolute() && path.file_name().is_some_and(|name| name == "daguard")
                    })
                && options
                    .get("policy")
                    .and_then(Value::as_str)
                    .is_some_and(|path| Path::new(path).is_absolute()))
            .then(|| PathBuf::from(package))
        })
        .collect::<Vec<_>>();
    if configured.is_empty() {
        return Err(OpenCodeError::Invalid(
            "no OpenCode plugin uses absolute bridge, guard, and policy paths",
        ));
    }
    Ok(configured)
}

#[derive(Debug)]
pub(crate) enum OpenCodeError {
    Json(serde_json::Error),
    Invalid(&'static str),
    Model(crate::model::ModelError),
}

impl fmt::Display for OpenCodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(
                formatter,
                "invalid OpenCode hook JSON at line {} column {}",
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

    use super::{normalize, render, validate_config};
    use crate::model::{
        Capability, Decision, DecisionEffect, Evidence, PROTOCOL_VERSION, PolicyLayer, Severity,
    };

    const BASH: &[u8] =
        include_bytes!("../../tests/fixtures/opencode/tool_execute_before/bash.json");
    const FILE_READ: &[u8] =
        include_bytes!("../../tests/fixtures/opencode/tool_execute_before/file_read.json");
    const APPLY_PATCH: &[u8] =
        include_bytes!("../../tests/fixtures/opencode/tool_execute_before/apply_patch.json");
    const UNKNOWN: &[u8] =
        include_bytes!("../../tests/fixtures/opencode/tool_execute_before/unknown.json");

    #[test]
    fn normalizes_golden_fixtures() {
        let shell = normalize(BASH).unwrap();
        assert_eq!(shell.agent, "opencode");
        assert_eq!(shell.tool.capability, Capability::ShellExecute);
        assert_eq!(shell.facts.command.as_deref(), Some("git status"));
        assert_eq!(shell.session_id.as_deref(), Some("ses_fixture_shell"));
        assert_eq!(shell.call_id.as_deref(), Some("call_fixture_shell"));

        let read = normalize(FILE_READ).unwrap();
        assert_eq!(read.tool.capability, Capability::FileRead);
        assert_eq!(
            read.facts.paths,
            ["web/modules/custom/example/example.module"]
        );

        let patch = normalize(APPLY_PATCH).unwrap();
        assert_eq!(patch.tool.capability, Capability::FileWrite);
        assert_eq!(patch.facts.paths, ["web/core/lib/Drupal.php"]);

        let unknown = normalize(UNKNOWN).unwrap();
        assert_eq!(unknown.tool.capability, Capability::Unknown);
        assert_eq!(unknown.input["path"], "README.md");
    }

    #[test]
    fn renders_golden_responses_and_maps_ask_to_deny() {
        let mut decision = synthetic_decision(DecisionEffect::Allow, "default.no_matching_rule");
        let actual: Value = serde_json::to_value(render(&decision)).unwrap();
        let expected: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/opencode/responses/allow.json"
        ))
        .unwrap();
        assert_eq!(actual, expected);

        decision.effect = DecisionEffect::Deny;
        decision.rule_id = "drupal.secret.settings_php".to_owned();
        let actual: Value = serde_json::to_value(render(&decision)).unwrap();
        let expected: Value = serde_json::from_slice(include_bytes!(
            "../../tests/fixtures/opencode/responses/deny.json"
        ))
        .unwrap();
        assert_eq!(actual, expected);

        decision.effect = DecisionEffect::Ask;
        assert_eq!(
            serde_json::to_value(render(&decision)).unwrap()["decision"],
            "deny"
        );
    }

    #[test]
    fn validates_secure_v2_configuration() {
        assert!(validate_config(include_bytes!("../../config/opencode/opencode.json")).is_ok());
        let relative = br#"{"plugins":[{"package":"./plugin","options":{"guard":"./daguard","policy":"./policy.json"}}]}"#;
        assert!(validate_config(relative).is_err());
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

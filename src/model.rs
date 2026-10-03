//! Versioned canonical request and decision models.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const PROTOCOL_VERSION: u16 = 1;
const MAX_INPUT_BYTES: usize = crate::json::MAX_REQUEST_BYTES;
const MAX_INPUT_DEPTH: usize = 16;
const MAX_INPUT_NODES: usize = 1_024;
const MAX_STRING_BYTES: usize = 16 * 1024;
const MAX_PATHS: usize = 128;
const MAX_PATH_BYTES: usize = 4_096;
const MAX_IDENTIFIER_BYTES: usize = 256;

/// The primary behavior requested by an agent tool.
///
/// Adapters must map a tool to the narrowest known capability. Tools without a
/// reliable mapping use `Unknown`; they must never be silently reclassified as
/// a known-safe capability. File moves/searches and `NetworkRequest` are retained
/// for compatibility with the design schema, while network read/write provide
/// the more precise Phase 1 representation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Capability {
    FileRead,
    FileWrite,
    FileDelete,
    FileMove,
    FileSearch,
    ShellExecute,
    NetworkRead,
    NetworkWrite,
    NetworkRequest,
    McpCall,
    GitOperation,
    Unknown,
}

impl Capability {
    pub(crate) const fn is_read(self) -> bool {
        matches!(self, Self::FileRead)
    }

    pub(crate) const fn is_write(self) -> bool {
        matches!(self, Self::FileWrite | Self::FileDelete | Self::FileMove)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Tool {
    pub(crate) native_name: String,
    pub(crate) capability: Capability,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct Facts {
    #[serde(default)]
    pub(crate) paths: Vec<String>,
    #[serde(default)]
    pub(crate) command: Option<String>,
    #[serde(default)]
    pub(crate) argv: Vec<String>,
    #[serde(default)]
    pub(crate) urls: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct CanonicalRequest {
    pub(crate) protocol: u16,
    pub(crate) agent: String,
    pub(crate) event: String,
    #[serde(default)]
    pub(crate) session_id: Option<String>,
    #[serde(default)]
    pub(crate) call_id: Option<String>,
    pub(crate) cwd: String,
    pub(crate) tool: Tool,
    pub(crate) input: Value,
    #[serde(default)]
    pub(crate) facts: Facts,
}

impl CanonicalRequest {
    pub(crate) fn from_slice(input: &[u8]) -> Result<Self, ModelError> {
        if input.len() > MAX_INPUT_BYTES {
            return Err(ModelError::Limit("request exceeds 64 KiB"));
        }
        crate::json::preflight(input, MAX_INPUT_BYTES).map_err(ModelError::Json)?;
        let request: Self = serde_json::from_slice(input).map_err(ModelError::Json)?;
        request.validate()?;
        Ok(request)
    }

    pub(crate) fn validate(&self) -> Result<(), ModelError> {
        if self.protocol != PROTOCOL_VERSION {
            return Err(ModelError::Invalid("unsupported protocol version"));
        }
        validate_identifier("agent", &self.agent)?;
        validate_identifier("event", &self.event)?;
        validate_identifier("tool.native_name", &self.tool.native_name)?;
        validate_optional_identifier("session_id", self.session_id.as_deref())?;
        validate_optional_identifier("call_id", self.call_id.as_deref())?;
        if !std::path::Path::new(&self.cwd).is_absolute()
            || self.cwd.len() > MAX_PATH_BYTES
            || self.cwd.contains('\0')
        {
            return Err(ModelError::Invalid("cwd is invalid"));
        }
        if self.facts.paths.len() > MAX_PATHS {
            return Err(ModelError::Limit("too many fact paths"));
        }
        for path in &self.facts.paths {
            if path.is_empty() || path.len() > MAX_PATH_BYTES || path.contains('\0') {
                return Err(ModelError::Invalid("fact path is invalid"));
            }
        }
        if self
            .facts
            .command
            .as_ref()
            .is_some_and(|command| command.len() > MAX_STRING_BYTES || command.contains('\0'))
        {
            return Err(ModelError::Invalid("fact command is invalid"));
        }
        validate_string_collection("fact argv is invalid", &self.facts.argv)?;
        validate_string_collection("fact URLs are invalid", &self.facts.urls)?;
        let mut nodes = 0;
        validate_value(&self.input, 0, &mut nodes)?;
        Ok(())
    }

    /// Returns bounded command facts plus recognized command fields for unknown tools.
    pub(crate) fn candidate_commands(&self) -> Vec<&str> {
        let mut commands = self
            .facts
            .command
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if matches!(
            self.tool.capability,
            Capability::Unknown | Capability::McpCall
        ) {
            collect_command_values(&self.input, None, &mut commands);
        }
        commands
    }

    /// Returns normalized facts plus path-like strings found in unknown tool input.
    ///
    /// Known adapters are expected to populate `facts.paths`. Unknown tools get
    /// a bounded recursive fallback for common path field names so a novel tool
    /// cannot bypass universal sensitive-path rules merely by lacking a mapping.
    pub(crate) fn candidate_paths(&self) -> Vec<&str> {
        let mut paths = self
            .facts
            .paths
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if matches!(self.tool.capability, Capability::Unknown) {
            collect_path_values(&self.input, None, &mut paths);
        }
        paths
    }
}

fn validate_string_collection(message: &'static str, values: &[String]) -> Result<(), ModelError> {
    if values.len() > MAX_PATHS
        || values
            .iter()
            .any(|value| value.len() > MAX_STRING_BYTES || value.contains('\0'))
    {
        return Err(ModelError::Invalid(message));
    }
    Ok(())
}

fn collect_command_values<'a>(value: &'a Value, key: Option<&str>, commands: &mut Vec<&'a str>) {
    match value {
        Value::String(value)
            if key.is_some_and(|key| {
                matches!(
                    key.to_ascii_lowercase().as_str(),
                    "command" | "cmd" | "shell_command"
                )
            }) =>
        {
            commands.push(value);
        }
        Value::Array(values) => {
            for value in values {
                collect_command_values(value, key, commands);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                collect_command_values(value, Some(key), commands);
            }
        }
        _ => {}
    }
}

fn collect_path_values<'a>(value: &'a Value, key: Option<&str>, paths: &mut Vec<&'a str>) {
    // validate() bounds all input to 1,024 nodes; never truncate candidates,
    // because a protected path may be the last one in an unknown tool.
    match value {
        Value::String(value) if key.is_some_and(is_path_key) => paths.push(value),
        Value::Array(values) => {
            for value in values {
                collect_path_values(value, key, paths);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                collect_path_values(value, Some(key), paths);
            }
        }
        _ => {}
    }
}

fn is_path_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "path"
            | "paths"
            | "file"
            | "files"
            | "file_path"
            | "file_paths"
            | "filepath"
            | "filename"
            | "target"
            | "destination"
    )
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ModelError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.contains('\0') {
        return Err(ModelError::Invalid(field));
    }
    Ok(())
}

fn validate_optional_identifier(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ModelError> {
    if let Some(value) = value {
        validate_identifier(field, value)?;
    }
    Ok(())
}

fn validate_value(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), ModelError> {
    if depth > MAX_INPUT_DEPTH {
        return Err(ModelError::Limit("tool input is nested too deeply"));
    }
    *nodes += 1;
    if *nodes > MAX_INPUT_NODES {
        return Err(ModelError::Limit("tool input contains too many values"));
    }
    match value {
        Value::String(value) if value.len() > MAX_STRING_BYTES => {
            Err(ModelError::Limit("tool input string exceeds 16 KiB"))
        }
        Value::Array(values) => {
            for value in values {
                validate_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            for (key, value) in values {
                if key.len() > MAX_IDENTIFIER_BYTES {
                    return Err(ModelError::Limit("tool input key exceeds 256 bytes"));
                }
                validate_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecisionEffect {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PolicyLayer {
    BuiltIn,
    Organization,
    Project,
    Default,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) matched_path: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub(crate) struct Decision {
    pub(crate) protocol: u16,
    #[serde(rename = "decision")]
    pub(crate) effect: DecisionEffect,
    pub(crate) rule_id: String,
    pub(crate) severity: Severity,
    pub(crate) category: String,
    pub(crate) reason: String,
    pub(crate) policy_layer: PolicyLayer,
    pub(crate) details: Evidence,
}

#[derive(Debug)]
pub(crate) enum ModelError {
    Json(serde_json::Error),
    Invalid(&'static str),
    Limit(&'static str),
}

impl fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => write!(
                formatter,
                "invalid canonical request JSON at line {} column {}",
                error.line(),
                error.column()
            ),
            Self::Invalid(message) | Self::Limit(message) => formatter.write_str(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalRequest, Capability, ModelError};

    const VALID: &str = r#"{
        "protocol": 1,
        "agent": "fixture",
        "event": "pre_tool_use",
        "cwd": "/workspace/project",
        "tool": {"native_name": "read", "capability": "file_read"},
        "input": {},
        "facts": {"paths": ["README.md"]}
    }"#;

    #[test]
    fn parses_a_complete_request() {
        let request = CanonicalRequest::from_slice(VALID.as_bytes()).unwrap();
        assert_eq!(request.tool.capability, Capability::FileRead);
        assert_eq!(request.session_id, None);
    }

    #[test]
    fn rejects_malformed_json() {
        assert!(matches!(
            CanonicalRequest::from_slice(br#"{"protocol":1"#),
            Err(ModelError::Json(_))
        ));
    }

    #[test]
    fn rejects_missing_required_fields() {
        assert!(matches!(
            CanonicalRequest::from_slice(br#"{"protocol":1}"#),
            Err(ModelError::Json(_))
        ));
    }

    #[test]
    fn rejects_unknown_capability_values() {
        let input = VALID.replace("file_read", "surprise");
        assert!(matches!(
            CanonicalRequest::from_slice(input.as_bytes()),
            Err(ModelError::Json(_))
        ));
    }

    #[test]
    fn accepts_explicit_unknown_capability() {
        let input = VALID.replace("file_read", "unknown");
        let request = CanonicalRequest::from_slice(input.as_bytes()).unwrap();
        assert_eq!(request.tool.capability, Capability::Unknown);
    }

    #[test]
    fn extracts_nested_path_fields_for_unknown_tools() {
        let input = VALID
            .replace("file_read", "unknown")
            .replace(
                "\"input\": {}",
                "\"input\": {\"nested\": {\"path\": \".env\"}}",
            )
            .replace("[\"README.md\"]", "[]");
        let request = CanonicalRequest::from_slice(input.as_bytes()).unwrap();
        assert_eq!(request.candidate_paths(), vec![".env"]);
    }

    #[test]
    fn rejects_an_unsupported_protocol() {
        let input = VALID.replace("\"protocol\": 1", "\"protocol\": 2");
        assert!(matches!(
            CanonicalRequest::from_slice(input.as_bytes()),
            Err(ModelError::Invalid("unsupported protocol version"))
        ));
    }

    #[test]
    fn parses_every_capability_wire_name() {
        for capability in [
            "file_read",
            "file_write",
            "file_delete",
            "file_move",
            "file_search",
            "shell_execute",
            "network_read",
            "network_write",
            "network_request",
            "mcp_call",
            "git_operation",
            "unknown",
        ] {
            let input = VALID.replace("file_read", capability);
            CanonicalRequest::from_slice(input.as_bytes()).unwrap();
        }
    }

    #[test]
    fn rejects_unbounded_fact_collections() {
        let paths = (0..129)
            .map(|index| format!("file-{index}"))
            .collect::<Vec<_>>();
        let input = VALID.replace("[\"README.md\"]", &serde_json::to_string(&paths).unwrap());
        assert!(matches!(
            CanonicalRequest::from_slice(input.as_bytes()),
            Err(ModelError::Limit("too many fact paths"))
        ));
    }
}

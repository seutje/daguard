//! Safe audit-event construction and append-only output.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use crate::model::{
    CanonicalPostToolEvent, CanonicalRequest, Capability, Decision, DecisionEffect, PolicyLayer,
    ResultEffect, ResultStatus, SensitivityCategory, Severity, SinkCategory,
};
use crate::sensitivity::SourceClassification;

pub(crate) const AUDIT_SCHEMA_VERSION: u16 = 4;

/// A deliberately small event that cannot contain raw tool input, commands,
/// paths, file contents, SQL data, HTTP bodies, or decision evidence.
#[derive(Debug, Serialize)]
pub(crate) struct AuditEvent<'a> {
    schema: u16,
    timestamp_unix_ms: u128,
    guard_version: &'static str,
    agent: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_version: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter_schema: Option<u16>,
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call: Option<String>,
    capability: Capability,
    decision: DecisionEffect,
    rule_id: &'a str,
    category: &'a str,
    severity: Severity,
    policy_layer: PolicyLayer,
    mode: &'static str,
    enforcement_decision: DecisionEffect,
    enforcement_rule_id: &'a str,
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    sensitivity_categories: BTreeSet<SensitivityCategory>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sink: Option<SinkCategory>,
}

pub(crate) struct SecurityContext {
    pub(crate) sensitivity_categories: BTreeSet<SensitivityCategory>,
    pub(crate) sink: Option<SinkCategory>,
}

pub(crate) struct AppendContext<'a> {
    pub(crate) audit_only: bool,
    pub(crate) agent_version: Option<&'a str>,
    pub(crate) adapter_schema: Option<u16>,
    pub(crate) security: Option<&'a SecurityContext>,
}

impl<'a> AuditEvent<'a> {
    pub(crate) fn new(
        request: &'a CanonicalRequest,
        decision: &'a Decision,
        enforcement: &'a Decision,
        audit_only: bool,
        agent_version: Option<&'a str>,
        adapter_schema: Option<u16>,
        security: Option<&SecurityContext>,
    ) -> io::Result<Self> {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_millis();
        Ok(Self {
            schema: AUDIT_SCHEMA_VERSION,
            timestamp_unix_ms,
            guard_version: env!("CARGO_PKG_VERSION"),
            agent: known_agent(&request.agent),
            agent_version,
            adapter_schema,
            event: known_event(&request.event),
            session: request.session_id.as_deref().map(pseudonymize),
            call: request.call_id.as_deref().map(pseudonymize),
            capability: request.tool.capability,
            decision: decision.effect,
            rule_id: &decision.rule_id,
            category: &decision.category,
            severity: decision.severity,
            policy_layer: decision.policy_layer,
            mode: if audit_only { "audit_only" } else { "enforce" },
            enforcement_decision: enforcement.effect,
            enforcement_rule_id: &enforcement.rule_id,
            sensitivity_categories: security
                .map(|context| context.sensitivity_categories.clone())
                .unwrap_or_default(),
            sink: security.and_then(|context| context.sink),
        })
    }
}

pub(crate) fn append(
    path: &Path,
    request: &CanonicalRequest,
    decision: &Decision,
    enforcement: &Decision,
    context: &AppendContext<'_>,
) -> io::Result<()> {
    let event = AuditEvent::new(
        request,
        decision,
        enforcement,
        context.audit_only,
        context.agent_version,
        context.adapter_schema,
        context.security,
    )?;
    let mut line = serde_json::to_vec(&event).map_err(io::Error::other)?;
    line.push(b'\n');

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    validate_destination(&file)?;
    file.write_all(&line)
}

#[derive(Debug, Serialize)]
struct PostAuditEvent<'a> {
    schema: u16,
    timestamp_unix_ms: u128,
    guard_version: &'static str,
    agent: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    adapter_schema: Option<u16>,
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    call: Option<String>,
    capability: Capability,
    result_status: ResultStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_content_type: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_byte_size: Option<u64>,
    decision: &'static str,
    source_ids: Vec<&'a str>,
    sensitivity_categories: BTreeSet<SensitivityCategory>,
}

pub(crate) fn append_post(
    path: &Path,
    event: &CanonicalPostToolEvent,
    classifications: &[SourceClassification],
    adapter_schema: Option<u16>,
) -> io::Result<()> {
    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis();
    let mut sensitivity_categories = BTreeSet::new();
    for classification in classifications {
        sensitivity_categories.extend(classification.categories.iter().copied());
    }
    let audit = PostAuditEvent {
        schema: AUDIT_SCHEMA_VERSION,
        timestamp_unix_ms,
        guard_version: env!("CARGO_PKG_VERSION"),
        agent: known_agent(&event.agent),
        adapter_schema,
        event: "post_tool_use",
        session: event.session_id.as_deref().map(pseudonymize),
        call: event.call_id.as_deref().map(pseudonymize),
        capability: event.tool.capability,
        result_status: event.result.status,
        result_content_type: event.result.content_type.as_deref().map(known_content_type),
        result_byte_size: event.result.byte_size,
        decision: "recorded",
        source_ids: classifications
            .iter()
            .map(|classification| classification.source_id.as_str())
            .collect(),
        sensitivity_categories,
    };
    write_event(path, &audit)
}

#[derive(Debug, Serialize)]
struct ResultAuditEvent<'a> {
    schema: u16,
    timestamp_unix_ms: u128,
    guard_version: &'static str,
    agent: &'static str,
    event: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    decision: &'static str,
    exit_code: i32,
    source_ids: Vec<&'a str>,
    sensitivity_categories: BTreeSet<SensitivityCategory>,
}

/// Append only result-decision metadata. Neither the raw nor sanitized body is
/// accepted by this API, making result leakage structurally impossible here.
pub(crate) fn append_result(
    path: &Path,
    agent: &str,
    session_id: Option<&str>,
    classifications: &[SourceClassification],
    result_effect: ResultEffect,
    exit_code: i32,
) -> io::Result<()> {
    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis();
    let mut sensitivity_categories = BTreeSet::new();
    for classification in classifications {
        sensitivity_categories.extend(classification.categories.iter().copied());
    }
    let event = ResultAuditEvent {
        schema: AUDIT_SCHEMA_VERSION,
        timestamp_unix_ms,
        guard_version: env!("CARGO_PKG_VERSION"),
        agent: known_agent(agent),
        event: "result_containment",
        session: session_id.map(pseudonymize),
        decision: match result_effect {
            ResultEffect::Allow => "allow",
            ResultEffect::Sanitize => "sanitize",
            ResultEffect::Block => "block",
        },
        exit_code,
        source_ids: classifications
            .iter()
            .map(|classification| classification.source_id.as_str())
            .collect(),
        sensitivity_categories,
    };
    write_event(path, &event)
}

fn write_event(path: &Path, event: &impl Serialize) -> io::Result<()> {
    let mut line = serde_json::to_vec(event).map_err(io::Error::other)?;
    line.push(b'\n');

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    validate_destination(&file)?;
    file.write_all(&line)
}

fn validate_destination(file: &std::fs::File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "audit destination is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit destination permits group or other access",
            ));
        }
    }
    Ok(())
}

pub(crate) fn sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(result, "{byte:02x}").expect("writing to a String cannot fail");
    }
    result
}

fn pseudonymize(value: &str) -> String {
    format!("sha256:{}", sha256(value.as_bytes()))
}

fn known_agent(agent: &str) -> &'static str {
    match agent.as_bytes() {
        b"codex" => "codex",
        b"cursor" => "cursor",
        b"opencode" => "opencode",
        b"guarded_execution" => "guarded_execution",
        b"mcp_proxy" => "mcp_proxy",
        _ => "unknown",
    }
}

fn known_event(event: &str) -> &'static str {
    match event.as_bytes() {
        b"pre_tool_use" => "pre_tool_use",
        _ => "unknown",
    }
}

fn known_content_type(content_type: &str) -> &'static str {
    match content_type {
        "application/json" => "application/json",
        "text/plain" => "text/plain",
        "text/markdown" => "text/markdown",
        "application/octet-stream" => "application/octet-stream",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::{AUDIT_SCHEMA_VERSION, AuditEvent};
    use crate::model::CanonicalRequest;
    use crate::policy;
    use serde_json::{Value, json};

    #[test]
    fn event_omits_sensitive_request_material_and_hashes_identifiers() {
        let input = json!({
            "protocol": 1,
            "agent": "synthetic-agent-secret",
            "event": "synthetic-event-secret",
            "session_id": "raw-session-secret",
            "call_id": "raw-call-secret",
            "cwd": "/workspace/project",
            "tool": {"native_name": "synthetic-tool-secret", "capability": "shell_execute"},
            "input": {"command": "cat .env", "password": "synthetic-secret"},
            "facts": {"command": "cat .env", "paths": [".env"]}
        });
        let request = CanonicalRequest::from_slice(&serde_json::to_vec(&input).unwrap()).unwrap();
        let decision = policy::evaluate(&request, None, None).unwrap();
        let event =
            AuditEvent::new(&request, &decision, &decision, false, None, Some(1), None).unwrap();
        let encoded = serde_json::to_string(&event).unwrap();
        let value: Value = serde_json::from_str(&encoded).unwrap();

        assert_eq!(value["schema"], AUDIT_SCHEMA_VERSION);
        assert!(value["session"].as_str().unwrap().starts_with("sha256:"));
        for sensitive in [
            "raw-session-secret",
            "raw-call-secret",
            "synthetic-secret",
            "synthetic-agent-secret",
            "synthetic-event-secret",
            "synthetic-tool-secret",
            "cat .env",
            "/workspace/project",
        ] {
            assert!(!encoded.contains(sensitive), "audit leaked {sensitive}");
        }
    }
}

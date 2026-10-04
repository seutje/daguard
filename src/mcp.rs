//! Line-delimited JSON-RPC MCP response gateway primitives.
//!
//! The CLI gateway owns transport forwarding; this module only validates and
//! sanitizes complete messages before release.

use std::io;
use std::path::Path;

use serde_json::Value;

#[cfg(any(unix, test))]
use crate::result::ResultDecision;
use crate::scanner::ScanConfig;
#[cfg(unix)]
use crate::state::StateStore;

#[cfg(any(unix, test))]
pub(crate) const MAX_MCP_MESSAGE_BYTES: usize = crate::scanner::MAX_SCAN_BYTES;

#[cfg(any(unix, test))]
pub(crate) fn inspect_response(line: &[u8], config: &ScanConfig) -> Result<ResultDecision, ()> {
    if line.len() > MAX_MCP_MESSAGE_BYTES {
        return Ok(ResultDecision::block(
            "result.scan_limit",
            "The MCP response exceeded the complete-scan limit.",
        ));
    }
    crate::json::preflight(line, MAX_MCP_MESSAGE_BYTES).map_err(|_| ())?;
    let value: Value = serde_json::from_slice(line).map_err(|_| ())?;
    if !value.is_object() && !value.is_array() {
        return Err(());
    }
    if contains_unsupported_binary(&value) {
        return Ok(ResultDecision::block(
            "result.unsupported_binary",
            "The MCP response contained a binary or attachment result that cannot be sanitized safely.",
        ));
    }
    Ok(crate::scanner::inspect(line, config))
}

#[cfg(unix)]
pub(crate) fn inspect_metadata(bytes: &[u8], config: &ScanConfig) -> Result<ResultDecision, ()> {
    crate::json::preflight(bytes, MAX_MCP_MESSAGE_BYTES).map_err(|_| ())?;
    let value: Value = serde_json::from_slice(bytes).map_err(|_| ())?;
    Ok(if safe(&value, config) {
        ResultDecision::allow(String::from_utf8(bytes.to_vec()).map_err(|_| ())?)
    } else {
        ResultDecision::block(
            "result.metadata_sensitive",
            "Sensitive protocol metadata cannot be rewritten safely.",
        )
    })
}

#[cfg(unix)]
fn safe(value: &Value, config: &ScanConfig) -> bool {
    safe_metadata(value, config, std::time::Instant::now(), false, false)
}

#[cfg(unix)]
fn safe_metadata(
    value: &Value,
    config: &ScanConfig,
    started: std::time::Instant,
    schema: bool,
    sensitive_property: bool,
) -> bool {
    if started.elapsed() > crate::scanner::MAX_SCAN_DURATION {
        return false;
    }
    match value {
        Value::Object(values) => values.iter().all(|(key, value)| {
            let key_safe = matches!(
                crate::scanner::inspect(key.as_bytes(), config).decision,
                crate::model::ResultEffect::Allow
            );
            if !key_safe {
                return false;
            }
            if schema && key == "properties" {
                return value.as_object().is_some_and(|properties| {
                    properties.iter().all(|(name, definition)| {
                        safe_metadata(&Value::String(name.clone()), config, started, true, false)
                            && safe_metadata(
                                definition,
                                config,
                                started,
                                true,
                                crate::scanner::field_category(name, config).is_some(),
                            )
                    })
                });
            }
            if (!schema && crate::scanner::field_category(key, config).is_some()
                || schema
                    && sensitive_property
                    && matches!(key.as_str(), "default" | "enum" | "examples" | "const"))
                && !value.is_null()
            {
                return false;
            }
            safe_metadata(
                value,
                config,
                started,
                schema || matches!(key.as_str(), "inputSchema" | "outputSchema"),
                sensitive_property,
            )
        }),
        Value::Array(values) => values
            .iter()
            .all(|value| safe_metadata(value, config, started, schema, sensitive_property)),
        Value::String(text) => matches!(
            crate::scanner::inspect(text.as_bytes(), config).decision,
            crate::model::ResultEffect::Allow
        ),
        _ => true,
    }
}

#[cfg(any(unix, test))]
fn contains_unsupported_binary(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().any(contains_unsupported_binary),
        Value::Object(values) => {
            let binary_type = values
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "image" | "audio" | "attachment" | "blob"));
            let binary_mime = values
                .get("mimeType")
                .or_else(|| values.get("mime_type"))
                .and_then(Value::as_str)
                .is_some_and(|mime| !mime.starts_with("text/") && mime != "application/json");
            values.contains_key("blob")
                || (binary_type && values.contains_key("data"))
                || (binary_mime && (values.contains_key("data") || values.contains_key("blob")))
                || values.values().any(contains_unsupported_binary)
        }
        _ => false,
    }
}

#[cfg(any(unix, test))]
pub(crate) fn blocked_response(id: &Value, rule_id: &str) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": -32001,
            "message": "Blocked by result-containment policy",
            "data": {"rule_id": rule_id}
        }
    })
}

// Kept for one CLI contract; unsupported platforms fail before accessing fields.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct ProxyOptions<'a> {
    pub(crate) timeout: std::time::Duration,
    pub(crate) command: &'a [String],
    pub(crate) cwd: &'a Path,
    pub(crate) config: &'a ScanConfig,
    pub(crate) state_dir: Option<&'a Path>,
    pub(crate) session_id: Option<&'a str>,
    pub(crate) agent: &'a str,
    pub(crate) audit_log: Option<&'a Path>,
}

// Kept for one CLI contract; unsupported platforms fail before accessing fields.
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) struct Authorization {
    pub(crate) rule_id: Option<String>,
    pub(crate) sources: Vec<crate::sensitivity::SourceClassification>,
}

pub(crate) fn proxy(
    options: &ProxyOptions<'_>,
    authorize: impl FnMut(&Value) -> io::Result<Authorization>,
) -> io::Result<i32> {
    #[cfg(unix)]
    {
        crate::mcp_runtime::proxy(options, authorize)
    }
    #[cfg(not(unix))]
    {
        let _ = (options, authorize);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Bounded MCP transport currently requires Unix",
        ))
    }
}

#[cfg(test)]
fn safe_response_id(message: &[u8], config: &ScanConfig) -> Value {
    let id = serde_json::from_slice::<Value>(message)
        .ok()
        .and_then(|value| value.get("id").cloned())
        .unwrap_or(Value::Null);
    match &id {
        Value::Null | Value::Number(_) => id,
        Value::String(value)
            if matches!(
                crate::scanner::inspect(value.as_bytes(), config).decision,
                crate::model::ResultEffect::Allow
            ) =>
        {
            id
        }
        Value::Bool(_) | Value::String(_) | Value::Array(_) | Value::Object(_) => Value::Null,
    }
}

#[cfg(unix)]
pub(crate) fn persist_result_metadata(
    decision: &ResultDecision,
    agent: &str,
    state_dir: Option<&Path>,
    session_id: Option<&str>,
    audit_log: Option<&Path>,
    sources: &[crate::sensitivity::SourceClassification],
) -> io::Result<()> {
    let mut classifications = decision_classifications(decision);
    classifications.extend_from_slice(sources);
    if let Some(session) = session_id
        && !classifications.is_empty()
    {
        StateStore::open(state_dir)
            .and_then(|store| store.merge(agent, session, &classifications))
            .map_err(|error| io::Error::other(error.to_string()))?;
    }
    if let Some(path) = audit_log {
        crate::audit::append_result(
            path,
            agent,
            session_id,
            &classifications,
            decision.decision,
            if matches!(decision.decision, crate::model::ResultEffect::Block) {
                crate::guarded::BLOCKED_EXIT_CODE
            } else {
                0
            },
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn decision_classifications(
    decision: &ResultDecision,
) -> Vec<crate::sensitivity::SourceClassification> {
    let mut sources = std::collections::BTreeMap::new();
    for finding in &decision.findings {
        sources
            .entry(finding.detector_id)
            .or_insert_with(std::collections::BTreeSet::new)
            .insert(finding.category);
    }
    if sources.is_empty() && !decision.categories.is_empty() {
        sources.insert(decision.rule_id, decision.categories.clone());
    }
    sources
        .into_iter()
        .map(|(detector_id, categories)| {
            crate::sensitivity::SourceClassification::dynamic(detector_id, categories)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{blocked_response, inspect_response, safe_response_id};
    use crate::model::ResultEffect;
    use crate::scanner::ScanConfig;

    #[test]
    fn a15_resource_blobs_ignore_mime_claims() {
        for mime in [None, Some("text/plain"), Some("application/json")] {
            let mut resource = serde_json::json!({"uri":"synthetic://resource", "blob":"U1lOVEhFVElDX0FVRElUX1NFQ1JFVA=="});
            if let Some(mime) = mime {
                resource["mimeType"] = mime.into();
            }
            let response = serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"resource","resource":resource}]}});
            let decision = inspect_response(
                &serde_json::to_vec(&response).unwrap(),
                &ScanConfig::default(),
            )
            .unwrap();
            assert_eq!(decision.decision, ResultEffect::Block);
            assert!(decision.content.is_none());
        }
        let text = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"resource","resource":{"uri":"synthetic://resource","text":"ordinary text","mimeType":"text/plain"}}]}}"#;
        assert_eq!(
            inspect_response(text, &ScanConfig::default())
                .unwrap()
                .decision,
            ResultEffect::Allow
        );
    }

    #[test]
    fn sanitizes_nested_mcp_text_without_returning_raw_content() {
        let line = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"mail: mcp-canary@example.test"}]}}"#;
        let decision = inspect_response(line, &ScanConfig::default()).unwrap();
        assert_eq!(decision.decision, ResultEffect::Sanitize);
        let content = decision.content.unwrap();
        assert!(!content.contains("mcp-canary@example.test"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&content).unwrap()["id"],
            1
        );
    }

    #[test]
    fn blocked_response_contains_only_safe_metadata() {
        let response = blocked_response(&serde_json::json!(7), "result.scan_limit");
        assert_eq!(response["id"], 7);
        assert_eq!(response["error"]["data"]["rule_id"], "result.scan_limit");
    }

    #[test]
    fn blocks_unsupported_binary_content() {
        let line = br#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"image","mimeType":"image/png","data":"synthetic"}]}}"#;
        let decision = inspect_response(line, &ScanConfig::default()).unwrap();
        assert_eq!(decision.decision, ResultEffect::Block);
        assert_eq!(decision.rule_id, "result.unsupported_binary");
        assert!(decision.content.is_none());

        let line = br#"{"jsonrpc":"2.0","id":"blocked-id@example.test","result":{"content":[{"type":"image","data":"synthetic"}]}}"#;
        assert_eq!(
            safe_response_id(line, &ScanConfig::default()),
            serde_json::Value::Null
        );
    }
}

//! Line-delimited JSON-RPC MCP response gateway primitives.
//!
//! The CLI gateway owns transport forwarding; this module only validates and
//! sanitizes complete messages before release.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{ChildStderr, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

use serde_json::Value;

use crate::result::ResultDecision;
use crate::scanner::ScanConfig;
use crate::state::StateStore;

pub(crate) const MAX_MCP_MESSAGE_BYTES: usize = crate::scanner::MAX_SCAN_BYTES;

pub(crate) struct Message {
    pub(crate) bytes: Vec<u8>,
    pub(crate) oversized: bool,
}

pub(crate) fn read_message(reader: &mut impl BufRead) -> io::Result<Option<Message>> {
    let mut bytes = Vec::new();
    let mut oversized = false;
    let mut saw_data = false;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(saw_data.then_some(Message { bytes, oversized }));
        }
        saw_data = true;
        let count = buffer
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        let remaining = MAX_MCP_MESSAGE_BYTES.saturating_sub(bytes.len());
        if count > remaining {
            bytes.extend_from_slice(&buffer[..remaining]);
            oversized = true;
        } else if !oversized {
            bytes.extend_from_slice(&buffer[..count]);
        }
        let complete = buffer[..count].last() == Some(&b'\n');
        reader.consume(count);
        if complete {
            while bytes
                .last()
                .is_some_and(|byte| matches!(*byte, b'\n' | b'\r'))
            {
                bytes.pop();
            }
            return Ok(Some(Message { bytes, oversized }));
        }
    }
}

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

pub(crate) struct ProxyOptions<'a> {
    pub(crate) command: &'a [String],
    pub(crate) cwd: &'a Path,
    pub(crate) config: &'a ScanConfig,
    pub(crate) state_dir: Option<&'a Path>,
    pub(crate) session_id: Option<&'a str>,
    pub(crate) agent: &'a str,
    pub(crate) audit_log: Option<&'a Path>,
}

pub(crate) fn proxy(
    options: &ProxyOptions<'_>,
    mut authorize: impl FnMut(&Value) -> io::Result<Option<String>>,
) -> io::Result<i32> {
    let child = Command::new(&options.command[0])
        .args(&options.command[1..])
        .current_dir(options.cwd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut child = crate::guarded::ChildGuard::new(child);
    let mut upstream_input = child
        .child_mut()
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("could not open MCP upstream stdin"))?;
    let upstream_output = child
        .child_mut()
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("could not open MCP upstream stdout"))?;
    let upstream_error = child
        .child_mut()
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("could not open MCP upstream stderr"))?;
    let output = Arc::new(Mutex::new(io::stdout()));
    let response_thread = response_worker(
        Arc::clone(&output),
        upstream_output,
        options.config.clone(),
        options.agent.to_owned(),
        options.state_dir.map(Path::to_path_buf),
        options.session_id.map(str::to_owned),
        options.audit_log.map(Path::to_path_buf),
    );
    let error_thread = diagnostic_worker(upstream_error, options.config.clone());

    let mut client = BufReader::new(io::stdin());
    while let Some(message) = read_message(&mut client)? {
        if message.oversized {
            write_response(
                &output,
                &blocked_response(&Value::Null, "mcp.request_limit"),
            )?;
            continue;
        }
        crate::json::preflight(&message.bytes, MAX_MCP_MESSAGE_BYTES)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed MCP request"))?;
        let value: Value = serde_json::from_slice(&message.bytes)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "malformed MCP request"))?;
        if value.is_array() {
            write_response(
                &output,
                &blocked_response(&Value::Null, "mcp.unsupported_batch"),
            )?;
            continue;
        }
        if !value.is_object() {
            write_response(
                &output,
                &blocked_response(&Value::Null, "mcp.invalid_request"),
            )?;
            continue;
        }
        if let Some(rule_id) = authorize(&value)? {
            if let Some(id) = value.get("id") {
                write_response(&output, &blocked_response(id, &rule_id))?;
            }
            continue;
        }
        upstream_input.write_all(&message.bytes)?;
        upstream_input.write_all(b"\n")?;
        upstream_input.flush()?;
    }
    drop(upstream_input);
    join_worker(response_thread, "MCP response worker failed")?;
    let diagnostic = join_diagnostic(error_thread)?;
    persist_result_metadata(
        &diagnostic,
        options.agent,
        options.state_dir,
        options.session_id,
        options.audit_log,
    )?;
    if matches!(diagnostic.decision, crate::model::ResultEffect::Block) {
        writeln!(
            io::stderr().lock(),
            "daguard blocked MCP diagnostic [result.inspection_failed]"
        )?;
    } else if let Some(content) = diagnostic.content {
        io::stderr().lock().write_all(content.as_bytes())?;
    }
    Ok(child.wait()?.code().unwrap_or(1))
}

fn response_worker(
    output: Arc<Mutex<io::Stdout>>,
    upstream: ChildStdout,
    config: ScanConfig,
    agent: String,
    state_dir: Option<PathBuf>,
    session_id: Option<String>,
    audit_log: Option<PathBuf>,
) -> JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        let mut reader = BufReader::new(upstream);
        while let Some(message) = read_message(&mut reader)? {
            let decision = if message.oversized {
                ResultDecision::block(
                    "result.scan_limit",
                    "The MCP response exceeded the complete-scan limit.",
                )
            } else {
                inspect_response(&message.bytes, &config).unwrap_or_else(|()| {
                    ResultDecision::block(
                        "result.protocol_error",
                        "The MCP response was malformed and could not be inspected safely.",
                    )
                })
            };
            persist_result_metadata(
                &decision,
                &agent,
                state_dir.as_deref(),
                session_id.as_deref(),
                audit_log.as_deref(),
            )?;
            let blocked = matches!(decision.decision, crate::model::ResultEffect::Block);
            let safe = if blocked {
                let id = safe_response_id(&message.bytes, &config);
                serde_json::to_vec(&blocked_response(&id, decision.rule_id))
                    .map_err(io::Error::other)?
            } else {
                decision.content.unwrap_or_default().into_bytes()
            };
            let mut writer = output
                .lock()
                .map_err(|_| io::Error::other("MCP stdout lock poisoned"))?;
            writer.write_all(&safe)?;
            writer.write_all(b"\n")?;
            writer.flush()?;
        }
        Ok(())
    })
}

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

fn persist_result_metadata(
    decision: &ResultDecision,
    agent: &str,
    state_dir: Option<&Path>,
    session_id: Option<&str>,
    audit_log: Option<&Path>,
) -> io::Result<()> {
    let classifications = decision_classifications(decision);
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

fn diagnostic_worker(
    upstream: ChildStderr,
    config: ScanConfig,
) -> JoinHandle<io::Result<ResultDecision>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        upstream
            .take(crate::scanner::MAX_SCAN_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        Ok(crate::scanner::inspect(&bytes, &config))
    })
}

fn write_response(output: &Arc<Mutex<io::Stdout>>, response: &Value) -> io::Result<()> {
    let mut writer = output
        .lock()
        .map_err(|_| io::Error::other("MCP stdout lock poisoned"))?;
    serde_json::to_writer(&mut *writer, response).map_err(io::Error::other)?;
    writeln!(writer)?;
    writer.flush()
}

fn join_worker(worker: JoinHandle<io::Result<()>>, message: &'static str) -> io::Result<()> {
    worker.join().map_err(|_| io::Error::other(message))?
}

fn join_diagnostic(worker: JoinHandle<io::Result<ResultDecision>>) -> io::Result<ResultDecision> {
    worker
        .join()
        .map_err(|_| io::Error::other("MCP diagnostic worker failed"))?
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

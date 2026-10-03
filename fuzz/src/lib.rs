//! Fuzz-only access to the exact production modules, without a public guard API.
#![allow(dead_code)]
#[path = "../../src/adapters/mod.rs"]
mod adapters;
#[path = "../../src/analyzers/mod.rs"]
mod analyzers;
#[path = "../../src/json.rs"]
mod json;
#[path = "../../src/model.rs"]
mod model;
#[path = "../../src/paths.rs"]
mod paths;
#[path = "../../src/policy.rs"]
mod policy;
#[path = "../../src/shell.rs"]
mod shell;

pub fn canonical(bytes: &[u8]) {
    if let Ok(request) = model::CanonicalRequest::from_slice(bytes) {
        let _ = policy::evaluate(&request, None, None);
    }
}
pub fn codex(bytes: &[u8]) {
    if let Ok(request) = adapters::codex::normalize(bytes) {
        if let Ok(decision) = policy::evaluate(&request, None, None) {
            let _ = serde_json::to_vec(&adapters::codex::render(&decision));
        }
    }
}
pub fn cursor(bytes: &[u8]) {
    if let Ok(request) = adapters::cursor::normalize(bytes) {
        if let Ok(decision) = policy::evaluate(&request, None, None) {
            let _ = serde_json::to_vec(&adapters::cursor::render(&decision));
        }
    }
}
pub fn opencode(bytes: &[u8]) {
    if let Ok(request) = adapters::opencode::normalize(bytes) {
        if let Ok(decision) = policy::evaluate(&request, None, None) {
            let _ = serde_json::to_vec(&adapters::opencode::render(&decision));
        }
    }
}
pub fn path(bytes: &[u8]) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let (cwd, candidate) = text
            .split_once('\n')
            .unwrap_or(("/workspace/project", text));
        if let Ok(normalized) = paths::normalize(cwd, candidate) {
            assert_eq!(
                paths::normalize("/", &normalized).ok().as_ref(),
                Some(&normalized)
            );
        }
        let _ = paths::PathPattern::compile(text);
    }
}
pub fn shell(bytes: &[u8]) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = shell::tokenize(text);
        let request = model::CanonicalRequest {
            protocol: 1,
            agent: "fuzz".to_owned(),
            event: "pre_tool_use".to_owned(),
            session_id: None,
            call_id: None,
            cwd: "/workspace/project".to_owned(),
            tool: model::Tool {
                native_name: "shell".to_owned(),
                capability: model::Capability::ShellExecute,
            },
            input: serde_json::json!({}),
            facts: model::Facts {
                command: Some(text.to_owned()),
                ..Default::default()
            },
        };
        let _ = policy::evaluate(&request, None, None);
    }
}
pub fn sql(bytes: &[u8]) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = analyzers::sql::analyze(text, &["synthetic_sensitive"]);
    }
}
pub fn policy(bytes: &[u8]) {
    let _ = policy::Policy::from_slice(bytes, policy::PolicyKind::Organization);
    let _ = policy::Policy::from_slice(bytes, policy::PolicyKind::Project);
}

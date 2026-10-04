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
#[path = "../../src/result.rs"]
mod result;
#[path = "../../src/scanner.rs"]
mod scanner;
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
                paths::normalize(&normalized, &normalized).ok().as_ref(),
                Some(&normalized)
            );
        }
        let _ = paths::PathPattern::compile(text);
    }
}
fn shell_request(command: &str) -> model::CanonicalRequest {
    model::CanonicalRequest {
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
            command: Some(command.to_owned()),
            ..Default::default()
        },
    }
}

pub fn shell(bytes: &[u8]) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = shell::tokenize(text);
        let _ = policy::evaluate(&shell_request(text), None, None);
    }
    // Generate only semantics-preserving literal transformations. Arbitrary
    // input still exercises the parser, but cannot erase the denial oracle.
    let index = usize::from(bytes.first().copied().unwrap_or(0));
    let denied = [
        "cat .env",
        "drush --root=/workspace/project/web php:eval 'return 1;'",
        "mysql --execute='DELETE FROM node'",
        "git push --force origin main",
        "cp README.md vendor/file.txt",
    ][index % 5];
    let wrappers = [
        "",
        "command ",
        "env CHECK=1 ",
        "timeout 5 ",
        "nice -n 5 ",
        "ddev exec ",
    ];
    let prefix = wrappers[usize::from(bytes.get(1).copied().unwrap_or(0)) % wrappers.len()];
    let spacing = if bytes.get(2).is_some_and(|byte| byte & 1 == 1) {
        "\t"
    } else {
        " "
    };
    let command = format!("{prefix}{denied}");
    // Tabs replace only separators outside literal SQL/PHP payloads.
    let command = command.replacen(' ', spacing, 1);
    let decision = policy::evaluate(&shell_request(&command), None, None).unwrap();
    assert_eq!(
        decision.effect,
        model::DecisionEffect::Deny,
        "mandatory shell denial lost"
    );
    let safe = format!("{prefix}git status");
    assert_eq!(
        policy::evaluate(&shell_request(&safe), None, None)
            .unwrap()
            .effect,
        model::DecisionEffect::Allow,
        "safe literal wrapper rejected"
    );
}

pub fn sql(bytes: &[u8]) {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = analyzers::sql::analyze(text, &["synthetic_sensitive"]);
    }
    let index = usize::from(bytes.first().copied().unwrap_or(0));
    let keyword = [
        "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "REPLACE", "CREATE", "GRANT",
        "REVOKE",
    ][index % 10];
    let keyword = if bytes.get(1).is_some_and(|byte| byte & 1 == 1) {
        keyword.to_ascii_lowercase()
    } else {
        keyword.to_owned()
    };
    let query = format!("/* harmless comment */ {keyword} node;");
    assert_eq!(
        analyzers::sql::analyze(&query, &[]).unwrap().effect,
        model::DecisionEffect::Deny,
        "SQL mutation denial lost"
    );
    let table = if bytes.get(2).is_some_and(|byte| byte & 1 == 1) {
        "`synthetic_sensitive`"
    } else {
        "\"synthetic_sensitive\""
    };
    assert_eq!(
        analyzers::sql::analyze(&format!("SELECT * FROM {table}"), &["synthetic_sensitive"])
            .unwrap()
            .effect,
        model::DecisionEffect::Deny,
        "sensitive identifier denial lost"
    );
    assert!(analyzers::sql::analyze("SELECT nid FROM node", &[]).is_none());
}
pub fn policy(bytes: &[u8]) {
    let _ = policy::Policy::from_slice(bytes, policy::PolicyKind::Organization);
    let _ = policy::Policy::from_slice(bytes, policy::PolicyKind::Project);
}
fn validate_scanner_output(bytes: &[u8], decision: &result::ResultDecision) {
    if decision.decision == model::ResultEffect::Block {
        assert!(decision.content.is_none(), "blocked result carried content");
    } else {
        let content = decision
            .content
            .as_ref()
            .expect("deliverable result missing content");
        if serde_json::from_slice::<serde_json::Value>(bytes).is_ok() {
            assert!(
                serde_json::from_str::<serde_json::Value>(content).is_ok(),
                "sanitized JSON became invalid"
            );
        }
    }
}

pub fn result_scanner(bytes: &[u8]) {
    let config = scanner::ScanConfig::default();
    validate_scanner_output(bytes, &scanner::inspect(bytes, &config));
    validate_scanner_output(bytes, &scanner::inspect_sensitive_source(bytes, &config));
    // The canary is generated from fuzz bytes, always fake, and never inserted
    // into assertion messages. Test values, classified keys and known sources.
    let mut canary = String::from("SYNTHETIC_FUZZ_CANARY_");
    for byte in bytes.iter().take(16) {
        use std::fmt::Write;
        write!(&mut canary, "{byte:02x}").unwrap();
    }
    for value in [
        serde_json::json!({"password": canary}),
        serde_json::json!({"customer_profile": {canary.clone(): null}}),
        serde_json::json!({"password": format!("[REDACTED:credentials:provider_token:{canary}]")}),
    ] {
        let input = serde_json::to_vec(&value).unwrap();
        let decision = scanner::inspect(&input, &config);
        validate_scanner_output(&input, &decision);
        let serialized = serde_json::to_string(&decision).unwrap();
        assert!(
            !serialized.contains(&canary),
            "protected fake marker survived scanning"
        );
    }
    let source =
        serde_json::to_vec(&serde_json::json!({canary.clone(): [canary.clone()]})).unwrap();
    let decision = scanner::inspect_sensitive_source(&source, &config);
    validate_scanner_output(&source, &decision);
    assert!(
        !serde_json::to_string(&decision).unwrap().contains(&canary),
        "known-source fake marker survived scanning"
    );
    let text = format!("password=\n{canary}");
    let decision = scanner::inspect(text.as_bytes(), &config);
    assert!(
        !serde_json::to_string(&decision).unwrap().contains(&canary),
        "continuation fake marker survived scanning"
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn security_oracles_cover_literal_variants() {
        for selector in 0..=255 {
            for wrapper in 0..6 {
                super::shell(&[selector, wrapper, selector]);
                super::sql(&[selector, wrapper, selector]);
            }
            super::result_scanner(&[selector]);
        }
    }
}

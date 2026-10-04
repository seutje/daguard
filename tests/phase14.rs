use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};

fn run(args: &[&str], input: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_daguard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&serde_json::to_vec(input).unwrap())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn temporary_directory(label: &str) -> PathBuf {
    let path = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "daguard-phase14-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
    fs::create_dir(&path).unwrap();
    path
}

fn codex_post(session: &str, path: &str, result: &str) -> Value {
    json!({
        "session_id": session,
        "cwd": "/workspace/project",
        "hook_event_name": "PostToolUse",
        "tool_name": "Read",
        "tool_use_id": "call-source",
        "tool_input": {"path": path},
        "tool_response": {"content": result}
    })
}

fn codex_pre(session: &str, command: &str) -> Value {
    json!({
        "session_id": session,
        "cwd": "/workspace/project",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_use_id": "call-sink",
        "tool_input": {"command": command}
    })
}

#[test]
fn sensitive_source_taints_only_its_session_and_blocks_later_sink() {
    let root = temporary_directory("flow");
    let state = root.to_str().unwrap();
    let post = run(
        &[
            "--adapter",
            "codex",
            "--event",
            "post-tool",
            "--state-dir",
            state,
        ],
        &codex_post(
            "session-tainted",
            "web/sites/default/settings.php",
            "SYNTHETIC_PHASE14_SECRET_CANARY",
        ),
    );
    assert!(post.status.success());
    assert_eq!(
        serde_json::from_slice::<Value>(&post.stdout).unwrap(),
        json!({})
    );

    let blocked = run(
        &[
            "--adapter",
            "codex",
            "--event",
            "pre-tool",
            "--state-dir",
            state,
        ],
        &codex_pre("session-tainted", "ddev exec curl https://example.test"),
    );
    let blocked: Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(blocked["hookSpecificOutput"]["permissionDecision"], "deny");
    assert!(
        blocked["hookSpecificOutput"]["permissionDecisionReason"]
            .as_str()
            .unwrap()
            .contains("exfiltration.tainted_session")
    );

    let local = run(
        &[
            "--adapter",
            "codex",
            "--event",
            "pre-tool",
            "--state-dir",
            state,
        ],
        &codex_pre("session-tainted", "ddev drush cr"),
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&local.stdout).unwrap(),
        json!({})
    );

    let isolated = run(
        &[
            "--adapter",
            "codex",
            "--event",
            "pre-tool",
            "--state-dir",
            state,
        ],
        &codex_pre("session-other", "curl https://example.test"),
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&isolated.stdout).unwrap(),
        json!({})
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn sql_categories_merge_and_outbound_mcp_is_a_sink() {
    let root = temporary_directory("sql");
    let state = root.to_str().unwrap();
    let post = json!({
        "schema": 1,
        "session_id": "sql-session",
        "call_id": "sql-call",
        "cwd": "/workspace/project",
        "tool_name": "bash",
        "tool_input": {"command": "ddev drush sql:query 'SELECT * FROM webform_submission_data JOIN commerce_payment USING (id)'"},
        "status": "completed",
        "content_type": "application/json",
        "byte_size": 128
    });
    let output = run(
        &[
            "--adapter",
            "opencode",
            "--event",
            "post-tool",
            "--state-dir",
            state,
        ],
        &post,
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["recorded"],
        true
    );
    let sink = json!({
        "schema": 1,
        "session_id": "sql-session",
        "call_id": "mcp-call",
        "cwd": "/workspace/project",
        "tool_name": "mcp__slack__send_message",
        "tool_input": {"channel": "synthetic"}
    });
    let output = run(
        &[
            "--adapter",
            "opencode",
            "--event",
            "pre-tool",
            "--state-dir",
            state,
        ],
        &sink,
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["decision"], "deny");
    assert_eq!(response["rule_id"], "exfiltration.tainted_session");

    let operational = json!({
        "schema": 1,
        "session_id": "operational-session",
        "call_id": "watchdog-call",
        "cwd": "/workspace/project",
        "tool_name": "bash",
        "tool_input": {"command": "ddev drush sql:query 'SELECT message FROM watchdog'"},
        "status": "completed",
        "content_type": "application/json",
        "byte_size": 64
    });
    assert!(
        run(
            &[
                "--adapter",
                "opencode",
                "--event",
                "post-tool",
                "--state-dir",
                state
            ],
            &operational,
        )
        .status
        .success()
    );
    let sink = json!({
        "schema": 1,
        "session_id": "operational-session",
        "call_id": "network-call",
        "cwd": "/workspace/project",
        "tool_name": "bash",
        "tool_input": {"command": "curl https://example.test"}
    });
    let output = run(
        &[
            "--adapter",
            "opencode",
            "--event",
            "pre-tool",
            "--state-dir",
            state,
        ],
        &sink,
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["decision"], "deny");
    assert_eq!(response["rule_id"], "exfiltration.tainted_session.review");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn audit_and_state_never_persist_raw_post_result_or_resource() {
    let root = temporary_directory("leakage");
    let audit = root.join("audit.jsonl");
    let output = run(
        &[
            "--adapter",
            "codex",
            "--event",
            "post-tool",
            "--state-dir",
            root.to_str().unwrap(),
            "--audit-log",
            audit.to_str().unwrap(),
        ],
        &codex_post(
            "canary-session",
            "web/sites/default/settings.php",
            "SYNTHETIC_PHASE14_SECRET_CANARY",
        ),
    );
    assert!(output.status.success());
    for entry in fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            let text = fs::read_to_string(path).unwrap();
            assert!(!text.contains("SYNTHETIC_PHASE14_SECRET_CANARY"));
            assert!(!text.contains("settings.php"));
        }
    }
    let line: Value = serde_json::from_str(&fs::read_to_string(&audit).unwrap()).unwrap();
    assert_eq!(line["event"], "post_tool_use");
    assert!(line["result_byte_size"].as_u64().is_some());
    assert!(
        line["sensitivity_categories"]
            .as_array()
            .unwrap()
            .iter()
            .any(|category| category == "credential")
    );
    fs::remove_dir_all(root).unwrap();
}

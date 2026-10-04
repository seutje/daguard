#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

fn run(args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_daguard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn temporary_directory(label: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "daguard-phase15-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn inspect_result_sanitizes_structured_and_configured_sensitive_values() {
    let root = temporary_directory("inspect");
    let policy = root.join("policy.json");
    fs::write(
        &policy,
        br#"{
          "schema":3,
          "result":{
            "secret_prefixes":["org_live_"],
            "sensitive_fields":{"case_reference":"private_content"},
            "ip_addresses_are_personal":true
          }
        }"#,
    )
    .unwrap();
    let input = br#"{"case_reference":"PRIVATE-CASE-CANARY","note":"org_live_abcdefghijklmnop","ip":"192.0.2.44","ip6":"2001:db8::44","safe":"kept"}"#;
    let output = run(
        &["inspect-result", "--policy", policy.to_str().unwrap(), "-"],
        input,
    );
    assert!(output.status.success());
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "sanitize");
    let content = decision["content"].as_str().unwrap();
    assert!(!content.contains("PRIVATE-CASE-CANARY"));
    assert!(!content.contains("org_live_abcdefghijklmnop"));
    assert!(!content.contains("192.0.2.44"));
    assert!(!content.contains("2001:db8::44"));
    assert!(content.contains("kept"));
    serde_json::from_str::<Value>(content).unwrap();

    let protected_file = root.join("settings.php");
    fs::write(&protected_file, "DIRECT-FILE-CANARY").unwrap();
    let rejected = run(&["inspect-result", protected_file.to_str().unwrap()], b"");
    assert_eq!(rejected.status.code(), Some(2));
    assert_eq!(rejected.stdout, Vec::<u8>::new());
    assert!(!String::from_utf8_lossy(&rejected.stderr).contains("DIRECT-FILE-CANARY"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn shipped_policy_enables_common_result_detectors() {
    let policy = format!("{}/policy/default-policy.json", env!("CARGO_MANIFEST_DIR"));
    let input = br#"{
        "username":"username-canary",
        "display_name":"display-canary",
        "first_name":"first-canary",
        "last_name":"last-canary",
        "given_name":"given-canary",
        "family_name":"family-canary",
        "account_number":"account-canary",
        "customer_id":"customer-canary",
        "order_id":"order-canary",
        "case_reference":"case-canary",
        "tokens":[
            "npm_abcdefghijklmnopqrstuvwxyz123456",
            "pypi-abcdefghijklmnopqrstuvwxyz",
            "dop_v1_abcdefghijklmnopqrstuvwxyz",
            "hvs.abcdefghijklmnopqrstuvwxyz",
            "hvb.abcdefghijklmnopqrstuvwxyz",
            "hf_abcdefghijklmnopqrstuvwxyz"
        ],
        "ip":"192.0.2.44",
        "safe":"kept"
    }"#;
    let output = run(&["inspect-result", "--policy", &policy, "-"], input);
    assert!(output.status.success());

    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "sanitize");
    let content = decision["content"].as_str().unwrap();
    for canary in [
        "username-canary",
        "display-canary",
        "first-canary",
        "last-canary",
        "given-canary",
        "family-canary",
        "account-canary",
        "customer-canary",
        "order-canary",
        "case-canary",
        "npm_abcdefghijklmnopqrstuvwxyz123456",
        "pypi-abcdefghijklmnopqrstuvwxyz",
        "dop_v1_abcdefghijklmnopqrstuvwxyz",
        "hvs.abcdefghijklmnopqrstuvwxyz",
        "hvb.abcdefghijklmnopqrstuvwxyz",
        "hf_abcdefghijklmnopqrstuvwxyz",
        "192.0.2.44",
    ] {
        assert!(!content.contains(canary));
    }
    assert!(content.contains("kept"));

    let sanitized: Value = serde_json::from_str(content).unwrap();
    assert_eq!(sanitized["username"], "[REDACTED:PERSONAL_DATA]");
    assert_eq!(sanitized["customer_id"], "[REDACTED:CUSTOMER_DATA]");
    assert_eq!(sanitized["account_number"], "[REDACTED:FINANCIAL_DATA]");
}

#[test]
fn guarded_execution_buffers_and_sanitizes_stdout_stderr_and_tables() {
    let stdout_canary = "phase15-stdout@example.test";
    let stderr_canary = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    let table = format!(
        "mail|pass|safe\n----|----|----\n{stdout_canary}|synthetic-password-hash|kept\nsecond@example.test|second-password-hash|also-kept\n"
    );
    let output = run(&["exec", "--", "/usr/bin/printf", "%s", &table], b"");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(!stdout.contains(stdout_canary));
    assert!(!stdout.contains("synthetic-password-hash"));
    assert!(!stdout.contains("second-password-hash"));
    assert!(stdout.contains("kept"));
    assert!(stdout.contains("also-kept"));

    let root = temporary_directory("stderr");
    let stderr_program = root.join("stderr-program");
    fs::write(
        &stderr_program,
        b"#!/bin/sh\nprintf '%s\\n' \"$1\" >&2\nexit 23\n",
    )
    .unwrap();
    fs::set_permissions(&stderr_program, fs::Permissions::from_mode(0o700)).unwrap();
    let stderr_output = run(
        &[
            "exec",
            "--",
            stderr_program.to_str().unwrap(),
            stderr_canary,
        ],
        b"",
    );
    assert_eq!(stderr_output.status.code(), Some(23));
    let stderr = String::from_utf8(stderr_output.stderr).unwrap();
    assert!(!stderr.contains(stderr_canary));
    assert!(stderr.contains("[REDACTED:CREDENTIAL]"));

    let split = run(
        &[
            "exec",
            "--",
            "/bin/sh",
            "-c",
            "printf 'phase15-split@'; printf 'example.test'",
        ],
        b"",
    );
    assert!(split.status.success());
    assert!(!String::from_utf8_lossy(&split.stdout).contains("phase15-split@example.test"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn guarded_sql_denies_sensitive_sources_and_redacts_permitted_sensitive_columns() {
    let root = temporary_directory("sql-source");
    let ddev = root.join("ddev");
    fs::write(
        &ddev,
        b"#!/bin/sh\ncase \"$*\" in\n  *mail*) printf 'mail|title\\n---|---\\nphase15-sql@example.test|public-title\\n' ;;\n  *) printf 'nid|title\\n---|---\\n1|source-canary\\n' ;;\nesac\n",
    )
    .unwrap();
    fs::set_permissions(&ddev, fs::Permissions::from_mode(0o700)).unwrap();

    let sensitive = run(
        &[
            "exec",
            "--",
            ddev.to_str().unwrap(),
            "drush",
            "sql:query",
            "SELECT uid, name FROM users_field_data",
        ],
        b"",
    );
    assert_eq!(sensitive.status.code(), Some(125));
    assert_eq!(sensitive.stdout, Vec::<u8>::new());
    assert!(String::from_utf8_lossy(&sensitive.stderr).contains("sql.read.sensitive_table"));

    let column_redaction = run(
        &[
            "exec",
            "--",
            ddev.to_str().unwrap(),
            "drush",
            "sql:query",
            "SELECT mail, title FROM node_field_data",
        ],
        b"",
    );
    assert!(column_redaction.status.success());
    let output = String::from_utf8(column_redaction.stdout).unwrap();
    assert!(!output.contains("phase15-sql@example.test"));
    assert!(output.contains("public-title"));

    let ordinary = run(
        &[
            "exec",
            "--",
            ddev.to_str().unwrap(),
            "drush",
            "sql:query",
            "SELECT nid, title FROM node_field_data",
        ],
        b"",
    );
    assert!(ordinary.status.success());
    assert!(String::from_utf8_lossy(&ordinary.stdout).contains("source-canary"));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn guarded_execution_preserves_exit_status_and_blocks_before_sensitive_read() {
    let status = run(&["exec", "--", "/bin/sh", "-c", "exit 23"], b"");
    assert_eq!(status.status.code(), Some(23));

    let denied = run(
        &[
            "exec",
            "--",
            "/usr/bin/cat",
            "/workspace/project/web/sites/default/settings.php",
        ],
        b"",
    );
    assert_eq!(denied.status.code(), Some(125));
    assert_eq!(denied.stdout, Vec::<u8>::new());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("drupal.secret.settings_php"));

    let root = temporary_directory("cwd");
    let current = run(
        &["exec", "--cwd", root.to_str().unwrap(), "--", "/bin/pwd"],
        b"",
    );
    assert!(current.status.success());
    let expected = fs::canonicalize(&root).unwrap();
    assert_eq!(
        PathBuf::from(String::from_utf8_lossy(&current.stdout).trim()),
        expected
    );
    fs::remove_dir_all(root).unwrap();
}

fn assert_native_bridge(state: &std::path::Path, request: &Value) {
    let native = json!({"session_id":"phase15-session", "tool_use_id":"synthetic",
        "cwd":"/workspace/project", "hook_event_name":"PreToolUse", "tool_name":"mcp__remote__read_file",
        "tool_input":{"path":"README.md"}});
    let native_output = run(
        &[
            "--adapter",
            "codex",
            "--event",
            "pre-tool",
            "--state-dir",
            state.to_str().unwrap(),
        ],
        &serde_json::to_vec(&native).unwrap(),
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&native_output.stdout).unwrap()["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    let isolated = serde_json::to_vec(&request).unwrap();
    let isolated = String::from_utf8(isolated)
        .unwrap()
        .replace("\"codex\"", "\"cursor\"");
    assert_eq!(
        serde_json::from_slice::<Value>(
            &run(
                &["check", "--state-dir", state.to_str().unwrap(), "-"],
                isolated.as_bytes()
            )
            .stdout
        )
        .unwrap()["decision"],
        "allow"
    );
}

#[test]
fn guarded_detection_taints_session_without_persisting_the_canary() {
    let root = temporary_directory("taint");
    let audit = root.join("audit.jsonl");
    let state = root.join("state");
    let canary = "phase15-taint@example.test";
    let guarded = run(
        &[
            "exec",
            "--state-dir",
            state.to_str().unwrap(),
            "--audit-log",
            audit.to_str().unwrap(),
            "--session-id",
            "phase15-session",
            "--integration-agent",
            "codex",
            "--",
            "/usr/bin/printf",
            "%s",
            canary,
        ],
        b"",
    );
    assert!(guarded.status.success());
    assert!(!String::from_utf8_lossy(&guarded.stdout).contains(canary));

    let request = json!({
        "protocol":1,
        "agent":"codex",
        "event":"pre_tool_use",
        "session_id":"phase15-session",
        "cwd":"/workspace/project",
        "tool":{"native_name":"Bash","capability":"shell_execute"},
        "input":{"command":"curl https://example.test"},
        "facts":{"command":"curl https://example.test"}
    });
    let blocked = run(
        &["check", "--state-dir", state.to_str().unwrap(), "-"],
        &serde_json::to_vec(&request).unwrap(),
    );
    let decision: Value = serde_json::from_slice(&blocked.stdout).unwrap();
    assert_eq!(decision["rule_id"], "exfiltration.tainted_session");
    assert_native_bridge(&state, &request);
    let result_event = fs::read_to_string(&audit)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .find(|event| event["event"] == "result_containment")
        .unwrap();
    assert_eq!(result_event["schema"], 4);
    assert_eq!(result_event["decision"], "sanitize");
    assert!(
        result_event["source_ids"]
            .as_array()
            .unwrap()
            .iter()
            .any(|source| source == "personal.email")
    );
    for entry in fs::read_dir(&root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            assert!(!fs::read_to_string(path).unwrap().contains(canary));
        } else {
            for state_entry in fs::read_dir(path).unwrap() {
                assert!(
                    !fs::read_to_string(state_entry.unwrap().path())
                        .unwrap()
                        .contains(canary)
                );
            }
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn guarded_execution_fails_closed_on_timeout_and_oversized_output() {
    let started = Instant::now();
    let timeout = run(
        &[
            "exec",
            "--timeout-seconds",
            "1",
            "--",
            "/bin/sh",
            "-c",
            "sleep 30",
        ],
        b"",
    );
    assert_eq!(timeout.status.code(), Some(124));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(String::from_utf8_lossy(&timeout.stderr).contains("result.timeout"));

    let oversized = run(
        &["exec", "--", "/usr/bin/head", "-c", "1048577", "/dev/zero"],
        b"",
    );
    assert_eq!(oversized.status.code(), Some(125));
    assert_eq!(oversized.stdout, Vec::<u8>::new());
    assert!(String::from_utf8_lossy(&oversized.stderr).contains("result.scan_limit"));
}

#[test]
fn guarded_execution_forwards_termination_and_withholds_on_metadata_failure() {
    let started = Instant::now();
    let child = Command::new(env!("CARGO_BIN_EXE_daguard"))
        .args(["exec", "--", "/bin/sh", "-c", "sleep 30"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(100));
    let signal = Command::new("/bin/kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .unwrap();
    assert!(signal.success());
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(143));
    assert!(started.elapsed() < Duration::from_secs(5));

    let root = temporary_directory("metadata-failure");
    let canary = "metadata-failure@example.test";
    let blocked = run(
        &[
            "exec",
            "--audit-log",
            root.to_str().unwrap(),
            "--",
            "/usr/bin/printf",
            "%s",
            canary,
        ],
        b"",
    );
    assert_eq!(blocked.status.code(), Some(4));
    assert!(!String::from_utf8_lossy(&blocked.stdout).contains(canary));
    assert!(!String::from_utf8_lossy(&blocked.stderr).contains(canary));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn mcp_gateway_sanitizes_responses_and_applies_pre_tool_policy() {
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"mcp-canary@example.test"}]}}"#;
    let script = format!("IFS= read -r ignored; printf '%s\\n' '{response}'");
    let request = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"lookup","arguments":{"search_term":"safe"}}}
"#;
    let output = run(&["mcp-proxy", "--", "/bin/sh", "-c", &script], request);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let safe = String::from_utf8(output.stdout).unwrap();
    assert!(!safe.contains("mcp-canary@example.test"));
    assert!(safe.contains("[REDACTED:PERSONAL_DATA]"));
    serde_json::from_str::<Value>(safe.trim()).unwrap();

    let diagnostic_canary = "mcp-diagnostic@example.test";
    let root = temporary_directory("mcp-diagnostic");
    let server = root.join("mcp-server");
    let script = format!(
        "#!/bin/sh\nIFS= read -r ignored\nprintf '%s\\n' '{diagnostic_canary}' >&2\nprintf '%s\\n' '{response}'\n"
    );
    fs::write(&server, script).unwrap();
    fs::set_permissions(&server, fs::Permissions::from_mode(0o700)).unwrap();
    let output = run(&["mcp-proxy", "--", server.to_str().unwrap()], request);
    let diagnostic = String::from_utf8(output.stderr).unwrap();
    assert!(!diagnostic.contains(diagnostic_canary));
    assert!(diagnostic.contains("[REDACTED:PERSONAL_DATA]"));

    let denied = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"shell","command":"git push --force"}}
"#;
    let output = run(
        &[
            "mcp-proxy",
            "--",
            "/bin/sh",
            "-c",
            "IFS= read -r ignored || exit 0; printf '{}\\n'",
        ],
        denied,
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["id"], 7);
    assert_eq!(response["error"]["data"]["rule_id"], "git.force_push");

    let denied_path = br#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"read_file","path":".env"}}
"#;
    let output = run(
        &[
            "mcp-proxy",
            "--",
            "/bin/sh",
            "-c",
            "IFS= read -r ignored || exit 0; printf '{}\\n'",
        ],
        denied_path,
    );
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["id"], 8);
    assert_eq!(response["error"]["data"]["rule_id"], "drupal.secret.env");
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a12_session_binding_requires_complete_host_identity() {
    for args in [
        vec!["exec", "--session-id", "synthetic", "--", "/usr/bin/true"],
        vec![
            "exec",
            "--integration-agent",
            "codex",
            "--",
            "/usr/bin/true",
        ],
        vec![
            "exec",
            "--integration-agent",
            "untrusted",
            "--session-id",
            "synthetic",
            "--",
            "/usr/bin/true",
        ],
    ] {
        let output = run(&args, b"");
        assert!(!output.status.success());
        assert_eq!(output.stdout, [] as [u8; 0]);
    }
}

#[test]
fn a13_classified_key_is_absent_from_output_errors_and_metadata() {
    let root = temporary_directory("classified-key");
    let script = root.join("synthetic-producer");
    fs::write(&script, b"#!/bin/sh\nprintf '%s' '{\"password\":{\"SYNTHETIC_AUDIT_SECRET\":null}}'\nprintf '%s' '{\"password\":[{\"SYNTHETIC_AUDIT_SECRET\":\"value\"}]}' >&2\nexit 7\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let state = root.join("state");
    let audit = root.join("audit.jsonl");
    let output = run(
        &[
            "exec",
            "--integration-agent",
            "codex",
            "--session-id",
            "synthetic",
            "--state-dir",
            state.to_str().unwrap(),
            "--audit-log",
            audit.to_str().unwrap(),
            "--",
            script.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(output.status.code(), Some(7));
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!String::from_utf8_lossy(bytes).contains("SYNTHETIC_AUDIT_SECRET"));
    }
    assert!(
        !fs::read_to_string(audit)
            .unwrap()
            .contains("SYNTHETIC_AUDIT_SECRET")
    );
    for entry in fs::read_dir(state).unwrap() {
        assert!(
            !fs::read_to_string(entry.unwrap().path())
                .unwrap()
                .contains("SYNTHETIC_AUDIT_SECRET")
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a14_truncated_secrets_are_contained_on_error_streams() {
    let root = temporary_directory("truncated-key");
    let script = root.join("synthetic-producer");
    fs::write(&script, b"#!/bin/sh\nprintf 'password=\nSYNTHETIC_AUDIT_KEY_BODY\n'\nprintf '%s\n' '-----BEGIN PRIVATE KEY-----' 'SYNTHETIC_AUDIT_KEY_BODY' >&2\nexit 7\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let audit = root.join("audit.jsonl");
    let output = run(
        &[
            "exec",
            "--audit-log",
            audit.to_str().unwrap(),
            "--",
            script.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(output.status.code(), Some(7));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_AUDIT_KEY_BODY"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SYNTHETIC_AUDIT_KEY_BODY"));
    assert!(
        !fs::read_to_string(audit)
            .unwrap()
            .contains("SYNTHETIC_AUDIT_KEY_BODY")
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a17_detached_descendant_cannot_extend_capture_deadline() {
    let root = temporary_directory("detached-pipe");
    let script = root.join("synthetic-producer");
    fs::write(&script, b"#!/bin/sh\nsetsid /bin/sh -c 'printf ready > \"$1/ready\"; /bin/sleep 2' synthetic \"$1\" &\nwhile [ ! -f \"$1/ready\" ]; do /bin/sleep 0.01; done\nexit 0\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
    let started = Instant::now();
    let output = run(
        &[
            "exec",
            "--timeout-seconds",
            "1",
            "--",
            script.to_str().unwrap(),
            root.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(output.status.code(), Some(124));
    assert!(started.elapsed() < Duration::from_millis(1700));
    assert_eq!(output.stdout, [] as [u8; 0]);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a18_mcp_listing_preserves_schema_metadata() {
    let response = r#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"lookup","inputSchema":{"type":"object","properties":{"password":{"type":"string"}}}}]}}"#;
    let script = format!("IFS= read -r ignored; printf '%s\n' '{response}'");
    let output = run(
        &["mcp-proxy", "--", "/bin/sh", "-c", &script],
        b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n",
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        value["result"]["tools"][0]["inputSchema"]["properties"]["password"]["type"],
        "string"
    );
}

#[test]
fn a18_mcp_control_messages_remain_usable_in_tainted_sessions() {
    let root = temporary_directory("mcp-control");
    let state = root.join("state");
    let seed = run(
        &[
            "exec",
            "--integration-agent",
            "codex",
            "--session-id",
            "synthetic",
            "--state-dir",
            state.to_str().unwrap(),
            "--",
            "/usr/bin/printf",
            "%s",
            "synthetic-control@example.test",
        ],
        b"",
    );
    assert!(seed.status.success());
    let initialization = r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"synthetic","version":"1"}}}"#;
    let listing = r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"lookup","inputSchema":{"type":"object","properties":{"password":{"type":"string"}}}}]}}"#;
    let script = format!(
        "IFS= read -r first; IFS= read -r second; printf '%s\n' '{initialization}' '{listing}'"
    );
    let requests = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"synthetic\",\"version\":\"1\"}}}\n{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";
    let output = run(
        &[
            "mcp-proxy",
            "--integration-agent",
            "codex",
            "--session-id",
            "synthetic",
            "--state-dir",
            state.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &script,
        ],
        requests,
    );
    assert!(output.status.success());
    let replies = String::from_utf8(output.stdout).unwrap();
    let replies = replies
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(replies.len(), 2);
    assert_eq!(replies[0]["result"]["protocolVersion"], "2025-06-18");
    assert_eq!(
        replies[1]["result"]["tools"][0]["inputSchema"]["properties"]["password"]["type"],
        "string"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a18_mcp_worker_failures_and_partial_frames_stop_connected_clients() {
    for script in [
        "IFS= read -r request; printf '%s\n' '{\"jsonrpc\":\"2.0\",\"id\":99,\"result\":\"SYNTHETIC_UNCORRELATED_BODY\"}'; /bin/sleep 3",
        "IFS= read -r request; printf '%s' '{\"jsonrpc\":'; /bin/sleep 3",
        "IFS= read -r request; /usr/bin/head -c 1048577 /dev/zero; /bin/sleep 3",
    ] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_daguard"))
            .args([
                "mcp-proxy",
                "--timeout-seconds",
                "1",
                "--",
                "/bin/sh",
                "-c",
                script,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        input.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"lookup\",\"arguments\":{}}}\n").unwrap();
        let started = Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if started.elapsed() >= Duration::from_millis(1800) {
                child.kill().unwrap();
                panic!("MCP supervision did not terminate promptly");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(input);
        let output = child.wait_with_output().unwrap();
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_UNCORRELATED_BODY"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("MCP gateway failed"));
    }
}

#[test]
fn a18_mcp_dynamic_detection_updates_native_session() {
    let root = temporary_directory("mcp-native-state");
    let state = root.join("state");
    let script = r#"IFS= read -r request; printf '%s\n' '{"jsonrpc":"2.0","id":1,"result":{"password":"SYNTHETIC_MCP_SECRET"}}'"#;
    let request = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"lookup\",\"arguments\":{}}}\n";
    let output = run(
        &[
            "mcp-proxy",
            "--integration-agent",
            "codex",
            "--session-id",
            "synthetic",
            "--state-dir",
            state.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            script,
        ],
        request,
    );
    assert!(output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SYNTHETIC_MCP_SECRET"));
    let native = json!({"session_id":"synthetic", "tool_use_id":"synthetic", "cwd":"/workspace/project", "hook_event_name":"PreToolUse", "tool_name":"mcp__remote__read_file", "tool_input":{"path":"README.md"}});
    let output = run(
        &[
            "--adapter",
            "codex",
            "--event",
            "pre-tool",
            "--state-dir",
            state.to_str().unwrap(),
        ],
        &serde_json::to_vec(&native).unwrap(),
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&output.stdout).unwrap()["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a18_mcp_cancelled_requests_need_no_reply() {
    let requests = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"lookup\",\"arguments\":{}}}\n{\"jsonrpc\":\"2.0\",\"method\":\"notifications/cancelled\",\"params\":{\"requestId\":1}}\n";
    let script = "IFS= read -r request; IFS= read -r cancel; exit 0";
    let output = run(
        &[
            "mcp-proxy",
            "--timeout-seconds",
            "1",
            "--",
            "/bin/sh",
            "-c",
            script,
        ],
        requests,
    );
    assert!(output.status.success());
    assert_eq!(output.stdout, [] as [u8; 0]);
}

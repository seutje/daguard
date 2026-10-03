use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::{fs, path::PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
struct Fixture {
    capability: String,
    path: String,
    decision: String,
    rule_id: String,
}

fn run(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_daguard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn temporary_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "daguard-{name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn request(capability: &str, path: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "protocol": 1,
        "agent": "synthetic-test-agent",
        "event": "pre_tool_use",
        "cwd": "/workspace/project",
        "tool": {"native_name": "synthetic", "capability": capability},
        "input": {"synthetic": true},
        "facts": {"paths": [path]}
    }))
    .unwrap()
}

fn shell_request(command: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "protocol": 1,
        "agent": "synthetic-test-agent",
        "event": "pre_tool_use",
        "cwd": "/workspace/project",
        "tool": {"native_name": "Bash", "capability": "shell_execute"},
        "input": {"command": command},
        "facts": {"command": command}
    }))
    .unwrap()
}

fn shell_decision(command: &str) -> Value {
    let output = run(&["check"], &shell_request(command));
    assert!(
        output.status.success(),
        "shell check failed for {command}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn codex_request(tool_name: &str, tool_input: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "session_id": "thr_synthetic",
        "transcript_path": null,
        "cwd": "/workspace/project",
        "hook_event_name": "PreToolUse",
        "model": "fixture-model",
        "turn_id": "turn_synthetic",
        "permission_mode": "default",
        "tool_name": tool_name,
        "tool_use_id": "call_synthetic",
        "tool_input": tool_input
    }))
    .unwrap()
}

fn run_codex(input: &[u8], extra_args: &[&str]) -> Output {
    let mut args = vec!["--adapter", "codex", "--event", "pre-tool"];
    args.extend_from_slice(extra_args);
    run(&args, input)
}

fn cursor_request(tool_name: &str, tool_input: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "call_synthetic",
        "cwd": "/workspace/project",
        "model": "fixture-model"
    }))
    .unwrap()
}

fn run_cursor(input: &[u8], extra_args: &[&str]) -> Output {
    let mut args = vec!["--adapter", "cursor", "--event", "pre-tool"];
    args.extend_from_slice(extra_args);
    run(&args, input)
}

#[test]
fn protected_path_fixtures_produce_expected_decisions() {
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/protected_paths.json")).unwrap();
    for fixture in fixtures {
        let output = run(&["check"], &request(&fixture.capability, &fixture.path));
        assert!(
            output.status.success(),
            "check failed for {}: {}",
            fixture.path,
            String::from_utf8_lossy(&output.stderr)
        );
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], fixture.decision, "{}", fixture.path);
        assert_eq!(decision["rule_id"], fixture.rule_id, "{}", fixture.path);
    }
}

#[test]
fn malformed_request_never_emits_allow() {
    let output = run(&["check"], br#"{"protocol":1"#);
    assert_eq!(output.status.code(), Some(4));
    assert_eq!(output.stdout, Vec::<u8>::new());
    assert_ne!(output.stderr, Vec::<u8>::new());
}

#[test]
fn unknown_tool_nested_sensitive_path_is_denied() {
    let request = serde_json::to_vec(&json!({
        "protocol": 1,
        "agent": "synthetic-test-agent",
        "event": "pre_tool_use",
        "cwd": "/workspace/project",
        "tool": {"native_name": "novel_tool", "capability": "unknown"},
        "input": {"options": {"path": ".env.development"}},
        "facts": {"paths": []}
    }))
    .unwrap();
    let output = run(&["check"], &request);
    assert!(output.status.success());
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "deny");
    assert_eq!(decision["rule_id"], "drupal.secret.env");
}

#[test]
fn invalid_mandatory_policy_never_emits_allow() {
    let policy = format!(
        "{}/tests/fixtures/invalid-policy.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = run(
        &["check", "--policy", &policy],
        &request("file_read", "README.md"),
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, Vec::<u8>::new());
    assert_ne!(output.stderr, Vec::<u8>::new());
}

#[test]
fn missing_mandatory_policy_never_emits_allow() {
    let output = run(
        &[
            "check",
            "--policy",
            "/definitely/missing/daguard-policy.json",
        ],
        &request("file_read", "README.md"),
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, Vec::<u8>::new());
}

#[test]
fn version_and_explain_are_available() {
    let version = run(&["version"], b"");
    assert!(version.status.success());
    assert!(String::from_utf8_lossy(&version.stdout).starts_with("daguard "));

    let explain = run(&["explain", "drupal.secret.settings_php"], b"");
    assert!(explain.status.success());
    assert!(String::from_utf8_lossy(&explain.stdout).contains("settings.php"));
    assert!(String::from_utf8_lossy(&explain.stdout).contains("Remediation:"));
}

#[test]
fn configured_audit_log_appends_redacted_versioned_events() {
    let audit = temporary_path("audit.jsonl");
    let audit_arg = audit.to_str().unwrap();
    let secret_command = "cat web/sites/default/settings.php";
    for _ in 0..2 {
        let output = run(
            &["check", "--audit-log", audit_arg],
            &shell_request(secret_command),
        );
        assert!(output.status.success());
    }

    let contents = fs::read_to_string(&audit).unwrap();
    let lines = contents.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    let event: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(event["schema"], 1);
    assert_eq!(event["decision"], "deny");
    assert_eq!(event["rule_id"], "drupal.secret.settings_php");
    assert!(event["timestamp_unix_ms"].as_u64().is_some());
    assert!(!contents.contains(secret_command));
    assert!(!contents.contains("settings.php"));
    assert!(!contents.contains("tool_input"));
    fs::remove_file(audit).unwrap();
}

#[test]
fn audit_failure_cannot_emit_an_allow_and_native_adapter_fails_closed() {
    let directory = env!("CARGO_MANIFEST_DIR");
    let canonical = run(
        &["check", "--audit-log", directory],
        &request("file_read", "README.md"),
    );
    assert_eq!(canonical.status.code(), Some(4));
    assert_eq!(canonical.stdout, Vec::<u8>::new());

    let native = run_codex(
        &codex_request("read_file", &json!({"path": "README.md"})),
        &["--audit-log", directory],
    );
    assert!(native.status.success());
    let response: Value = serde_json::from_slice(&native.stdout).unwrap();
    assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn doctor_reports_installation_policy_hash_and_integrations() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let policy = format!("{manifest}/policy/default-policy.json");
    let codex = format!("{manifest}/config/codex/hooks.json");
    let cursor = format!("{manifest}/config/cursor/hooks.json");
    let output = run(
        &[
            "doctor",
            "--policy",
            &policy,
            "--codex-hooks",
            &codex,
            "--cursor-hooks",
            &cursor,
        ],
        b"",
    );
    assert!(output.status.success());
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("daguard 0.0.0"));
    assert!(report.contains("policy SHA-256:"));
    assert!(report.contains("organization policy schema is valid"));
    assert!(report.contains("Codex hook valid"));
    assert!(report.contains("Cursor hook valid"));
    assert!(report.contains("OpenCode integration is planned for Phase 6"));

    let invalid = format!("{manifest}/tests/fixtures/invalid-policy.json");
    let failed = run(&["doctor", "--policy", &invalid], b"");
    assert_eq!(failed.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&failed.stdout).contains("[ERROR]"));
}

#[test]
fn check_reads_request_files_and_policy_lint_validates_defaults() {
    let manifest = env!("CARGO_MANIFEST_DIR");
    let request = format!("{manifest}/tests/fixtures/requests/safe-custom-write.json");
    let output = run(&["check", &request], b"");
    assert!(output.status.success());
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "allow");

    let default_policy = format!("{manifest}/policy/default-policy.json");
    let lint = run(&["policy", "lint", &default_policy], b"");
    assert!(lint.status.success());
    assert_eq!(lint.stdout, b"policy is valid\n");
}

#[test]
fn codex_adapter_enforces_protected_and_safe_file_operations() {
    let cases = [
        (
            "read_file",
            json!({"path": "web/sites/default/settings.php"}),
            "deny",
        ),
        ("read_file", json!({"path": ".env"}), "deny"),
        (
            "read_file",
            json!({"path": "web/modules/custom/example/example.module"}),
            "allow",
        ),
        (
            "write_file",
            json!({"path": "web/modules/custom/example/example.module", "content": "synthetic"}),
            "allow",
        ),
        (
            "apply_patch",
            json!({"command": "*** Begin Patch\n*** Update File: web/core/lib/Drupal.php\n@@\n-old\n+new\n*** End Patch"}),
            "deny",
        ),
    ];
    for (tool, input, expected) in cases {
        let output = run_codex(&codex_request(tool, &input), &[]);
        assert!(
            output.status.success(),
            "Codex adapter failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            response["hookSpecificOutput"]["permissionDecision"], expected,
            "tool {tool}"
        );
    }
}

#[test]
fn cursor_adapter_enforces_protected_and_safe_operations() {
    let cases = [
        (
            "Read",
            json!({"file_path": "web/sites/default/settings.php"}),
            "deny",
        ),
        ("Read", json!({"file_path": ".env"}), "deny"),
        (
            "Read",
            json!({"file_path": "web/modules/custom/example/example.module"}),
            "allow",
        ),
        (
            "Write",
            json!({"file_path": "web/modules/custom/example/example.module", "contents": "synthetic"}),
            "allow",
        ),
        (
            "Write",
            json!({"file_path": "web/core/lib/Drupal.php", "contents": "synthetic"}),
            "deny",
        ),
        (
            "Shell",
            json!({"command": "ddev drush ev 'print(1)'"}),
            "deny",
        ),
        (
            "Shell",
            json!({"command": "ddev mysql -e 'DELETE FROM node'"}),
            "deny",
        ),
    ];
    for (tool, input, expected) in cases {
        let output = run_cursor(&cursor_request(tool, &input), &[]);
        assert!(
            output.status.success(),
            "Cursor adapter failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response["permission"], expected, "tool {tool}");
    }
}

#[test]
fn cursor_adapter_errors_emit_a_native_deny_response() {
    let malformed = run_cursor(br#"{"tool_name":"Read""#, &[]);
    assert!(malformed.status.success());
    let response: Value = serde_json::from_slice(&malformed.stdout).unwrap();
    assert_eq!(response["permission"], "deny");
    assert!(response["user_message"].as_str().is_some());
}

#[test]
fn codex_adapter_applies_the_shipped_organization_policy() {
    let policy = format!("{}/policy/default-policy.json", env!("CARGO_MANIFEST_DIR"));
    let output = run_codex(
        &codex_request("read_file", &json!({"path": "env/local/settings.json"})),
        &["--policy", &policy],
    );
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
}

#[test]
fn codex_adapter_errors_emit_only_a_supported_deny_response() {
    let malformed = run_codex(br#"{"tool_name":"read_file""#, &[]);
    assert!(malformed.status.success());
    let malformed_response: Value = serde_json::from_slice(&malformed.stdout).unwrap();
    assert_eq!(
        malformed_response["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );

    let invalid_policy = format!(
        "{}/tests/fixtures/invalid-policy.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let failed = run_codex(
        &codex_request("read_file", &json!({"path": "README.md"})),
        &["--policy", &invalid_policy],
    );
    assert!(failed.status.success());
    let failed_response: Value = serde_json::from_slice(&failed.stdout).unwrap();
    assert_eq!(
        failed_response["hookSpecificOutput"]["permissionDecision"],
        "deny"
    );
    assert_ne!(
        failed_response["hookSpecificOutput"]["permissionDecision"],
        "allow"
    );
}

#[test]
fn codex_doctor_accepts_the_shipped_hook_template() {
    let hooks = format!("{}/config/codex/hooks.json", env!("CARGO_MANIFEST_DIR"));
    let output = run(&["doctor", "codex", &hooks], b"");
    assert!(
        output.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn normal_drupal_commands_remain_allowed() {
    for command in [
        "ddev start",
        "ddev describe",
        "drush cr",
        "drush status",
        "drush pm:list",
        "drush config:status",
        "ddev drush cr",
        "composer validate",
        "composer audit",
        "ddev composer validate",
        "git status",
        "git diff --find-renames",
        "git log -n 2",
        "drush sql:query 'SELECT title FROM node_field_data'",
    ] {
        assert_eq!(shell_decision(command)["decision"], "allow", "{command}");
    }
}

#[test]
fn dangerous_drush_and_sql_are_denied_directly_and_through_ddev() {
    let cases = [
        ("drush php:eval 'print 1'", "shell.drush.eval"),
        ("drush ev 'print 1'", "shell.drush.eval"),
        ("ddev drush php-eval 'print 1'", "shell.drush.eval"),
        ("ddev drush sql:dump", "shell.drush.sql_dump"),
        ("ddev drush sql:cli", "shell.drush.sql_cli"),
        ("ddev exec drush ev 'print 1'", "shell.drush.eval"),
        ("ddev exec \"drush ev 'print 1'\"", "shell.drush.eval"),
        ("drush sql:dump", "shell.drush.sql_dump"),
        ("drush sql:cli", "shell.drush.sql_cli"),
        ("drush sql:query 'DELETE FROM node'", "sql.mutation.delete"),
        (
            "ddev drush sql:query 'uPdAtE node SET title = 1'",
            "sql.mutation.update",
        ),
        ("mysql -e 'DROP TABLE node'", "sql.mutation.drop"),
        (
            "ddev mysql 'CREATE TABLE unsafe (id INT)'",
            "sql.mutation.create",
        ),
        (
            "drush sql:query 'SELECT * FROM site_users_field_data'",
            "sql.read.sensitive_table",
        ),
    ];
    for (command, rule) in cases {
        let decision = shell_decision(command);
        assert_eq!(decision["decision"], "deny", "{command}");
        assert_eq!(decision["rule_id"], rule, "{command}");
    }
}

#[test]
fn chaining_nested_shells_force_push_and_shell_escapes_are_denied() {
    let cases = [
        "git status && drush ev 'print 1'",
        "drush ev 'print 1' || git status",
        "git status | drush php:eval 'print 1'",
        "bash -c \"git status; git push --force origin main\"",
        "git -C repo push origin main -f",
        "ddev ssh",
        "ddev --yes drush ev 'print 1'",
        "ddev import-db --file snapshot.sql.gz",
        "sudo git status",
        "/usr/bin/sudo git status",
        "env SITE=local drush ev 'print 1'",
        "/usr/bin/git push origin main --force",
        "drush --uri=example.test ev 'print 1'",
        "php -r 'print 1'",
    ];
    for command in cases {
        assert_eq!(shell_decision(command)["decision"], "deny", "{command}");
    }
}

#[test]
fn protected_paths_are_enforced_for_shell_reads_writes_and_traversal() {
    let cases = [
        (
            "cat web/sites/default/settings.php",
            "drupal.secret.settings_php",
        ),
        (
            "cat web/modules/custom/example/../../../sites/default/settings.php",
            "drupal.secret.settings_php",
        ),
        (
            "echo changed > web/core/lib/Drupal.php",
            "filesystem.write.core",
        ),
        (
            "touch vendor/example/package/file.php",
            "filesystem.write.vendor",
        ),
        (
            "cp patch.php web/modules/contrib/example/example.module",
            "filesystem.write.contrib_module",
        ),
        ("grep password .env", "drupal.secret.env"),
        ("cp .env /tmp/example", "drupal.secret.env"),
    ];
    for (command, rule) in cases {
        let decision = shell_decision(command);
        assert_eq!(decision["decision"], "deny", "{command}");
        assert_eq!(decision["rule_id"], rule, "{command}");
    }
    assert_eq!(
        shell_decision("touch web/modules/custom/example/new.php")["decision"],
        "allow"
    );
}

#[test]
fn ambiguous_shell_syntax_fails_closed() {
    for command in [
        "echo $(git status)",
        "echo 'unterminated",
        "cat < input.txt",
    ] {
        let decision = shell_decision(command);
        assert_eq!(decision["decision"], "deny", "{command}");
        assert_eq!(decision["rule_id"], "shell.ambiguous", "{command}");
    }
}

#[test]
fn state_changing_development_commands_require_approval() {
    for command in [
        "composer require drupal/example",
        "composer update --no-scripts",
        "composer run-script post-install-cmd",
        "ddev composer exec tool",
        "drush config:import",
        "ddev drush updatedb",
        "git commit -m synthetic",
        "git push origin main",
    ] {
        assert_eq!(shell_decision(command)["decision"], "ask", "{command}");
    }
}

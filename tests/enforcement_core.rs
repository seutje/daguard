use std::io::Write;
use std::process::{Command, Output, Stdio};

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

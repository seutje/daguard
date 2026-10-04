use std::io::Write;
use std::process::{Command, Output, Stdio};
use std::{fs, path::PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};

#[test]
fn codex_safe_calls_return_empty_output_without_an_unsupported_allow_decision() {
    let output = run_codex(
        &codex_request("Bash", &json!({"command":"git status"})),
        &[],
    );
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response, json!({}));
}

#[test]
fn environment_settings_reads_are_denied_directly_and_through_shells() {
    for command in [
        "cat env/settings.local.php",
        "head ./env/dev/settings.php",
        "cat web/../env/settings.local.php",
        "bash -c 'cat env/settings.local.php'",
        "ddev exec cat env/settings.local.php",
        "rg -n -i -C 3 'synthetic_pattern' env/settings.local.php env 2>/dev/null",
    ] {
        let decision = shell_decision(command);
        assert_eq!(decision["decision"], "deny", "{command}");
        assert_eq!(decision["rule_id"], "drupal.secret.settings_php");
    }
    for path in ["env/settings.local.php", "env/dev/settings.php"] {
        let output = run(&["check"], &request("file_read", path));
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "deny", "{path}");
    }
    for command in [
        "cat environment/settings.local.php",
        "cat env/README.md",
        "cat web/modules/custom/example/settings.local.php",
    ] {
        assert_eq!(shell_decision(command)["decision"], "allow", "{command}");
    }
}

#[test]
fn windows_paths_enforce_case_insensitive_protection_in_core_and_adapters() {
    let cases = [
        (
            r"C:\Users\Developer\Sites\drupal",
            r"WEB\SITES\DEFAULT\SETTINGS.PHP",
        ),
        (
            r"\\server\share\projects\drupal",
            r"web\sites\default\settings.php",
        ),
        (
            r"\\wsl.localhost\Ubuntu\home\developer\drupal",
            r"web\sites\default\settings.php",
        ),
    ];
    for (cwd, path) in cases {
        let input = serde_json::to_vec(&json!({
            "protocol": 1,
            "agent": "synthetic-test-agent",
            "event": "pre_tool_use",
            "cwd": cwd,
            "tool": {"native_name": "synthetic", "capability": "file_read"},
            "input": {"synthetic": true},
            "facts": {"paths": [path]}
        }))
        .unwrap();
        let output = run(&["check"], &input);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "deny", "{cwd}: {path}");
        assert_eq!(decision["rule_id"], "drupal.secret.settings_php");

        let adapter_inputs = [
            (
                "codex",
                json!({
                    "session_id": "windows-synthetic", "cwd": cwd,
                    "hook_event_name": "PreToolUse", "tool_name": "Read",
                    "tool_use_id": "windows-call", "tool_input": {"path": path}
                }),
            ),
            (
                "cursor",
                json!({
                    "tool_name": "Read", "tool_input": {"path": path},
                    "tool_use_id": "windows-call", "cwd": cwd
                }),
            ),
            (
                "opencode",
                json!({
                    "schema": 1, "session_id": "windows-synthetic",
                    "call_id": "windows-call", "cwd": cwd,
                    "tool_name": "read", "tool_input": {"filePath": path}
                }),
            ),
        ];
        for (adapter, input) in adapter_inputs {
            let output = run(
                &["--adapter", adapter, "--event", "pre-tool"],
                &serde_json::to_vec(&input).unwrap(),
            );
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            let effect = match adapter {
                "codex" => &response["hookSpecificOutput"]["permissionDecision"],
                "cursor" => &response["permission"],
                _ => &response["decision"],
            };
            assert_eq!(effect, "deny", "{adapter}: {cwd}: {path}");
        }
    }
}

#[test]
fn organization_directory_read_policy_applies_to_recursive_shell_searches() {
    let policy = format!("{}/policy/default-policy.json", env!("CARGO_MANIFEST_DIR"));
    let output = run(
        &["check", "--policy", &policy],
        &request("file_read", "env"),
    );
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "deny");
    assert_eq!(decision["rule_id"], "organization.path.deny_read");

    for command in [
        "rg synthetic_pattern env",
        "ddev exec rg synthetic_pattern env",
    ] {
        let output = run(&["check", "--policy", &policy], &shell_request(command));
        assert!(output.status.success(), "{command}");
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "deny", "{command}");
        assert_eq!(
            decision["rule_id"], "organization.path.deny_read",
            "{command}"
        );
    }

    for command in [
        "rg synthetic_pattern web/modules/custom",
        "rg env web/modules/custom",
    ] {
        let output = run(&["check", "--policy", &policy], &shell_request(command));
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "allow", "{command}");
    }
}

#[derive(Deserialize)]
struct Fixture {
    capability: String,
    path: String,
    decision: String,
    rule_id: String,
}

#[derive(Deserialize)]
struct AdapterParityFixture {
    name: String,
    codex_tool: String,
    cursor_tool: String,
    opencode_tool: String,
    codex_input: Value,
    cursor_input: Value,
    opencode_input: Value,
    decision: String,
    rule_id: Option<String>,
}

fn run(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_daguard"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Err(error) = child.stdin.take().unwrap().write_all(stdin) {
        // CLI/configuration errors can exit before reading stdin. Collect the
        // output so callers still assert the expected exit code and response.
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
    }
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

fn installed_opencode_config(name: &str) -> (PathBuf, PathBuf) {
    let plugin = temporary_path(&format!("{name}-plugin"));
    fs::create_dir_all(&plugin).unwrap();
    fs::write(plugin.join("index.js"), "export default {}\n").unwrap();
    let config = temporary_path(&format!("{name}-config.json"));
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "plugins": [{
                "package": plugin,
                "options": {
                    "guard": "/usr/local/bin/daguard",
                    "policy": "/etc/daguard/policy.json"
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    (config, plugin)
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

fn opencode_request(tool_name: &str, tool_input: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": 1,
        "session_id": "ses_synthetic",
        "call_id": "call_synthetic",
        "cwd": "/workspace/project",
        "tool_name": tool_name,
        "tool_input": tool_input
    }))
    .unwrap()
}

fn run_opencode(input: &[u8], extra_args: &[&str]) -> Output {
    let mut args = vec!["--adapter", "opencode", "--event", "pre-tool"];
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
fn invalid_policy_exit_is_collected_when_stdin_exceeds_pipe_capacity() {
    let policy = format!(
        "{}/tests/fixtures/invalid-policy.json",
        env!("CARGO_MANIFEST_DIR")
    );
    // Exceed Linux pipe capacity so the write cannot finish before the guard
    // rejects policy without reading stdin, regardless of process scheduling.
    let input = vec![b' '; 2 * 1024 * 1024];
    let output = run(&["check", "--policy", &policy], &input);
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
    let version = String::from_utf8_lossy(&version.stdout);
    assert!(version.starts_with("daguard "));
    assert!(version.contains("profile:"));
    assert!(version.contains("rustc:"));
    assert!(version.contains("git:"));
    assert!(version.contains("Cargo.lock SHA-256:"));
    assert!(version.contains("provenance:"));

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
    assert_eq!(event["schema"], 3);
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
    let (opencode, opencode_plugin) = installed_opencode_config("doctor-report");
    let output = run(
        &[
            "doctor",
            "--policy",
            &policy,
            "--codex-hooks",
            &codex,
            "--cursor-hooks",
            &cursor,
            "--opencode-config",
            opencode.to_str().unwrap(),
        ],
        b"",
    );
    assert!(output.status.success());
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains(&format!("daguard {}", env!("CARGO_PKG_VERSION"))));
    assert!(report.contains("policy SHA-256:"));
    assert!(report.contains("organization policy schema is valid"));
    assert!(report.contains("Codex hook valid"));
    assert!(report.contains("Cursor hook valid"));
    assert!(report.contains("OpenCode hook valid"));

    fs::remove_file(opencode).unwrap();
    fs::remove_dir_all(opencode_plugin).unwrap();

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
        if expected == "allow" {
            assert_eq!(response, json!({}), "tool {tool}");
        } else {
            assert_eq!(
                response["hookSpecificOutput"]["permissionDecision"], expected,
                "tool {tool}"
            );
        }
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
fn opencode_adapter_errors_emit_a_native_deny_response() {
    let malformed = run_opencode(br#"{"tool_name":"read""#, &[]);
    assert!(malformed.status.success());
    let response: Value = serde_json::from_slice(&malformed.stdout).unwrap();
    assert_eq!(response["decision"], "deny");
    assert_eq!(response["rule_id"], "guard.evaluation_error");
}

#[test]
fn all_adapters_enforce_the_shared_scenario_matrix() {
    assert_adapter_matrix(&[]);
}

#[test]
fn pilot_keeps_the_shared_three_adapter_security_matrix() {
    let audit = temporary_path("pilot-adapter-matrix.jsonl");
    assert_adapter_matrix(&[
        "--policy",
        PILOT_POLICY,
        "--audit-log",
        audit.to_str().unwrap(),
    ]);
    fs::remove_file(audit).unwrap();
}

fn assert_adapter_matrix(extra_args: &[&str]) {
    let fixtures: Vec<AdapterParityFixture> =
        serde_json::from_str(include_str!("fixtures/adapter_parity.json")).unwrap();
    for fixture in fixtures {
        let codex = run_codex(
            &codex_request(&fixture.codex_tool, &fixture.codex_input),
            extra_args,
        );
        let cursor = run_cursor(
            &cursor_request(&fixture.cursor_tool, &fixture.cursor_input),
            extra_args,
        );
        let opencode = run_opencode(
            &opencode_request(&fixture.opencode_tool, &fixture.opencode_input),
            extra_args,
        );
        for (adapter, output) in [("codex", codex), ("cursor", cursor), ("opencode", opencode)] {
            assert!(
                output.status.success(),
                "{} failed for {}: {}",
                adapter,
                fixture.name,
                String::from_utf8_lossy(&output.stderr)
            );
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            let (decision, rule_id) = match adapter {
                "codex" => (
                    if response == json!({}) {
                        Some("allow")
                    } else {
                        response["hookSpecificOutput"]["permissionDecision"].as_str()
                    },
                    response["hookSpecificOutput"]["permissionDecisionReason"]
                        .as_str()
                        .and_then(|value| value.rsplit_once(' ').map(|(_, rule)| rule)),
                ),
                "cursor" => (
                    response["permission"].as_str(),
                    response["user_message"]
                        .as_str()
                        .and_then(|value| value.rsplit_once(' ').map(|(_, rule)| rule)),
                ),
                "opencode" => (response["decision"].as_str(), response["rule_id"].as_str()),
                _ => unreachable!(),
            };
            assert_eq!(
                decision,
                Some(fixture.decision.as_str()),
                "{} / {}",
                fixture.name,
                adapter
            );
            assert_eq!(
                rule_id,
                fixture.rule_id.as_deref(),
                "{} / {}",
                fixture.name,
                adapter
            );
        }
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

#[test]
fn opencode_doctor_requires_the_v2_local_directory_entrypoint() {
    let (config, plugin) = installed_opencode_config("doctor-opencode");
    let output = run(&["doctor", "opencode", config.to_str().unwrap()], b"");
    assert!(
        output.status.success(),
        "doctor failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    fs::remove_file(plugin.join("index.js")).unwrap();
    fs::write(plugin.join("daguard-plugin.js"), "export default {}\n").unwrap();
    let missing = run(&["doctor", "opencode", config.to_str().unwrap()], b"");
    assert_eq!(missing.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("required index.js entrypoint"));

    fs::remove_file(config).unwrap();
    fs::remove_dir_all(plugin).unwrap();
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
fn default_policy_protects_configured_sensitive_sql_tables_and_globs() {
    let policy: Value =
        serde_json::from_slice(include_bytes!("../policy/default-policy.json")).unwrap();
    let configured = policy["sql"]["sensitive_tables"].as_array().unwrap();
    let expected = [
        "users",
        "users_field_data",
        "users_data",
        "user__*",
        "sessions",
        "key_value",
        "key_value_expire",
        "flood",
        "comment",
        "comment_field_data",
        "comment__*",
        "webform_submission",
        "webform_submission_data",
        "webform_submission_log",
        "commerce_order",
        "commerce_order__*",
        "commerce_order_item",
        "commerce_order_item__*",
        "commerce_payment",
        "commerce_payment__*",
        "commerce_payment_method",
        "commerce_payment_method__*",
        "profile",
        "profile_field_data",
        "profile_revision",
        "profile_field_revision",
        "profile__*",
        "profile_revision__*",
        "commerce_shipment",
        "commerce_shipment__*",
    ];
    assert_eq!(
        configured,
        &expected.map(Value::from),
        "the shipped sensitive-table policy must remain explicit and reviewable"
    );

    let policy_path = format!("{}/policy/default-policy.json", env!("CARGO_MANIFEST_DIR"));
    for table in [
        "users_data",
        "user__roles",
        "flood",
        "comment__body",
        "webform_submission_log",
        "commerce_order__billing_profile",
        "commerce_order_item__field_data",
        "commerce_payment__remote_id",
        "commerce_payment_method__card",
        "profile_field_revision",
        "profile__address",
        "profile_revision__address",
        "commerce_shipment__items",
        "site_commerce_shipment__items",
    ] {
        let command = format!("drush sql:query 'SELECT * FROM {table}'");
        let output = run(
            &["check", "--policy", &policy_path],
            &shell_request(&command),
        );
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "deny", "{table}");
        assert_eq!(decision["rule_id"], "sql.read.sensitive_table", "{table}");
    }

    for table in ["user_account", "commentary", "commerce_order_archive"] {
        let command = format!("drush sql:query 'SELECT * FROM {table}'");
        let output = run(
            &["check", "--policy", &policy_path],
            &shell_request(&command),
        );
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "allow", "{table}");
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

const PILOT_POLICY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/pilot/organization.json"
);

#[test]
fn pilot_candidates_are_observed_while_overlapping_mandatory_rules_still_deny() {
    let audit = temporary_path("pilot-overlap.jsonl");
    let args = [
        "check",
        "--policy",
        PILOT_POLICY,
        "--audit-log",
        audit.to_str().unwrap(),
    ];
    for path in [
        "web/modules/custom/pilot/example.module",
        "web/modules/custom/other/../pilot/example.module",
    ] {
        let output = run(&args, &request("file_write", path));
        assert!(output.status.success());
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "allow");
        assert!(String::from_utf8_lossy(&output.stderr).contains("audit-only"));
    }
    let output = run(
        &args,
        &request(
            "file_write",
            "web/modules/custom/pilot/private/example.module",
        ),
    );
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "deny");
    assert_eq!(decision["rule_id"], "organization.mandatory.private_write");
    let output = run(
        &args,
        &request("file_write", "web/modules/custom/other/example.module"),
    );
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "allow");
    let contents = fs::read_to_string(&audit).unwrap();
    let events: Vec<Value> = contents
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(events.len(), 4);
    for event in &events[..3] {
        assert_eq!(event["schema"], 3);
        assert_eq!(event["mode"], "audit_only");
        assert_eq!(event["decision"], "deny");
        assert_eq!(event["rule_id"], "pilot.candidate.custom_write");
    }
    assert_eq!(events[0]["enforcement_decision"], "allow");
    assert_eq!(events[2]["enforcement_decision"], "deny");
    assert_eq!(
        events[2]["enforcement_rule_id"],
        "organization.mandatory.private_write"
    );
    assert_eq!(events[3]["decision"], "allow");
    for forbidden in [
        "example.module",
        "Synthetic candidate",
        "/workspace/project",
        "tool_input",
    ] {
        assert!(!contents.contains(forbidden));
    }
    fs::remove_file(audit).unwrap();
}

#[test]
fn pilot_native_responses_match_all_adapter_goldens() {
    for (adapter, tool, payload, golden) in [
        (
            "codex",
            "write_file",
            codex_request(
                "write_file",
                &json!({"path":"web/modules/custom/pilot/example.module", "content":"synthetic-secret-content"}),
            ),
            include_bytes!("fixtures/codex/responses/allow.json").as_slice(),
        ),
        (
            "cursor",
            "Write",
            cursor_request(
                "Write",
                &json!({"file_path":"web/modules/custom/pilot/example.module", "contents":"synthetic-secret-content"}),
            ),
            include_bytes!("fixtures/cursor/responses/allow.json").as_slice(),
        ),
        (
            "opencode",
            "write",
            opencode_request(
                "write",
                &json!({"filePath":"web/modules/custom/pilot/example.module", "content":"synthetic-secret-content"}),
            ),
            include_bytes!("fixtures/opencode/responses/allow.json").as_slice(),
        ),
    ] {
        let audit = temporary_path(adapter);
        let args = [
            "--adapter",
            adapter,
            "--event",
            "pre-tool",
            "--policy",
            PILOT_POLICY,
            "--audit-log",
            audit.to_str().unwrap(),
        ];
        let output = run(&args, &payload);
        assert!(output.status.success(), "{adapter}/{tool}");
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            serde_json::from_slice::<Value>(golden).unwrap(),
            "{adapter}/{tool}"
        );
        let contents = fs::read_to_string(&audit).unwrap();
        let event: Value = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(
            event["rule_id"], "pilot.candidate.custom_write",
            "{adapter}/{tool}"
        );
        assert_eq!(event["enforcement_decision"], "allow");
        assert!(!contents.contains("synthetic-secret-content"));
        fs::remove_file(audit).unwrap();
    }
}

#[test]
fn pilot_preserves_protected_path_matrix_and_command_security() {
    let audit = temporary_path("pilot-protections.jsonl");
    let args = [
        "check",
        "--policy",
        PILOT_POLICY,
        "--audit-log",
        audit.to_str().unwrap(),
    ];
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/protected_paths.json")).unwrap();
    for fixture in fixtures {
        let output = run(&args, &request(&fixture.capability, &fixture.path));
        assert!(output.status.success());
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], fixture.decision);
        assert_eq!(decision["rule_id"], fixture.rule_id);
    }
    for command in [
        "sudo id",
        "drush ev 'synthetic'",
        "ddev drush php:eval 'synthetic'",
        "git push -f",
        "ddev exec git push --force",
        "drush sql:query 'DELETE FROM synthetic_table'",
        "ddev drush sql:query 'SELECT * FROM synthetic_private_records'",
        "bash -c 'git status; git push --force'",
        "echo $(synthetic)",
    ] {
        let output = run(&args, &shell_request(command));
        assert!(output.status.success());
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "deny", "{command}");
    }
    for command in [
        "ddev start",
        "ddev describe",
        "ddev drush cr",
        "ddev drush status",
        "ddev composer validate",
        "ddev composer audit",
        "git status",
        "git diff",
    ] {
        let output = run(&args, &shell_request(command));
        let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(decision["decision"], "allow", "{command}");
    }
    let output = run(&args, &request("unknown", "README.md"));
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "deny");
    fs::remove_file(audit).unwrap();
}

#[test]
fn pilot_cannot_be_enabled_by_project_or_misspelled_policy() {
    let invalid = temporary_path("invalid-pilot-policy.json");
    for value in [
        json!({"schema":1,"audit_only_rules":[]}),
        json!({"schema":1,"audit_only_rules":null}),
        json!({"schema":2,"audit_only_rules":null}),
        json!({"schema":2,"audit_only_rules":"all"}),
        json!({"schema":2,"audit_only_rules":["missing.rule"]}),
        json!({"schema":2,"audit_only_rules":["drupal.secret.env"]}),
        json!({"schema":2,"audit_only_rule":[]}),
        json!({"schema":3}),
    ] {
        fs::write(&invalid, serde_json::to_vec(&value).unwrap()).unwrap();
        let output = run(
            &["check", "--policy", invalid.to_str().unwrap()],
            &request("file_read", "README.md"),
        );
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, Vec::<u8>::new());
    }
    for value in [
        json!({"schema":2,"audit_only_rules":[]}),
        serde_json::from_slice(include_bytes!("fixtures/pilot/organization.json")).unwrap(),
    ] {
        fs::write(&invalid, serde_json::to_vec(&value).unwrap()).unwrap();
        let output = run(
            &[
                "check",
                "--policy",
                "policy/default-policy.json",
                "--project-policy",
                invalid.to_str().unwrap(),
            ],
            &request("file_read", "README.md"),
        );
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, Vec::<u8>::new());
    }
    fs::remove_file(invalid).unwrap();
}

#[test]
fn pilot_telemetry_errors_and_malformed_input_fail_closed_for_all_adapters() {
    for (adapter, payload, decision_key) in [
        (
            "codex",
            codex_request("read_file", &json!({"path":"README.md"})),
            "/hookSpecificOutput/permissionDecision",
        ),
        (
            "cursor",
            cursor_request("read_file", &json!({"path":"README.md"})),
            "/permission",
        ),
        (
            "opencode",
            opencode_request("read", &json!({"filePath":"README.md"})),
            "/decision",
        ),
    ] {
        let base = [
            "--adapter",
            adapter,
            "--event",
            "pre-tool",
            "--policy",
            PILOT_POLICY,
        ];
        let output = run(&base, &payload);
        let response: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(response.pointer(decision_key).unwrap(), "deny");
        let mut args = base.to_vec();
        args.extend(["--audit-log", env!("CARGO_MANIFEST_DIR")]);
        for input in [payload.as_slice(), b"{".as_slice()] {
            let output = run(&args, input);
            let response: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(response.pointer(decision_key).unwrap(), "deny");
        }
    }
    let output = run(
        &["check", "--policy", PILOT_POLICY],
        &request("file_read", "README.md"),
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, Vec::<u8>::new());
}

#[test]
fn ending_pilot_restores_candidate_enforcement_and_reports_mode() {
    let policy = temporary_path("pilot-ended.json");
    let mut value: Value =
        serde_json::from_slice(include_bytes!("fixtures/pilot/organization.json")).unwrap();
    value.as_object_mut().unwrap().remove("audit_only_rules");
    fs::write(&policy, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = run(
        &["check", "--policy", policy.to_str().unwrap()],
        &request("file_write", "web/modules/custom/pilot/example.module"),
    );
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "deny");
    assert_eq!(decision["rule_id"], "pilot.candidate.custom_write");
    let output = run(&["doctor", "--policy", policy.to_str().unwrap()], b"");
    assert!(String::from_utf8_lossy(&output.stdout).contains("mode: enforcement"));
    let output = run(&["doctor", "--policy", PILOT_POLICY], b"");
    assert!(String::from_utf8_lossy(&output.stdout).contains("mode: audit-only"));
    fs::remove_file(policy).unwrap();
}

#[test]
fn pilot_candidate_ask_does_not_weaken_project_or_path_protection() {
    let organization = temporary_path("pilot-ask.json");
    let project = temporary_path("pilot-project.json");
    let audit = temporary_path("pilot-ask-audit.jsonl");
    let mut value: Value =
        serde_json::from_slice(include_bytes!("fixtures/pilot/organization.json")).unwrap();
    value["rules"][0]["effect"] = json!("ask");
    fs::write(&organization, serde_json::to_vec(&value).unwrap()).unwrap();
    fs::write(
        &project,
        br#"{"schema":1,"paths":{"deny_write":["**/web/modules/custom/pilot/**"]}}"#,
    )
    .unwrap();
    let path_request = request("file_write", "web/modules/custom/pilot/example.module");
    let base = [
        "check",
        "--policy",
        organization.to_str().unwrap(),
        "--audit-log",
        audit.to_str().unwrap(),
    ];
    let output = run(&base, &path_request);
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "allow");
    let event: Value = serde_json::from_str(fs::read_to_string(&audit).unwrap().trim()).unwrap();
    assert_eq!(event["decision"], "ask");
    assert_eq!(event["enforcement_decision"], "allow");
    let mut args = base.to_vec();
    args.extend(["--project-policy", project.to_str().unwrap()]);
    let output = run(&args, &path_request);
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "deny");
    assert_eq!(decision["rule_id"], "project.path.deny_write");
    value["paths"] = json!({"deny_write":["**/web/modules/custom/pilot/**"]});
    fs::write(&organization, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = run(&base, &path_request);
    let decision: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(decision["decision"], "deny");
    assert_eq!(decision["rule_id"], "organization.path.deny_write");
    for observed in [
        json!([
            "pilot.candidate.custom_write",
            "pilot.candidate.custom_write"
        ]),
        json!(["drupal.secret.env"]),
    ] {
        value["audit_only_rules"] = observed;
        fs::write(&organization, serde_json::to_vec(&value).unwrap()).unwrap();
        let output = run(&base, &path_request);
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(output.stdout, Vec::<u8>::new());
    }
    value["audit_only_rules"] = json!(["pilot.candidate.custom_write"]);
    value["rules"][0]["effect"] = json!("allow");
    fs::write(&organization, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = run(&base, &path_request);
    assert_eq!(output.status.code(), Some(3));
    for path in [organization, project, audit] {
        fs::remove_file(path).unwrap();
    }
}

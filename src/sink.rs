//! Deterministic outbound sink classification and taint enforcement.

use std::collections::BTreeSet;

use crate::analyzers::ddev;
use crate::model::{
    CanonicalRequest, Capability, Decision, DecisionEffect, Evidence, PROTOCOL_VERSION,
    PolicyLayer, SensitivityCategory, Severity, SinkCategory,
};
use crate::shell;
use crate::state::SessionTaint;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TaintSinkDecision {
    pub(crate) decision: Decision,
    pub(crate) categories: BTreeSet<SensitivityCategory>,
    pub(crate) sink: SinkCategory,
}

pub(crate) fn classify(request: &CanonicalRequest) -> Option<SinkCategory> {
    match request.tool.capability {
        Capability::NetworkWrite | Capability::NetworkRequest => {
            return Some(SinkCategory::OutboundNetwork);
        }
        Capability::McpCall => return Some(SinkCategory::OutboundMcp),
        Capability::NetworkRead if !request.facts.urls.is_empty() => {
            return Some(SinkCategory::OutboundHttp);
        }
        _ => {}
    }
    if matches!(request.tool.capability, Capability::Unknown) {
        let name = request.tool.native_name.to_ascii_lowercase();
        if name.contains("mcp") {
            return Some(SinkCategory::OutboundMcp);
        }
        if name.contains("upload") || name.contains("browser") {
            return Some(SinkCategory::BrowserUpload);
        }
        if name.contains("slack") || name.contains("email") || name.contains("message") {
            return Some(SinkCategory::Messaging);
        }
        if name.contains("issue")
            || name.contains("ticket")
            || name.contains("linear")
            || name.contains("github")
            || name.contains("gitlab")
        {
            return Some(SinkCategory::ApiSubmission);
        }
        if name.contains("http") || name.contains("fetch") || name.contains("request") {
            return Some(SinkCategory::OutboundHttp);
        }
    }
    request
        .candidate_commands()
        .into_iter()
        .find_map(|command| classify_shell(command, 0))
}

pub(crate) fn enforce(
    request: &CanonicalRequest,
    taint: &SessionTaint,
) -> Option<TaintSinkDecision> {
    if taint.categories.is_empty() {
        return None;
    }
    let sink = classify(request)?;
    let always_deny = taint.categories.iter().any(|category| {
        matches!(
            category,
            SensitivityCategory::Credential
                | SensitivityCategory::Authentication
                | SensitivityCategory::PersonalData
                | SensitivityCategory::FinancialData
                | SensitivityCategory::CustomerData
                | SensitivityCategory::PrivateContent
                | SensitivityCategory::UnknownSensitive
        )
    });
    let (effect, rule_id, severity, reason) = if always_deny {
        (
            DecisionEffect::Deny,
            "exfiltration.tainted_session",
            Severity::Critical,
            "Outbound transfer is prohibited after this session accessed sensitive resources.",
        )
    } else {
        (
            DecisionEffect::Ask,
            "exfiltration.tainted_session.review",
            Severity::High,
            "Outbound transfer requires approval after access to sensitive operational metadata.",
        )
    };
    Some(TaintSinkDecision {
        decision: Decision {
            protocol: PROTOCOL_VERSION,
            effect,
            rule_id: rule_id.to_owned(),
            severity,
            category: "exfiltration".to_owned(),
            reason: reason.to_owned(),
            policy_layer: PolicyLayer::BuiltIn,
            details: Evidence { matched_path: None },
        },
        categories: taint.categories.clone(),
        sink,
    })
}

fn classify_shell(command: &str, depth: usize) -> Option<SinkCategory> {
    if depth > 4 {
        return Some(SinkCategory::OutboundNetwork);
    }
    let tokens = shell::tokenize(command).ok()?;
    shell::segments(&tokens)
        .into_iter()
        .find_map(|segment| classify_argv(&shell::words(segment), depth))
}

fn classify_argv(words: &[&str], depth: usize) -> Option<SinkCategory> {
    let Ok(words) = shell::normalize_argv(words) else {
        return Some(SinkCategory::OutboundNetwork);
    };
    let (program, args) = words.split_first()?;
    let program = command_name(program);
    if matches!(program, "sh" | "bash") {
        let position = args
            .iter()
            .position(|arg| arg.starts_with('-') && !arg.starts_with("--") && arg.contains('c'))?;
        return args
            .get(position + 1)
            .and_then(|inner| classify_shell(inner, depth + 1));
    }
    if program == "ddev" {
        return match ddev::unwrap(args) {
            ddev::Target::Nested(inner, _) if inner.len() == 1 => {
                classify_shell(inner[0], depth + 1)
            }
            ddev::Target::Nested(inner, _) => classify_argv(inner, depth + 1),
            _ => None,
        };
    }
    match program {
        "curl" | "wget" | "http" | "https" | "httpie" | "xh" => Some(SinkCategory::OutboundHttp),
        "ssh" => Some(SinkCategory::RemoteShell),
        "scp" | "sftp" => Some(SinkCategory::RemoteFileTransfer),
        "rsync" if args.iter().any(|arg| is_remote_target(arg)) => {
            Some(SinkCategory::RemoteFileTransfer)
        }
        "git" if git_push(args) => Some(SinkCategory::GitRemoteWrite),
        "gh" | "aws" | "gcloud" | "az" => Some(SinkCategory::ApiSubmission),
        "nc" | "netcat" | "socat" => Some(SinkCategory::OutboundNetwork),
        "mail" | "mailx" | "sendmail" => Some(SinkCategory::Messaging),
        _ => None,
    }
}

fn git_push(args: &[&str]) -> bool {
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if matches!(
            *argument,
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace"
        ) {
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            return *argument == "push";
        }
    }
    false
}

fn is_remote_target(argument: &str) -> bool {
    argument.contains(':') || argument.starts_with("rsync://")
}

fn command_name(program: &str) -> &str {
    program.rsplit('/').next().unwrap_or(program)
}

#[cfg(test)]
mod tests {
    use super::classify;
    use crate::model::CanonicalRequest;

    fn request(command: &str) -> CanonicalRequest {
        let input = serde_json::json!({
            "protocol": 1,
            "agent": "fixture",
            "event": "pre_tool_use",
            "session_id": "synthetic",
            "cwd": "/workspace/project",
            "tool": {"native_name": "shell", "capability": "shell_execute"},
            "input": {},
            "facts": {"command": command}
        });
        CanonicalRequest::from_slice(&serde_json::to_vec(&input).unwrap()).unwrap()
    }

    #[test]
    fn wrappers_preserve_outbound_classification() {
        for command in [
            "timeout 5 curl https://example.test",
            "busybox wget https://example.test",
            "env -i nice -n 5 curl https://example.test",
        ] {
            assert_eq!(
                classify(&request(command)),
                Some(crate::model::SinkCategory::OutboundHttp)
            );
        }
    }

    #[test]
    fn distinguishes_local_work_from_wrapped_outbound_sinks() {
        use crate::model::SinkCategory;
        assert_eq!(classify(&request("git status")), None);
        assert_eq!(classify(&request("ddev drush cr")), None);
        assert_eq!(
            classify(&request("ddev exec bash -c 'curl https://example.test'")),
            Some(SinkCategory::OutboundHttp)
        );
        assert_eq!(
            classify(&request("git -C repo push origin main")),
            Some(SinkCategory::GitRemoteWrite)
        );
        assert_eq!(
            classify(&request("rsync README.md host:/tmp/")),
            Some(SinkCategory::RemoteFileTransfer)
        );
        assert_eq!(
            classify(&request("gh issue create --title synthetic")),
            Some(SinkCategory::ApiSubmission)
        );
    }
}

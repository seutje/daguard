//! Git operation analysis.

use crate::analyzers::decision;
use crate::model::{Decision, DecisionEffect, Severity};

pub(crate) fn analyze(args: &[&str]) -> Option<Decision> {
    let command = command(args)?;
    if command == "push"
        && args.iter().any(|arg| {
            matches!(
                *arg,
                "--force" | "--force-with-lease" | "--force-if-includes"
            ) || arg.starts_with("--force=")
                || arg.starts_with("--force-with-lease=")
                || (arg.starts_with('-') && !arg.starts_with("--") && arg[1..].contains('f'))
                || arg.starts_with('+')
        })
    {
        return Some(decision(
            DecisionEffect::Deny,
            "git.force_push",
            "git",
            "Force-pushing is prohibited.",
            Severity::High,
        ));
    }
    if command == "config"
        && args
            .iter()
            .any(|arg| arg.to_ascii_lowercase().contains("credential."))
    {
        return Some(decision(
            DecisionEffect::Deny,
            "git.credential_config",
            "git",
            "Changing Git credential configuration is prohibited.",
            Severity::High,
        ));
    }
    if matches!(command, "commit" | "push") {
        return Some(decision(
            DecisionEffect::Ask,
            "git.write.review",
            "git",
            "This Git operation requires approval.",
            Severity::Medium,
        ));
    }
    None
}

fn command<'a>(args: &'a [&'a str]) -> Option<&'a str> {
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
            return Some(argument);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::analyze;
    #[test]
    fn force_variants_deny_without_flag_substring_false_positives() {
        for arguments in [
            vec!["push", "--force-with-lease"],
            vec!["push", "--force-with-lease=refs/heads/main:synthetic"],
            vec!["push", "-vf", "origin", "main"],
            vec!["push", "origin", "+main:main"],
        ] {
            let decision = analyze(&arguments).unwrap();
            assert_eq!(decision.rule_id, "git.force_push");
            assert_eq!(decision.effect, crate::model::DecisionEffect::Deny);
        }
        assert_eq!(
            analyze(&["push", "origin", "main", "--force"])
                .unwrap()
                .rule_id,
            "git.force_push"
        );
        assert!(analyze(&["diff", "--find-renames"]).is_none());
        assert_eq!(
            analyze(&["-C", "repo", "push", "origin", "--force"])
                .unwrap()
                .rule_id,
            "git.force_push"
        );
    }
}

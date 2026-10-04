//! Composer operation analysis.

use crate::analyzers::decision;
use crate::model::{Decision, DecisionEffect, Severity};

pub(crate) fn analyze(args: &[&str]) -> Option<Decision> {
    let Ok(args) = super::argv::command(
        args,
        &[
            "--no-interaction",
            "-n",
            "--no-plugins",
            "--no-scripts",
            "--no-progress",
            "-q",
            "--quiet",
            "-v",
            "-vv",
            "-vvv",
            "--verbose",
            "--profile",
            "--ansi",
            "--no-ansi",
        ],
        &["--working-dir", "-d"],
    ) else {
        return Some(decision(
            DecisionEffect::Deny,
            "composer.ambiguous",
            "composer",
            "Composer options cannot be inspected safely.",
            Severity::High,
        ));
    };
    let command = *args.first()?;
    if matches!(command, "require" | "remove" | "update" | "install") {
        return Some(decision(
            DecisionEffect::Ask,
            "composer.dependencies.modify",
            "composer",
            "Dependency-changing Composer operations require approval.",
            Severity::Medium,
        ));
    }
    if matches!(command, "run-script" | "run" | "exec") {
        return Some(decision(
            DecisionEffect::Ask,
            "composer.scripts.execute",
            "composer",
            "Explicit Composer script execution requires approval.",
            Severity::High,
        ));
    }
    None
}

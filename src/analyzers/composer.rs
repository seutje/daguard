//! Composer operation analysis.

use crate::analyzers::decision;
use crate::model::{Decision, DecisionEffect, Severity};

pub(crate) fn analyze(args: &[&str]) -> Option<Decision> {
    let command = args.iter().copied().find(|arg| !arg.starts_with('-'))?;
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

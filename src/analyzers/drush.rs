//! Drush operation analysis.

use crate::analyzers::{decision, sql};
use crate::model::{Decision, DecisionEffect, Severity};

pub(crate) fn analyze(args: &[&str], sensitive_tables: &[&str]) -> Option<Decision> {
    if args
        .iter()
        .any(|argument| matches!(*argument, "php:eval" | "php-eval" | "ev"))
    {
        return Some(decision(
            DecisionEffect::Deny,
            "shell.drush.eval",
            "drush",
            "Arbitrary Drush PHP evaluation is prohibited.",
            Severity::Critical,
        ));
    }
    let position = args.iter().position(|arg| !arg.starts_with('-'))?;
    let command = args[position];
    match command {
        "php:eval" | "php-eval" | "ev" => Some(decision(
            DecisionEffect::Deny,
            "shell.drush.eval",
            "drush",
            "Arbitrary Drush PHP evaluation is prohibited.",
            Severity::Critical,
        )),
        "sql:dump" | "sql-dump" => Some(decision(
            DecisionEffect::Deny,
            "shell.drush.sql_dump",
            "drush",
            "Database dumps may expose sensitive data and are prohibited.",
            Severity::High,
        )),
        "sql:cli" | "sql-cli" => Some(decision(
            DecisionEffect::Deny,
            "shell.drush.sql_cli",
            "drush",
            "Interactive SQL cannot be inspected safely.",
            Severity::High,
        )),
        "config:import" | "config-import" | "cim" | "updatedb" | "updb" => Some(decision(
            DecisionEffect::Ask,
            "drush.mutation.review",
            "drush",
            "This state-changing Drush operation requires approval.",
            Severity::Medium,
        )),
        "sql:query" | "sql-query" | "sqlq" => args[position + 1..]
            .iter()
            .find(|argument| !argument.starts_with('-'))
            .and_then(|query| sql::analyze(query, sensitive_tables)),
        _ => None,
    }
}

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
    let Ok(args) = command_args(args) else {
        return Some(sql::uninspectable());
    };
    let (command, rest) = args.split_first()?;
    let command = *command;
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
        "sql:query" | "sql-query" | "sqlq" => match rest {
            [query] if !query.is_empty() && !query.starts_with('-') => {
                sql::analyze(query, sensitive_tables)
            }
            _ => Some(sql::uninspectable()),
        },
        _ => None,
    }
}

pub(crate) fn command_args<'a>(args: &'a [&'a str]) -> Result<&'a [&'a str], ()> {
    super::argv::command(
        args,
        &[
            "-y",
            "--yes",
            "-n",
            "--no",
            "-v",
            "--verbose",
            "-q",
            "--quiet",
            "--no-interaction",
            "--debug",
        ],
        &[
            "--root",
            "-r",
            "--uri",
            "-l",
            "--config",
            "-c",
            "--alias-path",
        ],
    )
}

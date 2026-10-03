//! DDEV wrapper analysis and normalization.

use crate::analyzers::decision;
use crate::model::{Decision, DecisionEffect, Severity};

pub(crate) enum Target<'a> {
    Safe,
    Nested(&'a [&'a str]),
    Drush(&'a [&'a str]),
    Composer(&'a [&'a str]),
    Sql(&'a str),
    Decision(Decision),
}

pub(crate) fn unwrap<'a>(args: &'a [&'a str]) -> Target<'a> {
    let args = skip_global_options(args);
    let Some((command, rest)) = args.split_first() else {
        return Target::Safe;
    };
    match *command {
        "drush" => Target::Drush(rest),
        "composer" => Target::Composer(rest),
        "exec" => Target::Nested(rest),
        "ssh" => Target::Decision(decision(
            DecisionEffect::Deny,
            "ddev.shell_escape",
            "ddev",
            "Unrestricted DDEV shell access cannot be inspected safely.",
            Severity::High,
        )),
        "import-db" | "export-db" => Target::Decision(decision(
            DecisionEffect::Deny,
            "ddev.database_transfer",
            "ddev",
            "Database import and export are prohibited for agents.",
            Severity::High,
        )),
        "mysql" if rest.is_empty() => Target::Decision(decision(
            DecisionEffect::Deny,
            "ddev.sql.interactive",
            "sql",
            "Interactive SQL cannot be inspected safely.",
            Severity::High,
        )),
        "mysql" => Target::Sql(rest.last().copied().unwrap_or_default()),
        _ => Target::Safe,
    }
}

fn skip_global_options<'a>(args: &'a [&'a str]) -> &'a [&'a str] {
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if matches!(
            *argument,
            "--project" | "--project-name" | "--project-type" | "--docroot"
        ) {
            index += 2;
        } else if argument.starts_with('-') {
            index += 1;
        } else {
            break;
        }
    }
    &args[index.min(args.len())..]
}

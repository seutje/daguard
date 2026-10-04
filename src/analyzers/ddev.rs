//! DDEV wrapper analysis and normalization.

use crate::analyzers::decision;
use crate::model::{Decision, DecisionEffect, Severity};

pub(crate) enum Target<'a> {
    Safe,
    Nested(&'a [&'a str], Option<&'a str>, bool),
    Drush(&'a [&'a str]),
    Composer(&'a [&'a str]),
    Sql(&'a str),
    Decision(Decision),
}

pub(crate) fn unwrap<'a>(args: &'a [&'a str]) -> Target<'a> {
    let Ok(args) = skip_global_options(args) else {
        return blocked("ddev.context.unknown");
    };
    let Some((command, rest)) = args.split_first() else {
        return Target::Safe;
    };
    match *command {
        "drush" => Target::Drush(rest),
        "composer" => Target::Composer(rest),
        "exec" | "." => execution_target(rest),
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
        "mysql" => match super::sql::client_query(rest, true) {
            Ok(query) => Target::Sql(query),
            Err(()) => Target::Decision(super::sql::uninspectable()),
        },
        "delete" | "snapshot" | "restore" => blocked("ddev.database_mutation"),
        "stop" if rest.iter().any(|arg| arg.starts_with("--remove-data")) => {
            blocked("ddev.database_mutation")
        }
        "start" | "describe" | "status" | "version" | "list" | "logs" | "stop" | "restart" => {
            Target::Safe
        }
        _ => blocked("ddev.command.unknown"),
    }
}

fn blocked(rule: &str) -> Target<'static> {
    Target::Decision(decision(
        DecisionEffect::Deny,
        rule,
        "ddev",
        "DDEV operation or execution context cannot be allowed safely.",
        Severity::High,
    ))
}

fn skip_global_options<'a>(args: &'a [&'a str]) -> Result<&'a [&'a str], ()> {
    let mut index = 0;
    while let Some(argument) = args.get(index) {
        if matches!(*argument, "--yes" | "-y" | "--verbose" | "-v") {
            index += 1;
        } else if argument.starts_with('-') {
            return Err(());
        } else {
            break;
        }
    }
    Ok(&args[index..])
}

fn execution_target<'a>(args: &'a [&'a str]) -> Target<'a> {
    let mut index = 0;
    let mut directory = None;
    let mut raw = false;
    while let Some(argument) = args.get(index) {
        if *argument == "--" {
            index += 1;
            break;
        }
        if !argument.starts_with('-') {
            break;
        }
        let (flag, value, consumed) = if let Some((flag, value)) = argument.split_once('=') {
            (flag, value, 1)
        } else if matches!(*argument, "--service" | "-s" | "--dir" | "-d") {
            let Some(value) = args.get(index + 1) else {
                return blocked("ddev.context.unknown");
            };
            (*argument, *value, 2)
        } else if matches!(*argument, "--raw" | "--raw=true") {
            raw = true;
            index += 1;
            continue;
        } else {
            return blocked("ddev.context.unknown");
        };
        match flag {
            "--service" | "-s" if value == "web" => {}
            "--dir" | "-d" if crate::paths::is_absolute(value) => directory = Some(value),
            "--raw" if value == "true" => raw = true,
            _ => return blocked("ddev.context.unknown"),
        }
        index += consumed;
    }
    if index == args.len() {
        return blocked("ddev.context.unknown");
    }
    Target::Nested(&args[index..], directory, raw)
}

/// DDEV 1.25 reconstructs a Bash string unless --raw is explicitly present.
/// Its quoting differs from the host shell: unquoted metacharacters expand,
/// while whitespace-containing operands are double-quoted, which still expands
/// dollars/backticks/backslashes. Classify only literal reconstruction here.
pub(crate) fn reconstruction_is_literal(args: &[&str]) -> bool {
    args.iter().all(|arg| {
        if arg.is_empty() {
            return false;
        }
        let double_quoted = arg.contains(['"', ' ', '\t', '\r', '\n', '#']);
        if double_quoted {
            !arg.contains(['$', '`', '\\'])
        } else {
            !arg.contains([
                '$', '`', '\\', '\'', ';', '|', '&', '<', '>', '*', '?', '[', ']', '(', ')', '{',
                '}', '~',
            ])
        }
    })
}

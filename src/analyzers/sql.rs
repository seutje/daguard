//! SQL operation analysis.

use crate::analyzers::decision;
use crate::model::{Decision, DecisionEffect, Severity};

pub(crate) fn analyze(sql: &str, configured_sensitive_tables: &[&str]) -> Option<Decision> {
    if sql.trim().is_empty() || sql.len() > 16 * 1024 || sql.contains('\0') {
        return Some(uninspectable());
    }
    let Some(words) = lexical_words(sql) else {
        return Some(uninspectable());
    };
    for statement in words.split(|word| word == ";") {
        for keyword in [
            "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "REPLACE", "CREATE",
            "GRANT", "REVOKE",
        ] {
            if statement.iter().any(|word| word == keyword) {
                return Some(decision(
                    DecisionEffect::Deny,
                    &format!("sql.mutation.{}", keyword.to_ascii_lowercase()),
                    "sql",
                    "Mutating SQL is prohibited.",
                    Severity::Critical,
                ));
            }
        }
        if !statement.is_empty()
            && !statement.first().is_some_and(|word| {
                matches!(word.as_str(), "SELECT" | "SHOW" | "EXPLAIN" | "DESCRIBE")
            })
        {
            return Some(uninspectable());
        }
        if statement
            .first()
            .is_some_and(|word| matches!(word.as_str(), "SELECT" | "SHOW" | "EXPLAIN" | "DESCRIBE"))
            && statement
                .iter()
                .any(|word| sensitive_table(word, configured_sensitive_tables))
        {
            return Some(decision(
                DecisionEffect::Deny,
                "sql.read.sensitive_table",
                "sql",
                "Reading sensitive Drupal database tables is prohibited.",
                Severity::High,
            ));
        }
    }
    None
}

/// Returns normalized sensitive table identifiers referenced by bounded SQL.
/// Values are schema identifiers only; no query literals or result content are
/// returned. `None` means the SQL could not be classified safely.
pub(crate) fn referenced_sensitive_tables(
    sql: &str,
    configured_sensitive_tables: &[&str],
) -> Option<Vec<String>> {
    if sql.len() > 16 * 1024 || sql.contains('\0') {
        return None;
    }
    let words = lexical_words(sql)?;
    let mut tables = Vec::new();
    for word in words {
        let table = word
            .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .to_ascii_lowercase();
        if table.is_empty() || tables.contains(&table) {
            continue;
        }
        if sensitive_table_name(&table, configured_sensitive_tables) {
            tables.push(table);
        }
    }
    Some(tables)
}

pub(crate) fn uninspectable() -> Decision {
    decision(
        DecisionEffect::Deny,
        "sql.ambiguous",
        "sql",
        "SQL syntax cannot be classified safely.",
        Severity::High,
    )
}

fn sensitive_table(word: &str, configured: &[&str]) -> bool {
    let table = word
        .trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .to_ascii_lowercase();
    sensitive_table_name(&table, configured)
}

fn sensitive_table_name(table: &str, configured: &[&str]) -> bool {
    const BUILT_IN: &[&str] = &[
        "sessions",
        "users",
        "users_field_data",
        "users_data",
        "user__*",
        "key_value",
        "key_value_expire",
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
        "watchdog",
        "flood",
    ];
    const PREFIXABLE_BUILT_IN: &[&str] = &[
        "sessions",
        "users",
        "users_field_data",
        "users_data",
        "user__*",
        "key_value",
        "key_value_expire",
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
        "profile_field_data",
        "profile_revision",
        "profile_field_revision",
        "profile__*",
        "profile_revision__*",
        "commerce_shipment",
        "commerce_shipment__*",
    ];
    BUILT_IN
        .iter()
        .any(|pattern| table_name_matches(table, pattern, false))
        || PREFIXABLE_BUILT_IN
            .iter()
            .any(|pattern| table_name_matches(table, pattern, true))
        || configured.iter().any(|pattern| {
            table_name_matches(table, pattern, false) || table_name_matches(table, pattern, true)
        })
}

/// Match the policy's deliberately small table glob syntax: `*` is the only
/// metacharacter and matches zero or more table-name characters. In prefixed
/// mode the virtual pattern `*_<pattern>` recognizes Drupal database prefixes
/// without repeatedly scanning every suffix of an untrusted table token.
fn table_name_matches(table: &str, pattern: &str, prefixed: bool) -> bool {
    let table = table.as_bytes();
    let pattern = pattern.as_bytes();
    let pattern_len = pattern.len() + usize::from(prefixed) * 2;
    let pattern_byte = |index: usize| {
        if prefixed && index == 0 {
            b'*'
        } else if prefixed && index == 1 {
            b'_'
        } else {
            pattern[index - usize::from(prefixed) * 2]
        }
    };
    let (mut table_index, mut pattern_index) = (0, 0);
    let (mut star_index, mut star_table_index) = (None, 0);

    while table_index < table.len() {
        if pattern_index < pattern_len
            && pattern_byte(pattern_index) != b'*'
            && pattern_byte(pattern_index).eq_ignore_ascii_case(&table[table_index])
        {
            table_index += 1;
            pattern_index += 1;
        } else if pattern_index < pattern_len && pattern_byte(pattern_index) == b'*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_table_index = table_index;
        } else if let Some(star) = star_index {
            star_table_index += 1;
            table_index = star_table_index;
            pattern_index = star + 1;
        } else {
            return false;
        }
    }

    while pattern_index < pattern_len && pattern_byte(pattern_index) == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern_len
}

fn lexical_words(sql: &str) -> Option<Vec<String>> {
    let chars = sql.chars().collect::<Vec<_>>();
    let mut result = Vec::new();
    let mut word = String::new();
    let mut index = 0;
    let mut quote = None;
    while index < chars.len() {
        let character = chars[index];
        if let Some(active) = quote {
            if character == active {
                if chars.get(index + 1) == Some(&active) {
                    index += 1;
                } else {
                    quote = None;
                    push(&mut result, &mut word);
                }
            } else if character == '\\' {
                return None; // SQL mode may disable backslash escaping.
            } else if active != '\'' {
                word.push(character.to_ascii_uppercase());
            }
            index += 1;
            continue;
        }
        if matches!(character, '\'' | '"' | '`') {
            push(&mut result, &mut word);
            quote = Some(character);
        } else if character == '#'
            || (character == '-'
                && chars.get(index + 1) == Some(&'-')
                && chars.get(index + 2).is_none_or(|character| {
                    character.is_ascii_whitespace() || character.is_ascii_control()
                }))
        {
            push(&mut result, &mut word);
            while index < chars.len() && chars[index] != '\n' {
                index += 1;
            }
        } else if character == '/' && chars.get(index + 1) == Some(&'*') {
            if chars.get(index + 2) == Some(&'!')
                || (chars.get(index + 2) == Some(&'M') && chars.get(index + 3) == Some(&'!'))
            {
                return None; // MySQL/MariaDB executable comments cannot be skipped.
            }
            push(&mut result, &mut word);
            index += 2;
            while index + 1 < chars.len() && !(chars[index] == '*' && chars[index + 1] == '/') {
                index += 1;
            }
            if index + 1 >= chars.len() {
                return None;
            }
            index += 1;
        } else if character == '\\' {
            return None; // Client meta commands and mode-dependent escapes.
        } else if character == ';' {
            push(&mut result, &mut word);
            result.push(";".to_owned());
        } else if character.is_ascii_alphanumeric() || character == '_' {
            word.push(character.to_ascii_uppercase());
        } else {
            push(&mut result, &mut word);
        }
        index += 1;
    }
    if quote.is_some() {
        return None;
    }
    push(&mut result, &mut word);
    Some(result)
}

fn push(result: &mut Vec<String>, word: &mut String) {
    if !word.is_empty() {
        result.push(std::mem::take(word));
    }
}

/// Direct clients and DDEV share attached/separated execution parsing.
pub(crate) fn client_query<'a>(args: &'a [&'a str], positional_query: bool) -> Result<&'a str, ()> {
    let mut query = None;
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        let value = if matches!(*arg, "-e" | "--execute") {
            index += 1;
            Some(*args.get(index).ok_or(())?)
        } else {
            arg.strip_prefix("--execute=")
                .or_else(|| arg.strip_prefix("-e").filter(|value| !value.is_empty()))
        };
        if let Some(value) = value {
            if query.replace(value).is_some() || value.is_empty() {
                return Err(());
            }
        } else if arg.starts_with("--init-command") || matches!(*arg, "--binary-mode" | "--force") {
            return Err(());
        } else if positional_query && args.len() == 1 && !arg.starts_with('-') {
            query = Some(*arg);
        } else if matches!(
            *arg,
            "-h" | "--host"
                | "-u"
                | "--user"
                | "-P"
                | "--port"
                | "-S"
                | "--socket"
                | "-D"
                | "--database"
        ) {
            index += 1;
            if args.get(index).is_none() {
                return Err(());
            }
        }
        if arg.starts_with('-')
            && value.is_none()
            && !matches!(
                *arg,
                "-h" | "--host"
                    | "-u"
                    | "--user"
                    | "-P"
                    | "--port"
                    | "-S"
                    | "--socket"
                    | "-D"
                    | "--database"
                    | "-B"
                    | "--batch"
                    | "-N"
                    | "--skip-column-names"
                    | "-t"
                    | "--table"
                    | "--no-defaults"
            )
            && ![
                "--host=",
                "--user=",
                "--port=",
                "--socket=",
                "--database=",
                "-h",
                "-u",
                "-P",
                "-S",
                "-D",
            ]
            .iter()
            .any(|flag| arg.starts_with(flag) && arg.len() > flag.len())
        {
            return Err(());
        }
        index += 1;
    }
    query.ok_or(())
}

#[cfg(test)]
mod tests {
    use super::{analyze, referenced_sensitive_tables};
    #[test]
    fn handles_comments_chains_and_quoted_keywords() {
        assert_eq!(
            analyze("/*x*/ SeLeCt 'DELETE FROM users' FROM node", &[]),
            None
        );
        assert_eq!(
            analyze("SELECT 1; --x\n DELETE FROM node", &[])
                .unwrap()
                .rule_id,
            "sql.mutation.delete"
        );
        assert_eq!(
            analyze("SELECT * FROM site_users_field_data", &[])
                .unwrap()
                .rule_id,
            "sql.read.sensitive_table"
        );
        for keyword in [
            "INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE", "REPLACE", "CREATE",
            "GRANT", "REVOKE",
        ] {
            assert!(
                analyze(&format!("{keyword} synthetic"), &[]).is_some(),
                "{keyword} must be denied"
            );
        }
        assert_eq!(
            analyze("SELECT * FROM customer_payments", &["customer_payments"])
                .unwrap()
                .rule_id,
            "sql.read.sensitive_table"
        );
        for table in [
            "user__roles",
            "site_user__roles",
            "commerce_order__field_data",
        ] {
            assert_eq!(
                analyze(
                    &format!("SELECT * FROM {table}"),
                    &["user__*", "commerce_order__*"]
                )
                .unwrap()
                .rule_id,
                "sql.read.sensitive_table",
                "{table}"
            );
        }
        assert_eq!(analyze("SELECT * FROM user_profile", &["user__*"]), None);
        assert_eq!(
            referenced_sensitive_tables(
                "SELECT * FROM webform_submission_data JOIN commerce_payment USING (id)",
                &[]
            )
            .unwrap(),
            ["webform_submission_data", "commerce_payment"]
        );
    }
}

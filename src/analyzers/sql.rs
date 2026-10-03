//! SQL operation analysis.

use crate::analyzers::decision;
use crate::model::{Decision, DecisionEffect, Severity};

pub(crate) fn analyze(sql: &str, configured_sensitive_tables: &[&str]) -> Option<Decision> {
    if sql.len() > 16 * 1024 || sql.contains('\0') {
        return Some(ambiguous());
    }
    let Some(words) = lexical_words(sql) else {
        return Some(ambiguous());
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
            return Some(ambiguous());
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

fn ambiguous() -> Decision {
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
    [
        "users",
        "users_field_data",
        "sessions",
        "key_value",
        "key_value_expire",
    ]
    .iter()
    .copied()
    .chain(configured.iter().copied())
    .any(|name| table == *name || table.ends_with(&format!("_{name}")))
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
                }
            } else if character == '\\' {
                index += 1;
            }
            index += 1;
            continue;
        }
        if character == '\'' || character == '"' {
            push(&mut result, &mut word);
            quote = Some(character);
        } else if character == '-' && chars.get(index + 1) == Some(&'-') {
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

#[cfg(test)]
mod tests {
    use super::analyze;
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
    }
}

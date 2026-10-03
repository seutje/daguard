//! Agent-specific protocol translation.

pub(crate) mod codex;
pub(crate) mod cursor;
pub(crate) mod opencode;

pub(crate) fn command_tokens(command: &str) -> Option<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in command.chars() {
        match (quote, character) {
            (Some(expected), value) if value == expected => quote = None,
            (None, '\'' | '"') => quote = Some(character),
            (None, value) if value.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            (Some(_) | None, value) => current.push(value),
        }
    }
    if quote.is_some() {
        return None;
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Some(tokens)
}

pub(crate) fn is_daguard_executable(path: &str) -> bool {
    crate::paths::is_absolute(path)
        && path.rsplit(['/', '\\']).next().is_some_and(|name| {
            name.eq_ignore_ascii_case("daguard") || name.eq_ignore_ascii_case("daguard.exe")
        })
}

#[cfg(test)]
mod tests {
    #[test]
    fn tokenizes_quoted_native_windows_hook_commands() {
        let tokens = super::command_tokens(
            r#""C:\Program Files\Daguard\daguard.exe" --policy "C:\ProgramData\Daguard\policy.json""#,
        )
        .unwrap();
        assert_eq!(tokens[0], r"C:\Program Files\Daguard\daguard.exe");
        assert_eq!(tokens[2], r"C:\ProgramData\Daguard\policy.json");
        assert!(super::is_daguard_executable(&tokens[0]));
    }
}

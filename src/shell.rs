//! Bounded shell tokenization and shell-level classification helpers.

use std::fmt;

const MAX_COMMAND_BYTES: usize = 16 * 1024;
const MAX_TOKENS: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Operator {
    Sequence,
    And,
    Or,
    Pipe,
    Redirect { append: bool },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Token {
    Word(String),
    Operator(Operator),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ShellError {
    Limit,
    Nul,
    UnterminatedQuote,
    Unsupported(&'static str),
}

impl fmt::Display for ShellError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Limit => formatter.write_str("shell command exceeds analysis limits"),
            Self::Nul => formatter.write_str("shell command contains a NUL byte"),
            Self::UnterminatedQuote => {
                formatter.write_str("shell command has an unterminated quote")
            }
            Self::Unsupported(feature) => {
                write!(formatter, "unsupported shell construct: {feature}")
            }
        }
    }
}

/// Tokenizes the deliberately small shell subset used by the policy analyzers.
/// Expansion is never performed. Unsupported expansion constructs fail closed.
pub(crate) fn tokenize(input: &str) -> Result<Vec<Token>, ShellError> {
    if input.len() > MAX_COMMAND_BYTES {
        return Err(ShellError::Limit);
    }
    if input.contains('\0') {
        return Err(ShellError::Nul);
    }
    let chars = input.chars().collect::<Vec<_>>();
    let mut tokens = Vec::new();
    let mut word = String::new();
    let mut index = 0;
    let mut quote = None;
    while index < chars.len() {
        let character = chars[index];
        if let Some(active) = quote {
            if character == active {
                quote = None;
            } else if character == '\\' && active == '"' {
                index += 1;
                let Some(next) = chars.get(index) else {
                    return Err(ShellError::UnterminatedQuote);
                };
                word.push(*next);
            } else {
                word.push(character);
            }
            index += 1;
            continue;
        }
        match character {
            '\'' | '"' => quote = Some(character),
            '\\' => {
                index += 1;
                let Some(next) = chars.get(index) else {
                    return Err(ShellError::Unsupported("trailing escape"));
                };
                word.push(*next);
            }
            '`' => return Err(ShellError::Unsupported("command substitution")),
            '$' if chars.get(index + 1) == Some(&'(') => {
                return Err(ShellError::Unsupported("command substitution"));
            }
            '<' if chars.get(index + 1) == Some(&'<') => {
                return Err(ShellError::Unsupported("here document"));
            }
            ' ' | '\t' | '\r' | '\n' => push_word(&mut tokens, &mut word),
            ';' => {
                push_word(&mut tokens, &mut word);
                tokens.push(Token::Operator(Operator::Sequence));
            }
            '&' if chars.get(index + 1) == Some(&'&') => {
                push_word(&mut tokens, &mut word);
                tokens.push(Token::Operator(Operator::And));
                index += 1;
            }
            '|' => {
                push_word(&mut tokens, &mut word);
                if chars.get(index + 1) == Some(&'|') {
                    tokens.push(Token::Operator(Operator::Or));
                    index += 1;
                } else {
                    tokens.push(Token::Operator(Operator::Pipe));
                }
            }
            '>' => {
                push_word(&mut tokens, &mut word);
                let append = chars.get(index + 1) == Some(&'>');
                if append {
                    index += 1;
                }
                tokens.push(Token::Operator(Operator::Redirect { append }));
            }
            '<' | '&' => {
                return Err(ShellError::Unsupported(
                    "redirection or background execution",
                ));
            }
            _ => word.push(character),
        }
        if tokens.len() > MAX_TOKENS {
            return Err(ShellError::Limit);
        }
        index += 1;
    }
    if quote.is_some() {
        return Err(ShellError::UnterminatedQuote);
    }
    push_word(&mut tokens, &mut word);
    if tokens.len() > MAX_TOKENS {
        return Err(ShellError::Limit);
    }
    Ok(tokens)
}

fn push_word(tokens: &mut Vec<Token>, word: &mut String) {
    if !word.is_empty() {
        tokens.push(Token::Word(std::mem::take(word)));
    }
}

pub(crate) fn segments(tokens: &[Token]) -> Vec<&[Token]> {
    let mut result = Vec::new();
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        if matches!(
            token,
            Token::Operator(Operator::Sequence | Operator::And | Operator::Or | Operator::Pipe)
        ) {
            if start < index {
                result.push(&tokens[start..index]);
            }
            start = index + 1;
        }
    }
    if start < tokens.len() {
        result.push(&tokens[start..]);
    }
    result
}

pub(crate) fn words(segment: &[Token]) -> Vec<&str> {
    segment
        .iter()
        .filter_map(|token| match token {
            Token::Word(word) => Some(word.as_str()),
            Token::Operator(_) => None,
        })
        .collect()
}

pub(crate) fn redirect_targets(tokens: &[Token]) -> Result<Vec<&str>, ShellError> {
    let mut targets = Vec::new();
    for window in tokens.windows(2) {
        if matches!(window[0], Token::Operator(Operator::Redirect { .. })) {
            match &window[1] {
                Token::Word(path) => targets.push(path.as_str()),
                Token::Operator(_) => {
                    return Err(ShellError::Unsupported("missing redirection target"));
                }
            }
        }
    }
    if matches!(
        tokens.last(),
        Some(Token::Operator(Operator::Redirect { .. }))
    ) {
        return Err(ShellError::Unsupported("missing redirection target"));
    }
    Ok(targets)
}

#[cfg(test)]
mod tests {
    use super::{Operator, ShellError, Token, redirect_targets, segments, tokenize, words};

    #[test]
    fn recognizes_quotes_chaining_pipes_and_redirects() {
        let tokens =
            tokenize("echo 'safe value' && git status | tee \"out file\"; echo ok >> log").unwrap();
        assert!(tokens.contains(&Token::Operator(Operator::And)));
        assert!(tokens.contains(&Token::Operator(Operator::Pipe)));
        assert_eq!(segments(&tokens).len(), 4);
        assert_eq!(redirect_targets(&tokens).unwrap(), ["log"]);
        assert_eq!(words(segments(&tokens)[0]), ["echo", "safe value"]);
    }

    #[test]
    fn rejects_ambiguous_or_unbounded_input() {
        assert_eq!(
            tokenize("echo $(danger)"),
            Err(ShellError::Unsupported("command substitution"))
        );
        assert_eq!(
            tokenize("echo 'unterminated"),
            Err(ShellError::UnterminatedQuote)
        );
        assert_eq!(tokenize(&"x".repeat(16 * 1024 + 1)), Err(ShellError::Limit));
    }
}

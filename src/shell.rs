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
// Keep the bounded tokenizer state machine together for review.
#[allow(clippy::too_many_lines)]
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
    let mut started = false;
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
                if *next != '\n' {
                    word.push(*next);
                }
            } else if active == '"' && (character == '$' || character == '`') {
                return Err(ShellError::Unsupported("quoted shell expansion"));
            } else {
                word.push(character);
            }
            index += 1;
            continue;
        }
        match character {
            '\'' | '"' => {
                started = true;
                quote = Some(character);
            }
            '\\' => {
                started = true;
                index += 1;
                let Some(next) = chars.get(index) else {
                    return Err(ShellError::Unsupported("trailing escape"));
                };
                if *next != '\n' {
                    word.push(*next);
                }
            }
            '`' => return Err(ShellError::Unsupported("command substitution")),
            '$' if chars.get(index + 1) == Some(&'(') => {
                return Err(ShellError::Unsupported("command substitution"));
            }
            '<' if chars.get(index + 1) == Some(&'<') => {
                return Err(ShellError::Unsupported("here document"));
            }
            ' ' | '\t' | '\r' => push_word(&mut tokens, &mut word, &mut started),
            '\n' | ';' => {
                push_word(&mut tokens, &mut word, &mut started);
                tokens.push(Token::Operator(Operator::Sequence));
            }
            '&' if chars.get(index + 1) == Some(&'&') => {
                push_word(&mut tokens, &mut word, &mut started);
                tokens.push(Token::Operator(Operator::And));
                index += 1;
            }
            '|' => {
                push_word(&mut tokens, &mut word, &mut started);
                if chars.get(index + 1) == Some(&'|') {
                    tokens.push(Token::Operator(Operator::Or));
                    index += 1;
                } else {
                    tokens.push(Token::Operator(Operator::Pipe));
                }
            }
            '>' => {
                push_word(&mut tokens, &mut word, &mut started);
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
            '$' | '*' | '?' | '[' | ']' | '(' | ')' | '{' | '}' | '~' => {
                return Err(ShellError::Unsupported("expansion or grouping"));
            }
            _ => {
                started = true;
                word.push(character);
            }
        }
        if tokens.len() > MAX_TOKENS {
            return Err(ShellError::Limit);
        }
        index += 1;
    }
    if quote.is_some() {
        return Err(ShellError::UnterminatedQuote);
    }
    push_word(&mut tokens, &mut word, &mut started);
    if tokens.len() > MAX_TOKENS {
        return Err(ShellError::Limit);
    }
    Ok(tokens)
}

fn push_word(tokens: &mut Vec<Token>, word: &mut String, started: &mut bool) {
    if *started {
        *started = false;
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

/// Normalize transparent execution wrappers without executing them.
pub(crate) fn normalize_argv<'a>(mut words: &'a [&'a str]) -> Result<&'a [&'a str], ShellError> {
    for _ in 0..8 {
        while words.first().is_some_and(|word| is_assignment(word)) {
            words = &words[1..];
        }
        let Some((program, args)) = words.split_first() else {
            return Ok(words);
        };
        let program = program.rsplit('/').next().unwrap_or(program);
        let skip = match program {
            "env" => wrapper_options(
                args,
                &["-i", "--ignore-environment", "-0", "--null"],
                &["-u", "--unset"],
            )?,
            "command" => wrapper_options(args, &["-p"], &[])?,
            "timeout" => {
                wrapper_options(
                    args,
                    &["--foreground", "--preserve-status", "-v", "--verbose"],
                    &["-s", "--signal", "-k", "--kill-after"],
                )? + 1
            }
            "nice" => wrapper_options(args, &[], &["-n", "--adjustment"])?,
            "nohup" | "setsid" => wrapper_options(args, &["-f", "--fork", "-w", "--wait"], &[])?,
            "stdbuf" => wrapper_options(
                args,
                &[],
                &["-i", "-o", "-e", "--input", "--output", "--error"],
            )?,
            "busybox" => 0,
            "daguard"
                if args
                    .first()
                    .is_some_and(|arg| matches!(*arg, "exec" | "mcp-proxy")) =>
            {
                args.iter()
                    .position(|arg| *arg == "--")
                    .ok_or(ShellError::Unsupported("guarded route"))?
                    + 1
            }
            "xargs" | "eval" | "exec" => {
                return Err(ShellError::Unsupported("opaque execution wrapper"));
            }
            _ => return Ok(words),
        };
        words = args
            .get(skip..)
            .filter(|rest| !rest.is_empty())
            .ok_or(ShellError::Unsupported("missing wrapped command"))?;
    }
    Err(ShellError::Limit)
}

fn is_assignment(word: &str) -> bool {
    word.split_once('=').is_some_and(|(name, _)| {
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn wrapper_options(args: &[&str], flags: &[&str], values: &[&str]) -> Result<usize, ShellError> {
    let mut index = 0;
    while let Some(arg) = args.get(index) {
        if *arg == "--" {
            return Ok(index + 1);
        }
        if !arg.starts_with('-') {
            return Ok(index);
        }
        if flags.contains(arg) {
            index += 1;
        } else if values.contains(arg) && args.get(index + 1).is_some() {
            index += 2;
        } else if values.iter().any(|flag| {
            arg.starts_with(&format!("{flag}="))
                || (flag.len() == 2 && arg.starts_with(flag) && arg.len() > 2)
        }) {
            index += 1;
        } else {
            return Err(ShellError::Unsupported("wrapper option"));
        }
    }
    Ok(index)
}

/// Literal `cd DIR && ...` is the only supported directory-changing form.
/// Other connectors can execute later commands in multiple possible directories.
pub(crate) fn contextual_segments<'a>(
    tokens: &'a [Token],
    cwd: &str,
) -> Result<Vec<(String, &'a [Token])>, ShellError> {
    let parts = segments(tokens);
    let changes_directory = parts.iter().any(|part| words(part).first() == Some(&"cd"));
    if changes_directory
        && tokens.iter().any(|token| {
            matches!(
                token,
                Token::Operator(Operator::Sequence | Operator::Or | Operator::Pipe)
            )
        })
    {
        return Err(ShellError::Unsupported("conditional directory context"));
    }
    let mut current = cwd.to_owned();
    let mut result = Vec::new();
    for part in parts {
        let argv = words(part);
        if argv.first() == Some(&"cd") {
            if argv.len() != 2
                || argv[1].starts_with('-')
                || argv[1].is_empty()
                || part.iter().any(|token| matches!(token, Token::Operator(_)))
            {
                return Err(ShellError::Unsupported("directory change"));
            }
            current = crate::paths::normalize(&current, argv[1])
                .map_err(|_| ShellError::Unsupported("directory path"))?;
        } else {
            result.push((current.clone(), part));
        }
    }
    Ok(result)
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
    fn preserves_empty_arguments() {
        assert_eq!(
            words(&tokenize("printf '%s' '' \"\"").unwrap()),
            ["printf", "%s", "", ""]
        );
    }

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

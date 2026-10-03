//! Lexical path normalization and matching primitives.

use std::fmt;
use std::path::{Component, Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};

const MAX_PATH_BYTES: usize = 4_096;

#[derive(Debug)]
pub(crate) enum PathError {
    Invalid(&'static str),
    Pattern(globset::Error),
}

impl fmt::Display for PathError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::Pattern(error) => write!(formatter, "invalid path pattern: {error}"),
        }
    }
}

/// Normalizes a request path without consulting the filesystem.
///
/// The v1 contract is intentionally lexical: repeated separators, `.` and `..`
/// are resolved, but symlinks are not followed. This recognizes future writes
/// and remains deterministic when a target does not exist.
pub(crate) fn normalize(cwd: &str, candidate: &str) -> Result<String, PathError> {
    if cwd.contains('\0')
        || candidate.contains('\0')
        || candidate.is_empty()
        || cwd.len() > MAX_PATH_BYTES
        || candidate.len() > MAX_PATH_BYTES
    {
        return Err(PathError::Invalid("path contains invalid data"));
    }
    let cwd = Path::new(cwd);
    if !cwd.is_absolute() {
        return Err(PathError::Invalid("request cwd must be absolute"));
    }
    let combined = if Path::new(candidate).is_absolute() {
        PathBuf::from(candidate)
    } else {
        cwd.join(candidate)
    };
    let mut normalized = PathBuf::from("/");
    for component in combined.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(part) => normalized.push(part),
            Component::Prefix(_) => {
                return Err(PathError::Invalid("unsupported path prefix"));
            }
        }
    }
    let normalized = normalized.to_string_lossy().into_owned();
    if normalized.len() > MAX_PATH_BYTES {
        return Err(PathError::Invalid("normalized path exceeds 4096 bytes"));
    }
    Ok(normalized)
}

pub(crate) struct PathPattern {
    matcher: GlobMatcher,
    directory_root_matcher: Option<GlobMatcher>,
}

impl PathPattern {
    pub(crate) fn compile(pattern: &str) -> Result<Self, PathError> {
        if pattern.is_empty()
            || pattern.contains('\0')
            || pattern.starts_with('/')
            || pattern.split('/').any(|component| component == "..")
        {
            return Err(PathError::Invalid(
                "path patterns must be relative and non-empty",
            ));
        }
        let matcher = GlobBuilder::new(pattern)
            .literal_separator(true)
            .backslash_escape(false)
            .build()
            .map_err(PathError::Pattern)?
            .compile_matcher();
        // Treat a recursive directory policy as covering the directory entry
        // itself as well as its descendants. `globset` intentionally does not
        // make `foo/**` match `foo`, but that distinction is unsafe and
        // surprising for access-control rules.
        let directory_root_matcher = pattern
            .strip_suffix("/**")
            .map(|root| {
                GlobBuilder::new(root)
                    .literal_separator(true)
                    .backslash_escape(false)
                    .build()
                    .map(|glob| glob.compile_matcher())
                    .map_err(PathError::Pattern)
            })
            .transpose()?;
        Ok(Self {
            matcher,
            directory_root_matcher,
        })
    }

    pub(crate) fn matches(&self, normalized: &str) -> bool {
        let relative = normalized.trim_start_matches('/');
        self.matcher.is_match(relative)
            || self
                .directory_root_matcher
                .as_ref()
                .is_some_and(|matcher| matcher.is_match(relative))
    }
}

#[cfg(test)]
mod tests {
    use super::{PathPattern, normalize};

    #[test]
    fn normalizes_relative_segments_and_repeated_separators() {
        assert_eq!(
            normalize("/workspace/project", "foo//bar/../file.txt").unwrap(),
            "/workspace/project/foo/file.txt"
        );
    }

    #[test]
    fn preserves_normalized_absolute_paths() {
        assert_eq!(
            normalize("/workspace/project", "/tmp/./one/../two").unwrap(),
            "/tmp/two"
        );
    }

    #[test]
    fn normalizes_traversal_before_matching() {
        let path = normalize(
            "/workspace/project",
            "web/modules/custom/../../sites/default/settings.php",
        )
        .unwrap();
        let pattern = PathPattern::compile("**/sites/*/settings.php").unwrap();
        assert!(pattern.matches(&path));
    }

    #[test]
    fn matches_multisite_settings_but_not_custom_source() {
        let pattern = PathPattern::compile("**/sites/*/settings.php").unwrap();
        assert!(pattern.matches("/workspace/web/sites/example/settings.php"));
        assert!(!pattern.matches("/workspace/web/modules/custom/site/settings.php"));
    }

    #[test]
    fn recursive_patterns_include_the_directory_root() {
        let pattern = PathPattern::compile("**/env/**").unwrap();
        assert!(pattern.matches("/workspace/project/env"));
        assert!(pattern.matches("/workspace/project/env/local/settings.json"));
        assert!(!pattern.matches("/workspace/project/environment"));
    }

    #[test]
    fn rejects_relative_working_directories() {
        assert!(normalize("relative", "file.txt").is_err());
    }

    #[test]
    fn rejects_parent_traversal_in_policy_patterns() {
        assert!(PathPattern::compile("../outside/**").is_err());
        assert!(PathPattern::compile("safe/../../outside/**").is_err());
    }
}

//! Lexical path normalization and matching primitives.

use globset::{GlobBuilder, GlobMatcher};
use std::fmt;

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
    if is_windows_absolute(cwd) {
        return normalize_windows(cwd, candidate);
    }
    if !cwd.starts_with('/') {
        return Err(PathError::Invalid("request cwd must be absolute"));
    }
    let mut parts = if candidate.starts_with('/') {
        Vec::new()
    } else {
        let mut parts = Vec::new();
        normalize_parts(&mut parts, cwd.split('/'));
        parts
    };
    normalize_parts(&mut parts, candidate.split('/'));
    let normalized = format!("/{}", parts.join("/"));
    if normalized.len() > MAX_PATH_BYTES {
        return Err(PathError::Invalid("normalized path exceeds 4096 bytes"));
    }
    Ok(normalized)
}

/// Returns true for an absolute path in either supported native syntax.
///
/// This is intentionally host-independent so adapters can validate Windows
/// payloads in shared fixture tests and Linux payloads on native Windows.
pub(crate) fn is_absolute(path: &str) -> bool {
    path.starts_with('/') || is_windows_absolute(path)
}

fn is_windows_absolute(path: &str) -> bool {
    let bytes = path.as_bytes();
    let drive_rooted = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'/' | b'\\');
    let unc = bytes.len() >= 5
        && matches!(bytes[0], b'/' | b'\\')
        && bytes[1] == bytes[0]
        && !matches!(bytes[2], b'/' | b'\\');
    drive_rooted || unc
}

#[derive(Clone)]
enum WindowsRoot {
    Drive(u8),
    Unc { server: String, share: String },
}

fn normalize_windows(cwd: &str, candidate: &str) -> Result<String, PathError> {
    let (cwd_root, cwd_parts) = parse_windows_absolute(cwd)?;
    let candidate = candidate.replace('\\', "/");
    let (root, mut parts, tail) = if is_windows_absolute(&candidate) {
        let (root, parts) = parse_windows_absolute(&candidate)?;
        (root, Vec::new(), parts)
    } else if has_drive_prefix(&candidate) {
        return Err(PathError::Invalid(
            "drive-relative Windows paths are unsupported",
        ));
    } else if candidate.starts_with('/') {
        (
            cwd_root,
            Vec::new(),
            candidate
                .trim_start_matches('/')
                .split('/')
                .map(str::to_owned)
                .collect(),
        )
    } else {
        (
            cwd_root,
            cwd_parts,
            candidate.split('/').map(str::to_owned).collect(),
        )
    };
    normalize_parts(&mut parts, tail.iter().map(String::as_str));
    let suffix = parts.join("/");
    let normalized = match root {
        WindowsRoot::Drive(letter) => {
            if suffix.is_empty() {
                format!("{}:/", (letter as char).to_ascii_uppercase())
            } else {
                format!("{}:/{suffix}", (letter as char).to_ascii_uppercase())
            }
        }
        WindowsRoot::Unc { server, share } => {
            if suffix.is_empty() {
                format!("//{server}/{share}")
            } else {
                format!("//{server}/{share}/{suffix}")
            }
        }
    };
    if normalized.len() > MAX_PATH_BYTES {
        return Err(PathError::Invalid("normalized path exceeds 4096 bytes"));
    }
    Ok(normalized)
}

fn parse_windows_absolute(path: &str) -> Result<(WindowsRoot, Vec<String>), PathError> {
    let normalized = path.replace('\\', "/");
    let bytes = normalized.as_bytes();
    if bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'/' {
        let mut parts = Vec::new();
        normalize_parts(&mut parts, normalized[3..].split('/'));
        return Ok((WindowsRoot::Drive(bytes[0]), parts));
    }
    if let Some(rest) = normalized.strip_prefix("//") {
        let mut components = rest.split('/').filter(|part| !part.is_empty());
        let server = components
            .next()
            .ok_or(PathError::Invalid("UNC path requires a server and share"))?;
        let share = components
            .next()
            .ok_or(PathError::Invalid("UNC path requires a server and share"))?;
        if matches!(server, "." | "..") || matches!(share, "." | "..") {
            return Err(PathError::Invalid("UNC path has an invalid root"));
        }
        let mut parts = Vec::new();
        normalize_parts(&mut parts, components);
        return Ok((
            WindowsRoot::Unc {
                server: server.to_owned(),
                share: share.to_owned(),
            },
            parts,
        ));
    }
    Err(PathError::Invalid("request cwd must be absolute"))
}

fn normalize_parts<'a>(parts: &mut Vec<String>, source: impl Iterator<Item = &'a str>) {
    for part in source {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            _ => parts.push(part.to_owned()),
        }
    }
}

fn has_drive_prefix(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':'
}

pub(crate) struct PathPattern {
    matcher: GlobMatcher,
    windows_matcher: GlobMatcher,
    directory_root_matcher: Option<GlobMatcher>,
    windows_directory_root_matcher: Option<GlobMatcher>,
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
        let windows_matcher = GlobBuilder::new(pattern)
            .literal_separator(true)
            .backslash_escape(false)
            .case_insensitive(true)
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
        let windows_directory_root_matcher = pattern
            .strip_suffix("/**")
            .map(|root| {
                GlobBuilder::new(root)
                    .literal_separator(true)
                    .backslash_escape(false)
                    .case_insensitive(true)
                    .build()
                    .map(|glob| glob.compile_matcher())
                    .map_err(PathError::Pattern)
            })
            .transpose()?;
        Ok(Self {
            matcher,
            windows_matcher,
            directory_root_matcher,
            windows_directory_root_matcher,
        })
    }

    pub(crate) fn matches(&self, normalized: &str) -> bool {
        let relative = normalized.trim_start_matches('/');
        let windows = is_windows_absolute(normalized);
        let matcher = if windows {
            &self.windows_matcher
        } else {
            &self.matcher
        };
        let root_matcher = if windows {
            &self.windows_directory_root_matcher
        } else {
            &self.directory_root_matcher
        };
        matcher.is_match(relative)
            || root_matcher
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
    fn normalizes_native_macos_paths_lexically() {
        assert_eq!(
            normalize(
                "/Users/developer/Projects/drupal site",
                "web/modules/custom/../custom/example.module",
            )
            .unwrap(),
            "/Users/developer/Projects/drupal site/web/modules/custom/example.module"
        );
        assert_eq!(
            normalize(
                "/Users/developer/Projects/drupal",
                "/Users/developer/Library/../.config/daguard/policy.json",
            )
            .unwrap(),
            "/Users/developer/.config/daguard/policy.json"
        );
    }

    #[test]
    fn normalizes_drive_paths_without_host_path_semantics() {
        assert_eq!(
            normalize(
                r"c:\Users\Developer\Sites\drupal",
                r"web\modules\custom\..\custom\example.module",
            )
            .unwrap(),
            "C:/Users/Developer/Sites/drupal/web/modules/custom/example.module"
        );
        assert_eq!(
            normalize(r"C:\workspace\one", r"D:\other\.\web\..\README.md").unwrap(),
            "D:/other/README.md"
        );
    }

    #[test]
    fn normalizes_unc_and_wsl_interop_paths_lexically() {
        assert_eq!(
            normalize(r"\\server\share\projects\drupal", r"web\..\composer.json",).unwrap(),
            "//server/share/projects/drupal/composer.json"
        );
        assert_eq!(
            normalize(
                r"\\wsl.localhost\Ubuntu\home\developer\drupal",
                r"web\sites\default\settings.php",
            )
            .unwrap(),
            "//wsl.localhost/Ubuntu/home/developer/drupal/web/sites/default/settings.php"
        );
        assert!(normalize(r"\\server", "file.txt").is_err());
    }

    #[test]
    fn windows_matching_is_case_insensitive_but_posix_is_not() {
        let pattern = PathPattern::compile("**/web/core/**").unwrap();
        assert!(pattern.matches("C:/Projects/Drupal/WEB/CORE/lib/file.php"));
        assert!(pattern.matches("//SERVER/Share/Drupal/Web/Core/lib/file.php"));
        assert!(!pattern.matches("/srv/drupal/WEB/CORE/lib/file.php"));
    }

    #[test]
    fn rejects_drive_relative_paths() {
        assert!(normalize(r"C:\workspace", r"D:secret.txt").is_err());
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

//! Project detection and project-policy discovery.

use std::path::{Path, PathBuf};

pub(crate) fn detect_root(start: &Path) -> Option<PathBuf> {
    let start = if start.is_file() {
        start.parent()?
    } else {
        start
    };
    let ancestors = start.ancestors().collect::<Vec<_>>();
    for marker in [".ddev/config.yaml", "composer.json", ".git"] {
        if let Some(root) = ancestors.iter().find(|root| root.join(marker).exists()) {
            return Some((*root).to_path_buf());
        }
    }
    None
}

pub(crate) fn is_inside_project(path: &Path) -> bool {
    detect_root(path).is_some()
}

#[cfg(test)]
mod tests {
    use super::detect_root;
    use std::fs;

    #[test]
    fn detects_a_repository_without_invoking_git() {
        let root =
            std::env::temp_dir().join(format!("daguard-project-test-{}", std::process::id()));
        let nested = root.join("web/modules/custom");
        fs::create_dir_all(root.join(".git")).unwrap();
        fs::create_dir_all(&nested).unwrap();
        assert_eq!(detect_root(&nested).as_deref(), Some(root.as_path()));
        fs::remove_dir_all(root).unwrap();
    }
}

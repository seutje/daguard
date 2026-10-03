//! Platform-specific path and operating-system behavior.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

pub(crate) fn is_wsl() -> bool {
    ["/proc/sys/kernel/osrelease", "/proc/version"]
        .iter()
        .filter_map(|path| fs::read_to_string(path).ok())
        .any(|value| value.to_ascii_lowercase().contains("microsoft"))
}

pub(crate) fn find_executable(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    if !metadata.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Root ownership and mode checks for the primary Linux/WSL managed deployment.
/// Other platforms need an explicit ACL implementation before managed support.
pub(crate) fn managed_metadata_is_trusted(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        trusted_mode(metadata.uid(), metadata.mode())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}

#[cfg(unix)]
fn trusted_mode(uid: u32, mode: u32) -> bool {
    uid == 0 && mode & 0o022 == 0
}

#[cfg(all(test, unix))]
mod tests {
    #[test]
    fn managed_modes_require_root_and_no_group_or_other_write() {
        assert!(super::trusted_mode(0, 0o100_644));
        assert!(super::trusted_mode(0, 0o40755));
        for (uid, mode) in [(1000, 0o100_644), (0, 0o100_664), (0, 0o40777)] {
            assert!(!super::trusted_mode(uid, mode));
        }
    }
}

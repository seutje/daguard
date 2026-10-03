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

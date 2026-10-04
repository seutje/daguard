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

/// Root ownership and mode checks for managed Unix deployments.
/// Native Windows needs an explicit ACL implementation before managed support.
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

/// Traverse using directory descriptors so symlinks (including ancestors) are
/// rejected before creation or permission changes. Existing ancestors are not
/// chmodded. Later operations still require the documented trusted-owner model.
#[cfg(unix)]
pub(crate) fn initialize_state_directory(path: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Component;

    let invalid = || std::io::Error::other("state directory path is not trusted");
    if !path.is_absolute() || path == Path::new("/") {
        return Err(invalid());
    }
    let mut directory = fs::File::open("/")?;
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => CString::new(name.as_bytes()).map_err(|_| invalid())?,
            _ => return Err(invalid()),
        };
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW;
        // SAFETY: directory is owned and live; name is a NUL-terminated component.
        let mut fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::NotFound {
            // SAFETY: same live descriptor and validated component; mode is owner-only.
            let created = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
            if created < 0
                && std::io::Error::last_os_error().kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(std::io::Error::last_os_error());
            }
            // SAFETY: no-follow open verifies the entry after creation/races.
            fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        }
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: successful openat returns a new descriptor owned by this File.
        directory = unsafe { fs::File::from_raw_fd(fd) };
    }
    let metadata = directory.metadata()?;
    // SAFETY: geteuid has no arguments or memory preconditions.
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(invalid());
    }
    // Operates on the validated descriptor, never on a replaced path entry.
    directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    let current = fs::symlink_metadata(path)?;
    if !current.is_dir()
        || current.file_type().is_symlink()
        || current.dev() != metadata.dev()
        || current.ino() != metadata.ino()
    {
        return Err(invalid());
    }
    Ok(())
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
#[cfg(unix)]
pub(crate) fn nonblocking(fd: std::os::fd::RawFd) -> std::io::Result<()> {
    // SAFETY: fcntl operates on a live owned pipe descriptor and integer flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Poll a pipe without allowing an inherited writer to extend the deadline.
#[cfg(unix)]
pub(crate) fn read_ready(
    fd: std::os::fd::RawFd,
    deadline: std::time::Instant,
) -> std::io::Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let timeout = i32::try_from(remaining.as_millis().min(100))
            .unwrap_or(100)
            .max(1);
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one initialized pollfd remains alive for the duration of poll.
        let result = unsafe { libc::poll(&raw mut descriptor, 1, timeout) };
        if result > 0 {
            return Ok(());
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

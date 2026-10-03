//! Managed configuration trust checks and operator-only integrity comparison.

use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path};

use sha2::{Digest, Sha256};

use crate::project;

/// Managed paths must be absolute, outside projects, and controlled by root.
/// Checking every ancestor prevents replacement through a writable directory.
/// No symlink component is accepted, including an alias into a project.
pub(crate) fn managed_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|part| matches!(part, Component::ParentDir))
    {
        return Err(untrusted());
    }
    if project::is_inside_project(path) {
        return Err(untrusted());
    }
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() {
            return Err(untrusted());
        }
        if !crate::platform::managed_metadata_is_trusted(&metadata) {
            return Err(untrusted());
        }
    }
    if !fs::metadata(path)?.is_file() {
        return Err(untrusted());
    }
    Ok(())
}

fn untrusted() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "managed file must be root-owned, outside projects, without symlinks or writable ancestors",
    )
}

pub(crate) fn hash_file(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

/// The installer's two-entry manifest contains labels, never executable paths.
pub(crate) fn compare_manifest(
    path: &Path,
    binary_hash: &str,
    policy_hash: &str,
) -> io::Result<()> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take(1025).read_to_end(&mut bytes)?;
    if bytes.len() > 1024 {
        return Err(invalid_manifest());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| invalid_manifest())?;
    let mut binary = None;
    let mut policy = None;
    for line in text.lines() {
        let Some((hash, label)) = line.split_once("  ") else {
            return Err(invalid_manifest());
        };
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(invalid_manifest());
        }
        let slot = match label {
            "daguard" => &mut binary,
            "policy.json" => &mut policy,
            _ => return Err(invalid_manifest()),
        };
        if slot.replace(hash).is_some() {
            return Err(invalid_manifest());
        }
    }
    match (binary, policy) {
        (Some(binary), Some(policy))
            if binary.eq_ignore_ascii_case(binary_hash)
                && policy.eq_ignore_ascii_case(policy_hash) =>
        {
            Ok(())
        }
        (Some(_), Some(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "installed binary or policy checksum mismatch",
        )),
        _ => Err(invalid_manifest()),
    }
}

fn invalid_manifest() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid installation checksum manifest",
    )
}

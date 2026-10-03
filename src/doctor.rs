//! Read-only installation diagnostics for operators.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use crate::adapters::{codex, cursor, opencode};
use crate::audit;
use crate::platform;
use crate::policy::{Policy, PolicyKind};
use crate::project;

#[derive(Default)]
pub(crate) struct DoctorOptions {
    pub(crate) policy: Option<PathBuf>,
    pub(crate) integrity_manifest: Option<PathBuf>,
    pub(crate) managed: bool,
    pub(crate) audit_log: Option<PathBuf>,
    pub(crate) codex_hooks: Option<PathBuf>,
    pub(crate) cursor_hooks: Option<PathBuf>,
    pub(crate) opencode_config: Option<PathBuf>,
}

pub(crate) struct DoctorReport {
    pub(crate) lines: Vec<String>,
    pub(crate) has_errors: bool,
}

pub(crate) fn diagnose(options: &DoctorOptions) -> DoctorReport {
    let mut lines = Vec::new();
    lines.push(format!("[OK] {}", crate::version::summary()));

    let executable = env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| error.to_string());
    match &executable {
        Ok(path) => {
            lines.push(format!("[OK] binary path: {}", path.display()));
            warn_if_project_path(&mut lines, "binary", path);
        }
        Err(error) => lines.push(format!("[WARN] binary path unavailable: {error}")),
    }

    let policy = options.policy.clone().or_else(default_policy_path);
    match &policy {
        Some(path) => inspect_policy(&mut lines, path),
        None => lines.push(
            "[WARN] organization policy not found in a standard location; pass --policy PATH"
                .to_owned(),
        ),
    }

    if options.managed && policy.is_none() {
        lines.push("[ERROR] managed organization policy is missing".to_owned());
    }
    if options.managed && executable.is_err() {
        lines.push("[ERROR] managed binary path is unavailable".to_owned());
    }
    if let (Ok(binary), Some(policy)) = (&executable, &policy) {
        inspect_integrity(&mut lines, options, binary, policy);
    }

    let audit_log = options.audit_log.clone().or_else(default_audit_path);
    match audit_log {
        Some(path) => inspect_audit_destination(&mut lines, &path),
        None => lines.push("[WARN] audit destination unavailable: HOME is not set".to_owned()),
    }

    if platform::is_wsl() {
        lines.push("[OK] WSL environment detected".to_owned());
    } else {
        lines.push("[INFO] WSL environment not detected".to_owned());
    }
    match platform::find_executable("ddev") {
        Some(path) => lines.push(format!("[OK] ddev available: {}", path.display())),
        None => lines.push("[WARN] ddev not found on PATH (not required by daguard)".to_owned()),
    }

    inspect_integration(
        &mut lines,
        "Codex",
        options
            .codex_hooks
            .clone()
            .or_else(|| home_join(".codex/hooks.json")),
        |bytes| codex::validate_hooks_config(bytes).map_err(|error| error.to_string()),
    );
    inspect_integration(
        &mut lines,
        "Cursor",
        options
            .cursor_hooks
            .clone()
            .or_else(|| home_join(".cursor/hooks.json")),
        |bytes| cursor::validate_hooks_config(bytes).map_err(|error| error.to_string()),
    );
    inspect_integration(
        &mut lines,
        "OpenCode",
        options
            .opencode_config
            .clone()
            .or_else(|| home_join(".config/opencode/opencode.json")),
        |bytes| opencode::validate_installed_config(bytes).map_err(|error| error.to_string()),
    );
    let has_errors = lines.iter().any(|line| line.starts_with("[ERROR]"));
    DoctorReport { lines, has_errors }
}

fn inspect_integrity(
    lines: &mut Vec<String>,
    options: &DoctorOptions,
    binary: &Path,
    policy: &Path,
) {
    if options.managed {
        for (label, path) in [("binary", binary), ("mandatory policy", policy)] {
            if let Err(error) = crate::integrity::managed_path(path) {
                lines.push(format!("[ERROR] {label} trust check failed: {error}"));
            }
        }
    }
    let binary_hash = crate::integrity::hash_file(binary);
    let policy_hash = crate::integrity::hash_file(policy);
    if let Ok(hash) = &binary_hash {
        lines.push(format!("[OK] binary SHA-256: {hash}"));
    }
    let manifest = options
        .integrity_manifest
        .clone()
        .unwrap_or_else(|| policy.with_file_name("SHA256SUMS"));
    if !manifest.exists() && options.integrity_manifest.is_none() {
        lines.push("[WARN] installation checksum manifest not found; fingerprints do not authenticate files".to_owned());
        return;
    }
    if options.managed
        && let Err(error) = crate::integrity::managed_path(&manifest)
    {
        lines.push(format!(
            "[ERROR] checksum manifest trust check failed: {error}"
        ));
    }
    let result = binary_hash.and_then(|binary_hash| {
        policy_hash.and_then(|policy_hash| {
            crate::integrity::compare_manifest(&manifest, &binary_hash, &policy_hash)
        })
    });
    match result {
        Ok(()) => {
            lines.push("[OK] binary and policy checksums match installation metadata".to_owned());
        }
        Err(error) => lines.push(format!(
            "[ERROR] installation integrity check failed: {error}"
        )),
    }
}

fn inspect_policy(lines: &mut Vec<String>, path: &Path) {
    lines.push(format!(
        "[INFO] organization policy path: {}",
        path.display()
    ));
    match fs::File::open(path).and_then(|file| {
        use std::io::Read;
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
        Ok(bytes)
    }) {
        Ok(bytes) => {
            lines.push(format!("[OK] policy SHA-256: {}", audit::sha256(&bytes)));
            match Policy::from_slice(&bytes, PolicyKind::Organization) {
                Ok(policy) => {
                    lines.push("[OK] organization policy schema is valid".to_owned());
                    lines.push(if policy.audit_only() {
                        "[WARN] mode: audit-only candidate rules; mandatory protections remain enforced"
                    } else {
                        "[INFO] mode: enforcement"
                    }.to_owned());
                }
                Err(error) => {
                    lines.push(format!("[ERROR] organization policy is invalid: {error}"));
                }
            }
            warn_if_project_path(lines, "mandatory policy", path);
        }
        Err(error) => lines.push(format!(
            "[ERROR] organization policy is unreadable: {error}"
        )),
    }
}

fn inspect_audit_destination(lines: &mut Vec<String>, path: &Path) {
    if let Ok(metadata) = fs::metadata(path) {
        if !metadata.is_file() {
            lines.push(format!(
                "[WARN] audit destination is not a regular file: {}",
                path.display()
            ));
            return;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode() & 0o077 != 0 {
                lines.push(format!(
                    "[WARN] audit file permits group or other access: {}",
                    path.display()
                ));
                return;
            }
        }
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    match fs::metadata(parent) {
        Ok(metadata) if metadata.is_dir() && !metadata.permissions().readonly() => lines.push(
            format!("[OK] audit directory is writable by mode: {}", parent.display()),
        ),
        Ok(_) => lines.push(format!(
            "[WARN] audit directory is not a writable directory: {}",
            parent.display()
        )),
        Err(error) => lines.push(format!(
            "[WARN] audit directory is unavailable (create it before enabling logging): {} ({error})",
            parent.display()
        )),
    }
}

fn inspect_integration<F>(lines: &mut Vec<String>, name: &str, path: Option<PathBuf>, validate: F)
where
    F: FnOnce(&[u8]) -> Result<(), String>,
{
    let Some(path) = path else {
        lines.push(format!(
            "[WARN] {name} hook path unavailable: HOME is not set"
        ));
        return;
    };
    match fs::read(&path) {
        Ok(bytes) => match validate(&bytes) {
            Ok(()) => lines.push(format!("[OK] {name} hook valid: {}", path.display())),
            Err(error) => lines.push(format!("[WARN] {name} hook invalid: {error}")),
        },
        Err(_) => lines.push(format!("[WARN] {name} hook not found: {}", path.display())),
    }
}

fn warn_if_project_path(lines: &mut Vec<String>, label: &str, path: &Path) {
    if project::is_inside_project(path) {
        lines.push(format!(
            "[WARN] {label} is inside an agent-writable project repository"
        ));
    }
}

fn default_policy_path() -> Option<PathBuf> {
    let managed = PathBuf::from("/etc/daguard/policy.json");
    if managed.exists() {
        return Some(managed);
    }
    let user = home_join(".config/daguard/policy.json")?;
    user.exists().then_some(user)
}

fn default_audit_path() -> Option<PathBuf> {
    home_join(".local/state/daguard/audit.jsonl")
}

fn home_join(relative: &str) -> Option<PathBuf> {
    env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(relative))
}

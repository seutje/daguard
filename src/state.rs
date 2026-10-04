//! Metadata-only session taint persistence.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use crate::model::{SensitivityCategory, merge_categories};
use crate::sensitivity::SourceClassification;

const STATE_SCHEMA_VERSION: u16 = 1;
const IDLE_TTL_SECONDS: u64 = 24 * 60 * 60;
const MAX_LIFETIME_SECONDS: u64 = 7 * 24 * 60 * 60;
const MAX_STATE_BYTES: usize = 64 * 1024;
const MAX_SOURCES: usize = 32;
const CLEANUP_LIMIT: usize = 32;
const LOCK_ATTEMPTS: usize = 40;
const LOCK_RETRY: Duration = Duration::from_millis(5);
const STALE_LOCK_SECONDS: u64 = 30;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SessionTaint {
    schema: u16,
    pub(crate) session: String,
    pub(crate) agent: String,
    created_unix_seconds: u64,
    updated_unix_seconds: u64,
    expires_unix_seconds: u64,
    pub(crate) categories: BTreeSet<SensitivityCategory>,
    sources: Vec<StoredSource>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StoredSource {
    source_id: String,
    resource_kind: String,
    resource: String,
    categories: BTreeSet<SensitivityCategory>,
}

pub(crate) struct StateStore {
    root: PathBuf,
}

impl StateStore {
    pub(crate) fn open(path: Option<&Path>) -> Result<Self, StateError> {
        let root = path.map_or_else(default_state_root, Path::to_path_buf);
        if !root.is_absolute() {
            return Err(StateError::Invalid("state directory must be absolute"));
        }
        #[cfg(not(unix))]
        fs::create_dir_all(&root).map_err(StateError::Io)?;
        #[cfg(unix)]
        {
            crate::platform::initialize_state_directory(&root).map_err(StateError::Io)?;
            let metadata = fs::symlink_metadata(&root).map_err(StateError::Io)?;
            if metadata.file_type().is_symlink()
                || !metadata.is_dir()
                || metadata.permissions().mode() & 0o077 != 0
                || metadata.uid() != effective_user_id()
            {
                return Err(StateError::Invalid(
                    "state directory must be an owner-only directory",
                ));
            }
        }
        let store = Self { root };
        store.cleanup_expired()?;
        Ok(store)
    }

    pub(crate) fn load(
        &self,
        agent: &str,
        session_id: &str,
    ) -> Result<Option<SessionTaint>, StateError> {
        let now = now_seconds()?;
        let path = self.state_path(agent, session_id);
        let _lock = Self::lock(&path)?;
        let Some(state) = read_state(&path)? else {
            return Ok(None);
        };
        validate_state(&state, agent, session_id)?;
        if expired(&state, now) {
            remove_if_exists(&path)?;
            return Ok(None);
        }
        Ok(Some(state))
    }

    pub(crate) fn merge(
        &self,
        agent: &str,
        session_id: &str,
        classifications: &[SourceClassification],
    ) -> Result<Option<SessionTaint>, StateError> {
        if classifications.is_empty() {
            return self.load(agent, session_id);
        }
        if classifications.iter().any(|classification| {
            let resource_valid = classification.resource == "metadata-only"
                || (classification.resource.starts_with("sha256:")
                    && classification.resource.len() == 71);
            classification.source_id.is_empty()
                || classification.source_id.len() > 128
                || !classification.source_id.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                })
                || !resource_valid
        }) {
            return Err(StateError::Invalid(
                "source classification metadata is invalid",
            ));
        }
        let now = now_seconds()?;
        let path = self.state_path(agent, session_id);
        let _lock = Self::lock(&path)?;
        let mut state = match read_state(&path)? {
            Some(state) if !expired(&state, now) => {
                validate_state(&state, agent, session_id)?;
                state
            }
            Some(_) => {
                remove_if_exists(&path)?;
                new_state(agent, session_id, now)
            }
            None => new_state(agent, session_id, now),
        };
        for classification in classifications {
            merge_categories(
                &mut state.categories,
                classification.categories.iter().copied(),
            );
            let source = StoredSource {
                source_id: classification.source_id.clone(),
                resource_kind: classification.resource_kind.clone(),
                resource: classification.resource.clone(),
                categories: classification.categories.clone(),
            };
            if !state.sources.contains(&source) {
                if state.sources.len() == MAX_SOURCES {
                    state.sources.remove(0);
                }
                state.sources.push(source);
            }
        }
        state.updated_unix_seconds = now;
        state.expires_unix_seconds = idle_expiry(state.created_unix_seconds, now);
        write_state(&path, &state)?;
        Ok(Some(state))
    }

    fn state_path(&self, agent: &str, session_id: &str) -> PathBuf {
        self.root.join(format!(
            "session-{}.json",
            digest(&format!("{agent}\0{session_id}"))
        ))
    }

    fn lock(state_path: &Path) -> Result<LockGuard, StateError> {
        let lock_path = state_path.with_extension("lock");
        for _ in 0..LOCK_ATTEMPTS {
            let mut options = OpenOptions::new();
            options.create_new(true).write(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(&lock_path) {
                Ok(mut file) => {
                    writeln!(file, "{}", std::process::id()).map_err(StateError::Io)?;
                    return Ok(LockGuard { path: lock_path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(&lock_path)? {
                        remove_if_exists(&lock_path)?;
                        continue;
                    }
                    thread::sleep(LOCK_RETRY);
                }
                Err(error) => return Err(StateError::Io(error)),
            }
        }
        Err(StateError::Invalid("session state is locked"))
    }

    fn cleanup_expired(&self) -> Result<(), StateError> {
        let now = now_seconds()?;
        for entry in fs::read_dir(&self.root)
            .map_err(StateError::Io)?
            .take(CLEANUP_LIMIT)
        {
            let entry = entry.map_err(StateError::Io)?;
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            match read_state(&path) {
                Ok(Some(state)) if expired(&state, now) => remove_if_exists(&path)?,
                Ok(_) | Err(_) => {
                    // A corrupt state file is not silently deleted: a matching
                    // session must fail closed when it attempts to load it.
                }
            }
        }
        Ok(())
    }
}

fn new_state(agent: &str, session_id: &str, now: u64) -> SessionTaint {
    SessionTaint {
        schema: STATE_SCHEMA_VERSION,
        session: format!("sha256:{}", digest(session_id)),
        agent: known_agent(agent).to_owned(),
        created_unix_seconds: now,
        updated_unix_seconds: now,
        expires_unix_seconds: idle_expiry(now, now),
        categories: BTreeSet::new(),
        sources: Vec::new(),
    }
}

fn validate_state(state: &SessionTaint, agent: &str, session_id: &str) -> Result<(), StateError> {
    let mut source_categories = BTreeSet::new();
    for source in &state.sources {
        source_categories.extend(source.categories.iter().copied());
        if source.source_id.is_empty()
            || source.resource_kind.is_empty()
            || !(source.resource == "metadata-only"
                || (source.resource.starts_with("sha256:") && source.resource.len() == 71))
        {
            return Err(StateError::Invalid("session state is invalid"));
        }
    }
    if state.schema != STATE_SCHEMA_VERSION
        || state.session != format!("sha256:{}", digest(session_id))
        || state.agent != known_agent(agent)
        || state.sources.len() > MAX_SOURCES
        || state.created_unix_seconds > state.updated_unix_seconds
        || state.updated_unix_seconds > state.expires_unix_seconds
        || state.expires_unix_seconds
            > idle_expiry(state.created_unix_seconds, state.updated_unix_seconds)
        || state.categories.is_empty()
        || !source_categories.is_subset(&state.categories)
    {
        return Err(StateError::Invalid("session state is invalid"));
    }
    Ok(())
}

fn read_state(path: &Path) -> Result<Option<SessionTaint>, StateError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StateError::Io(error)),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_STATE_BYTES as u64
    {
        return Err(StateError::Invalid("session state file is invalid"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(StateError::Invalid("session state file is not owner-only"));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(StateError::Io)?
        .take(MAX_STATE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(StateError::Io)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(StateError::Invalid("session state file is too large"));
    }
    crate::json::preflight(&bytes, MAX_STATE_BYTES).map_err(StateError::Json)?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(StateError::Json)
}

fn write_state(path: &Path, state: &SessionTaint) -> Result<(), StateError> {
    let bytes = serde_json::to_vec(state).map_err(StateError::Json)?;
    if bytes.len() > MAX_STATE_BYTES {
        return Err(StateError::Invalid("session state exceeds its size limit"));
    }
    let temporary = path.with_extension(format!("tmp-{}-{}", std::process::id(), now_seconds()?));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary).map_err(StateError::Io)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        let _ = fs::remove_file(&temporary);
        return Err(StateError::Io(error));
    }
    #[cfg(windows)]
    remove_if_exists(path)?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(StateError::Io(error));
    }
    Ok(())
}

fn lock_is_stale(path: &Path) -> Result<bool, StateError> {
    let modified = fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_err(StateError::Io)?;
    Ok(SystemTime::now()
        .duration_since(modified)
        .is_ok_and(|age| age.as_secs() >= STALE_LOCK_SECONDS))
}

fn expired(state: &SessionTaint, now: u64) -> bool {
    now >= state.expires_unix_seconds
        || now.saturating_sub(state.created_unix_seconds) >= MAX_LIFETIME_SECONDS
}

fn idle_expiry(created: u64, now: u64) -> u64 {
    now.saturating_add(IDLE_TTL_SECONDS)
        .min(created.saturating_add(MAX_LIFETIME_SECONDS))
}

fn now_seconds() -> Result<u64, StateError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| StateError::Invalid("system clock is before the Unix epoch"))
}

fn digest(value: &str) -> String {
    let bytes = Sha256::digest(value.as_bytes());
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn known_agent(agent: &str) -> &'static str {
    match agent {
        "codex" => "codex",
        "cursor" => "cursor",
        "opencode" => "opencode",
        _ => "unknown",
    }
}

fn default_state_root() -> PathBuf {
    // Use an identity-scoped owner-only directory. A caller that wants state
    // under XDG_RUNTIME_DIR can pass it explicitly with `--state-dir`; that
    // environment path is not guaranteed writable in sandboxed agent hosts.
    let temporary = std::env::temp_dir();
    // Resolve the OS-selected temporary directory (e.g. macOS /var -> /private/var).
    // Explicit state roots are never canonicalized or allowed to follow symlinks.
    let temporary = fs::canonicalize(&temporary).unwrap_or(temporary);
    temporary.join(format!("daguard-state-{}", effective_user_id()))
}

#[cfg(unix)]
fn effective_user_id() -> u32 {
    // SAFETY: geteuid has no arguments or memory preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
fn effective_user_id() -> u32 {
    let identity = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_owned());
    let hash = Sha256::digest(identity.as_bytes());
    u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
}

fn remove_if_exists(path: &Path) -> Result<(), StateError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(StateError::Io(error)),
    }
}

struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Debug)]
pub(crate) enum StateError {
    Io(std::io::Error),
    Json(serde_json::Error),
    Invalid(&'static str),
}

impl fmt::Display for StateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "session state I/O failed: {error}"),
            Self::Json(error) => write!(formatter, "session state JSON is invalid: {error}"),
            Self::Invalid(message) => formatter.write_str(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use super::{SessionTaint, StateStore};
    use crate::model::SensitivityCategory;
    use crate::sensitivity::SourceClassification;

    fn source(resource: &str, category: SensitivityCategory) -> SourceClassification {
        SourceClassification {
            source_id: "synthetic.source".to_owned(),
            resource_kind: "file".to_owned(),
            resource: resource.to_owned(),
            categories: BTreeSet::from([category]),
        }
    }

    #[cfg(unix)]
    #[test]
    fn a22_rejected_symlinks_do_not_change_target_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("daguard-state-symlink-{}", std::process::id()));
        fs::create_dir_all(root.join("target")).unwrap();
        fs::set_permissions(root.join("target"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink(root.join("target"), root.join("link")).unwrap();
        assert!(StateStore::open(Some(&root.join("link"))).is_err());
        assert_eq!(
            fs::metadata(root.join("target"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        assert!(StateStore::open(Some(&root.join("link/child"))).is_err());
        assert!(!root.join("target/child").exists());
        let store = StateStore::open(Some(&root.join("normal/nested"))).unwrap();
        assert_eq!(
            fs::metadata(&store.root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn persists_metadata_only_and_isolates_sessions_and_agents() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "daguard-state-test-{}-{}",
                std::process::id(),
                super::now_seconds().unwrap()
            ));
        let store = StateStore::open(Some(&root)).unwrap();
        let canary = "SYNTHETIC_PHASE14_SECRET_CANARY";
        store
            .merge(
                "codex",
                "session-a",
                &[source(
                    &format!("sha256:{}", super::digest(canary)),
                    SensitivityCategory::Credential,
                )],
            )
            .unwrap();
        assert!(store.load("codex", "session-a").unwrap().is_some());
        assert!(store.load("codex", "session-b").unwrap().is_none());
        assert!(store.load("cursor", "session-a").unwrap().is_none());
        for entry in fs::read_dir(&root).unwrap() {
            let bytes = fs::read(entry.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains(canary));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expired_state_is_removed_after_restart() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "daguard-state-expiry-{}-{}",
                std::process::id(),
                super::now_seconds().unwrap()
            ));
        let store = StateStore::open(Some(&root)).unwrap();
        store
            .merge(
                "codex",
                "expired",
                &[source(
                    &format!("sha256:{}", super::digest("synthetic")),
                    SensitivityCategory::PrivateContent,
                )],
            )
            .unwrap();
        let path = store.state_path("codex", "expired");
        let mut state: SessionTaint = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        state.expires_unix_seconds = 0;
        super::write_state(&path, &state).unwrap();
        drop(store);

        let restarted = StateStore::open(Some(&root)).unwrap();
        assert!(restarted.load("codex", "expired").unwrap().is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_updates_merge_without_losing_categories() {
        let root = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!(
                "daguard-state-concurrency-{}-{}",
                std::process::id(),
                super::now_seconds().unwrap()
            ));
        let categories = [
            SensitivityCategory::Credential,
            SensitivityCategory::PersonalData,
            SensitivityCategory::FinancialData,
            SensitivityCategory::CustomerData,
        ];
        let handles = categories.map(|category| {
            let root = root.clone();
            std::thread::spawn(move || {
                let store = StateStore::open(Some(&root)).unwrap();
                store
                    .merge(
                        "codex",
                        "concurrent",
                        &[source(
                            &format!("sha256:{}", super::digest(&format!("{category:?}"))),
                            category,
                        )],
                    )
                    .unwrap();
            })
        });
        for handle in handles {
            handle.join().unwrap();
        }
        let state = StateStore::open(Some(&root))
            .unwrap()
            .load("codex", "concurrent")
            .unwrap()
            .unwrap();
        assert!(
            categories
                .iter()
                .all(|category| state.categories.contains(category))
        );
        fs::remove_dir_all(root).unwrap();
    }
}

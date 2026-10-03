//! Build and release identity compiled into the executable.

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const TARGET: &str = env!("DAGUARD_BUILD_TARGET");
pub(crate) const PROFILE: &str = env!("DAGUARD_BUILD_PROFILE");
pub(crate) const GIT_SHA: &str = env!("DAGUARD_BUILD_GIT_SHA");
pub(crate) const RUSTC_VERSION: &str = env!("DAGUARD_BUILD_RUSTC_VERSION");
pub(crate) const CARGO_LOCK_SHA256: &str = env!("DAGUARD_BUILD_CARGO_LOCK_SHA256");
pub(crate) const PROVENANCE: &str = env!("DAGUARD_BUILD_PROVENANCE");

pub(crate) fn summary() -> String {
    format!("daguard {VERSION} ({TARGET})")
}

pub(crate) fn details() -> String {
    format!(
        "{}\nprofile: {PROFILE}\nrustc: {RUSTC_VERSION}\ngit: {GIT_SHA}\nCargo.lock SHA-256: {CARGO_LOCK_SHA256}\nprovenance: {PROVENANCE}",
        summary()
    )
}

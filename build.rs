use std::env;

fn main() {
    println!("cargo:rerun-if-env-changed=DAGUARD_GIT_SHA");
    println!("cargo:rerun-if-env-changed=DAGUARD_RUSTC_VERSION");
    println!("cargo:rerun-if-env-changed=DAGUARD_CARGO_LOCK_SHA256");
    println!("cargo:rerun-if-env-changed=DAGUARD_PROVENANCE");

    export("DAGUARD_BUILD_TARGET", env::var("TARGET").ok());
    export("DAGUARD_BUILD_PROFILE", env::var("PROFILE").ok());
    export("DAGUARD_BUILD_GIT_SHA", env::var("DAGUARD_GIT_SHA").ok());
    export(
        "DAGUARD_BUILD_RUSTC_VERSION",
        env::var("DAGUARD_RUSTC_VERSION").ok(),
    );
    export(
        "DAGUARD_BUILD_CARGO_LOCK_SHA256",
        env::var("DAGUARD_CARGO_LOCK_SHA256").ok(),
    );
    export(
        "DAGUARD_BUILD_PROVENANCE",
        env::var("DAGUARD_PROVENANCE").ok(),
    );
}

fn export(name: &str, value: Option<String>) {
    let value = value
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env={name}={value}");
}

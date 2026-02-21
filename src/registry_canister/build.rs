use std::process::Command;

fn main() {
    let git_commit = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=GIT_COMMIT={}", git_commit);

    // Keep deterministic-ish in local builds; CI can override by env injection if desired.
    println!("cargo:rustc-env=BUILD_TS={}", "2026-02-21");
}

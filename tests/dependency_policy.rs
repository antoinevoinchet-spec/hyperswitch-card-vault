//! The dependency policy of threat T31, read as text: `deny.toml` and the CI workflow that runs
//! cargo-deny. These tests fail if the policy is weakened or the job stops running on pull
//! requests, on `main` or weekly. They do not run cargo-deny itself. See
//! `docs/superpowers/specs/2026-11-25-untested-controls-design.md` (D6).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

fn read(path: &str) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|_| panic!("read {path}"))
}

/// The lines of the `[name]` section of a TOML file, comments and blank lines removed.
fn section(text: &str, name: &str) -> Vec<String> {
    let header = format!("[{name}]");
    text.lines()
        .skip_while(|line| line.trim() != header)
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .map(|line| line.split('#').next().unwrap_or("").trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

/// The quoted strings of the array that starts at `key = [` in `text`.
fn array(text: &str, key: &str) -> Vec<String> {
    let start = text
        .find(&format!("{key} = ["))
        .unwrap_or_else(|| panic!("no array {key}"));
    let body = &text[start..];
    let body = &body[..body.find(']').expect("array end")];
    body.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_string)
        .collect()
}

#[test]
fn deny_policy_checks_every_feature_and_every_source() {
    let deny = read("deny.toml");
    assert_eq!(section(&deny, "graph"), ["all-features = true"]);

    let sources = section(&deny, "sources");
    for rule in [
        r#"unknown-registry = "deny""#,
        r#"unknown-git = "deny""#,
        r#"required-git-spec = "tag""#,
    ] {
        assert!(sources.iter().any(|line| line == rule), "sources: {rule}");
    }
    assert_eq!(
        array(&deny, "allow-registry"),
        ["https://github.com/rust-lang/crates.io-index"]
    );
    assert_eq!(
        array(&deny, "allow-git"),
        [
            "https://github.com/juspay/hyperswitch",
            "https://github.com/juspay/framework-libs-rs"
        ]
    );
}

#[test]
fn deny_policy_keeps_the_license_list() {
    let deny = read("deny.toml");
    assert_eq!(
        array(&deny, "allow"),
        [
            "MIT",
            "Apache-2.0",
            "Apache-2.0 WITH LLVM-exception",
            "Unicode-3.0",
            "ISC",
            "BSD-2-Clause",
            "BSD-3-Clause",
            "Zlib",
            "CC0-1.0",
            "MPL-2.0",
            "OpenSSL",
        ]
    );
    let licenses = section(&deny, "licenses");
    assert!(
        licenses.iter().all(|line| !line.starts_with("exceptions")
            && !line.starts_with("clarify")
            && !line.starts_with("unused-allowed-license")),
        "no license exception"
    );
}

#[test]
fn deny_policy_lists_each_vulnerability_exception_with_reason_and_expiry() {
    let deny = read("deny.toml");
    let entries: Vec<&str> = deny
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("{ id = "))
        .collect();
    assert!(!entries.is_empty(), "the exceptions are read");
    for entry in &entries {
        assert!(entry.contains("id = \"RUSTSEC-"), "named entry: {entry}");
        assert!(entry.contains("reason = \""), "reason: {entry}");
        assert!(entry.contains("expiry = \"2027-02-21\""), "expiry: {entry}");
    }
    let ignore_lines = section(&deny, "advisories")
        .iter()
        .filter(|line| line.contains("RUSTSEC-") || line.contains("GHSA-"))
        .count();
    assert_eq!(ignore_lines, entries.len(), "every exception has the form above");
    let section_text = section(&deny, "advisories").join("\n");
    for weakening in ["vulnerability", "notice", "db-urls", "git-fetch-with-cli = false"] {
        assert!(
            !section_text.contains(weakening),
            "no override of the default refusal: {weakening}"
        );
    }
}

#[test]
fn dependency_workflow_runs_on_every_pull_request_main_and_weekly() {
    let workflow = read(".github/workflows/dependencies.yml");
    let on: Vec<&str> = workflow
        .lines()
        .skip_while(|line| *line != "on:")
        .skip(1)
        .take_while(|line| line.is_empty() || line.starts_with(' ') || line.starts_with('#'))
        .collect();
    let on = on.join("\n");
    assert!(on.contains("\n  pull_request:") || on.starts_with("  pull_request:"), "pull_request");
    assert!(on.contains("  push:\n    branches:\n      - main"), "push to main");
    assert!(on.contains("  schedule:\n    - cron: "), "weekly schedule");
    assert!(
        !on.contains("paths") && !on.contains("branches-ignore"),
        "no filter that skips a pull request"
    );
    assert!(!workflow.contains("continue-on-error"), "a failure fails the job");
    assert!(!workflow.contains("if:"), "no step or job is skipped by a condition");
    assert!(
        workflow
            .lines()
            .any(|line| line.trim() == "run: cargo deny --locked check advisories licenses sources"),
        "the check runs on the three families"
    );
}

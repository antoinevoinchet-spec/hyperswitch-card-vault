# CLAUDE.md: study fork of hyperswitch-card-vault

Public, unofficial fork of `juspay/hyperswitch-card-vault`, maintained by `antoinevoinchet-spec` as a study project. This code is neither audited nor compliant, and must not be used in production.

## Rules

- **Cryptography**: never write any by hand. Use only recognised, maintained libraries, preferably those already in `Cargo.toml` (`ring`, `josekit`…). Cover every addition with tests, including at least one error case.
- **Juspay**: never write to `juspay/*`: no PR, issue, comment or discussion. Pushing to the `upstream` remote is disabled (`DISABLED`) and `gh repo set-default` points to `antoinevoinchet-spec/hyperswitch-card-vault`: change neither. Always pass `-R antoinevoinchet-spec/hyperswitch-card-vault` to `gh pr …` and `gh issue …` commands.
- **No compliance claim**: never describe the project as compliant (PCI DSS, GDPR or other), certified, audited or production-ready, whether in code, docs, commits or PRs.
- **Branches**: work on a branch (`feat/…`, `fix/…`, `chore/…`), never directly on `main`.
- **Test key**: the `master_key` in `config/development.toml`, `config/docker-configuration.toml` and `config/config.example.toml` is public, since it is in Juspay's git history. It is not a usable secret. Use it only for local tests and never print its value.
- **`.env` tracked by git**: a `.env` file is versioned at the root. Do not read or print it.
- **Apache-2.0 license**: list every file changed from the original in `README.md`, under "Changes from the original".
- **Language**: write this file and the rest of the repository in English: the `typos` spell check in CI only knows English and fails on other languages.

## Observed commands (20/11/2026, Rust 1.100.0, Mac M2 with 8 GB)

- Rust is installed by Homebrew. Since 24/11/2026, `~/.zprofile` puts it on the PATH of a login terminal opened after that date. The Claude Code shell does not read `~/.zprofile` (`cargo not found` on 25/11/2026), so before `cargo` in it, run `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"`.
- Build: `cargo build -j 4` → exit code 0, 9 min 20 s for a cold build.
- Tests: `cargo test -j 4` → exit code 0, 18 tests passed, without PostgreSQL or Redis.
- The original CI also runs `cargo nextest run --profile ci --all-features`, `cargo clippy --all-features --all-targets` and `cargo +nightly fmt --all --check`. These commands were not run here: nextest and the nightly toolchain are not installed.

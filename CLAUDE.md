# CLAUDE.md : fork d'étude de hyperswitch-card-vault

Fork public et non officiel de `juspay/hyperswitch-card-vault`, tenu par `antoinevoinchet-spec` comme projet d'étude. Ce code n'est ni audité ni conforme, et ne doit pas servir en production.

## Règles

- **Cryptographie** : n'en écris aucune à la main. Utilise uniquement des bibliothèques reconnues et maintenues, en priorité celles déjà présentes dans `Cargo.toml` (`ring`, `josekit`…). Couvre chaque ajout par des tests, dont au moins un cas d'erreur.
- **Juspay** : n'écris jamais vers `juspay/*`, ni PR, ni issue, ni commentaire, ni discussion. La poussée vers le remote `upstream` est désactivée (`DISABLED`) et `gh repo set-default` pointe sur `antoinevoinchet-spec/hyperswitch-card-vault` : ne change ni l'un ni l'autre. Passe toujours `-R antoinevoinchet-spec/hyperswitch-card-vault` aux commandes `gh pr …` et `gh issue …`.
- **Aucune affirmation de conformité** : ne décris jamais le projet comme conforme (PCI DSS, RGPD ou autre), certifié, audité ou prêt pour la production, ni dans le code, ni dans la doc, ni dans les commits, ni dans les PR.
- **Branches** : travaille sur une branche (`feat/…`, `fix/…`, `chore/…`), jamais directement sur `main`.
- **Clé de test** : le `master_key` présent dans `config/development.toml`, `config/docker-configuration.toml` et `config/config.example.toml` est public, puisqu'il est dans l'historique git de Juspay. Ce n'est pas un secret utilisable. Ne t'en sers que pour des tests locaux et n'affiche jamais sa valeur.
- **`.env` suivi par git** : un fichier `.env` est versionné à la racine. Ne le lis pas et ne l'affiche pas.
- **Licence Apache-2.0** : liste chaque fichier modifié par rapport à l'original dans `README.md`, sous « Changes from the original ».

## Commandes constatées (20/11/2026, Rust 1.100.0, Mac M2 avec 8 Go)

- Rust est installé par Homebrew mais absent du PATH. Avant `cargo`, lance `export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"`.
- Build : `cargo build -j 4` → code de sortie 0, 9 min 20 de compilation à froid.
- Tests : `cargo test -j 4` → code de sortie 0, 18 tests réussis, sans base PostgreSQL ni Redis.
- La CI d'origine lance aussi `cargo nextest run --profile ci --all-features`, `cargo clippy --all-features --all-targets` et `cargo +nightly fmt --all --check`. Ces commandes n'ont pas été lancées ici : nextest et la toolchain nightly ne sont pas installés.

# Contributing

Thanks for taking a look. The bar to land a change is mostly mechanical:

1. **Fork + branch** off `main`.
2. **Run the local checks** that CI runs:
   ```sh
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   ```
3. **Conventional Commits** for the commit message (`feat: …`, `fix: …`, `docs: …`, `refactor: …`).
4. **Open a PR** describing the *why* in 1–2 paragraphs. Tests for new behavior, please. Snapshots for new TUI screens.

## Repo layout

- `crates/jwt-core/` — pure library, no I/O. Anything testable lives here.
- `crates/jwt-tui/` — binary. CLI subcommands in `src/app/*_cmd.rs`, TUI screens in `src/ui/*_view.rs`.
- `docs/DECISIONS.md` — running log of non-trivial choices. Add an entry when you make one.

## Test conventions

- Property tests on `jwt-core` parsing + signing (`proptest`).
- Integration tests on the binary via `assert_cmd`.
- TUI render tests use `ratatui::backend::TestBackend` — assert "renders without panic at 80x24" at minimum.
- Snapshot tests via `insta` for stable views (avoid for visuals still in flux).

## Security issues

Do **not** open public issues for security flaws. Email kemal@kemalasliyuksek.com or use GitHub's private vulnerability reporting.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). Be kind.

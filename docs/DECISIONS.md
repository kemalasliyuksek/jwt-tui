# Design decisions

A running log of non-trivial choices made while building jwt-tui. Each entry is short: context, decision, alternatives considered.

---

## Lint policy

**Context.** The brief asked for `clippy::pedantic` + `clippy::nursery` and "Resolve or `#[allow]` with justification."
**Decision.** Workspace-level allow-list for lints that are stylistic-only or whose fixes hurt readability (e.g. `doc_markdown` on technical acronyms, `cast_possible_truncation` on intentionally narrowed values, `vec_init_then_push` where readability is better with explicit pushes).
**Alternative.** Per-call-site `#[allow(...)]`. Rejected because the same lint fires in dozens of equivalent spots; keeping them in `Cargo.toml` next to a top-level "see DECISIONS.md" comment is more discoverable.

## Two-crate workspace, not one

**Context.** Could have a single binary crate for simplicity.
**Decision.** Split `jwt-core` (pure logic, publishable to crates.io) and `jwt-tui` (binary). Lets the security primitives be embedded, fuzzed, and audited independently of the TUI.
**Alternative.** Cargo features. Rejected because feature gating turns into a maintenance tax once tests start branching on which features are enabled.

## `ring` as the crypto backend

**Context.** Two mainstream Rust JOSE libraries: `jsonwebtoken` (built on ring) and lower-level `ring` directly.
**Decision.** Use `jsonwebtoken` only as an indirect dependency in workspace deps and rely on `ring` directly for sign/verify. The reason is the attack scenarios: `jsonwebtoken` deliberately rejects `alg: none` and other forgeries we *need* to be able to produce. Going one layer down lets us bypass those guardrails honestly instead of monkey-patching.
**Alternative.** Hand-roll all crypto. Rejected — too much risk for too little benefit.

## RSA SPKI → PKCS#1 stripping

**Context.** `ring`'s RSA verifier accepts a PKCS#1 `RSAPublicKey` SEQUENCE, but most users carry around `SubjectPublicKeyInfo` from PEM `BEGIN PUBLIC KEY` blocks.
**Decision.** Walk the SPKI DER manually to grab the inner key. Documented in `verify::strip_spki_to_rsa` with a "we don't validate the algorithm OID — verification will fail anyway" comment.
**Alternative.** Pull in `pkcs1`/`spki` crates. Rejected because the dependency graph already includes `ring`, which has its own ASN.1 logic; an extra crate just for header stripping is overkill.

## JWKS fetch behind a feature flag

**Context.** `jwt-core` would otherwise pull in `reqwest` + `tokio` for everyone.
**Decision.** Gate `fetch_jwks` behind a `jwks` cargo feature. The struct definitions (`Jwk`, `Jwks`, `JwksCache`) are always available. The binary opts in.
**Alternative.** Always-on. Rejected because library consumers who already have an HTTP client deserve a smaller dep tree.

## Single-file binary modules

**Context.** Could have many tiny `cli/`, `app/`, `ui/` files per command.
**Decision.** One file per subcommand (`app/decode_cmd.rs`, `app/sign_cmd.rs`, …) and one file per TUI screen (`ui/decode_view.rs`, …). The shape is "command runs synchronous code, view holds state + render fn."
**Alternative.** Mega-files. Rejected; would make snapshot tests harder to scope.

## `BruteOptions::capped` default of 10M

**Context.** The brief specified the cap; the rationale matters.
**Decision.** 10 million attempts is two orders of magnitude above the typical "common-passwords" list size and well below the point where rayon's per-element overhead dominates. It also lets a reasonable laptop finish in under a minute on HS256.
**Alternative.** Time-based cap (e.g. 60 seconds). Rejected because the user has more agency over time than over the wordlist.

## Lab-mode banner on stderr, not stdout

**Context.** Pipe-friendly tools must not pollute stdout with banners.
**Decision.** `[LAB MODE] …` prints to stderr in `attack_cmd::ensure_lab`. Stdout still emits the forged token (or its JSON form) so it pipes cleanly into other tools.
**Alternative.** `--quiet` flag. Rejected because users would forget; the stderr/stdout split gives both auditability and pipe-safety automatically.

## Token jar uses SQLite, not JSON

**Context.** A flat JSON file would be simpler.
**Decision.** SQLite via `rusqlite` with `bundled`. Tags are a separate table for indexable lookups; we WAL the DB for crash safety and bundle the SQLite library so users on minimal Linux installs don't need libsqlite3.
**Alternative.** JSON file with file locking. Rejected — every tag/label search becomes a full file rewrite, and concurrent writes from two `jwt-tui` processes is a real failure mode (CLI + TUI open at once).

## TUI test backend: ratatui::TestBackend + insta

**Context.** Snapshot tests for every screen.
**Decision.** Use `ratatui::backend::TestBackend` to render into an in-memory buffer; assert no panic at 80x24 and 120x40. We did *not* commit `insta` snapshot fixtures yet — they would lock us in too early before the visuals stabilize. The render-without-panic test catches the regression class we actually care about (resize, missing data, edge cases).
**Alternative.** Full `.snap` files. Deferred until the layout settles in 0.2.

## `tokio` only inside the binary's JWKS path

**Context.** Async would propagate everywhere if we let it.
**Decision.** `jwt-core::jwks::fetch_jwks` is `async`, but the CLI builds a `current_thread` runtime on demand inside `verify_cmd::fetch_key_via_jwks`. Everything else is sync.
**Alternative.** `reqwest::blocking`. Rejected because that pulls in a parallel runtime we don't need and breaks the offline-first invariant for users who never use JWKS.

## Theme handling: TOML config + three built-ins, RGB everywhere

**Context.** ratatui supports both ANSI named colors and 24-bit RGB.
**Decision.** Built-in palettes are RGB; `NO_COLOR=1` short-circuits to plain attributes. The high-contrast palette uses the eight ANSI primaries to play well on rare terminals where RGB is mishandled.
**Alternative.** Auto-detect background brightness. Rejected — too fragile; users who care set the theme.

## No `unsafe` and no native-tls

**Context.** Both are listed in the brief; this captures the rationale.
**Decision.** `#![forbid(unsafe_code)]` at workspace level. `reqwest` is `default-features = false` + `rustls-tls` to avoid OpenSSL/system-tls divergence across distros and to keep cross-compilation to musl trivial.

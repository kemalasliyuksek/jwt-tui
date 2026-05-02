# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial public release.
- `jwt-core` library: parse, sign (HS/RS/ES/EdDSA/none), verify with structured outcomes, JWKS support behind the `jwks` feature.
- `jwt-tui` binary: TUI with decode / sign / verify / attack / jar screens, plus matching CLI subcommands.
- Attack lab: `alg:none` forge, HS/RS confusion, `kid` injection templates, HS secret brute force, `jku`/`x5u` redirection helper.
- SQLite token jar with labels, tags, notes.
- Shell completion + man-page generation via `clap_complete` / `clap_mangen`.
- Conventional Commits + dual MIT/Apache-2.0 license.

[Unreleased]: https://github.com/kemalasliyuksek/jwt-tui/compare/v0.0.0...HEAD

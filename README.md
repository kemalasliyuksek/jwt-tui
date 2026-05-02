# jwt-tui

Offline-first terminal app for inspecting, signing, verifying, and security-testing JSON Web Tokens.

> **Status**: 0.1 — feature-complete for the spec, every test green, but the project is young. Treat it like a fresh tool: useful, but verify against your reference implementation before you trust it in CI.

## Highlights

- **Decode** any JWT — three-pane TUI shows token, header, payload; humanized `iat`/`exp`/`nbf`; flags dangerous headers (`alg=none`, `jku`, `x5u`, suspicious `kid`).
- **Sign / forge** with HS{256,384,512}, RS{256,384,512}, ES{256,384}, EdDSA, or `none`. Inline secrets, `@file`, `env:VAR`, or ephemeral keypair generation.
- **Verify** against an HMAC secret, a public key file, or a JWKS URL — structured pass/fail with reason codes (`signature_invalid`, `expired`, `algorithm_mismatch`, …).
- **Attack lab** (gated behind `--lab`):
  - `alg-none` forge — every capitalization variant.
  - HS/RS confusion — re-sign with a public-key file as the HMAC secret.
  - `kid` injection templates — path traversal, SQLi, command injection patterns.
  - HS secret brute force — parallel via rayon, live progress, default 10M cap.
  - `jku`/`x5u` redirection — emits forged token + sample JWKS to self-host.
- **Token jar** — local SQLite store (`~/.local/share/jwt-tui/jar.db`) for saved tokens with labels, tags, and notes.
- **CLI mode** — every TUI feature available as a pipe-friendly subcommand. `--json` everywhere.
- **Offline by default** — the only network call is JWKS fetching, and only if you ask for it.

## Install

```sh
# from source (recommended for now)
git clone https://github.com/kemalasliyuksek/jwt-tui
cd jwt-tui
cargo install --path crates/jwt-tui

# or, via cargo
cargo install jwt-tui
```

Prebuilt binaries land via the GitHub release pipeline (`.github/workflows/release.yml`) once tags start shipping.

## Five-minute quickstart

```sh
# decode a token
jwt-tui decode "$TOKEN"

# pipe-friendly
echo "$TOKEN" | jwt-tui decode --json | jq .payload

# sign with HS256
jwt-tui sign --alg HS256 --secret 'shh' \
  --payload '{"sub":"alice","iat":1700000000}'

# verify against a JWKS URL
jwt-tui verify "$TOKEN" --jwks https://issuer.example/.well-known/jwks.json \
  --expected-iss https://issuer.example --expected-aud my-api

# brute force an HS secret (lab only)
jwt-tui --lab attack hs-brute "$TOKEN" --wordlist rockyou.txt --threads 8

# launch the TUI
jwt-tui
```

## TUI cheatsheet

| Key            | Action                                |
|----------------|---------------------------------------|
| `?`            | Toggle help overlay                   |
| `q` / `Esc`    | Quit (or close overlay)               |
| `g d`          | Go to **D**ecode                      |
| `g s`          | Go to **S**ign                        |
| `g v`          | Go to **V**erify                      |
| `g a`          | Go to **A**ttack lab                  |
| `g j`          | Go to **J**ar                         |
| `i` / `Esc`    | Insert mode / leave                   |
| `:`            | Command prompt                        |
| `Ctrl-S`       | Save current token to jar             |
| `Ctrl-Y` / `y` | Yank to clipboard                     |
| `←` / `→`      | Cycle algorithm in Sign view          |

Full list in `docs/KEYBINDS.md` and the in-app help overlay.

## CLI reference (abridged)

```
jwt-tui decode <token>                                  # JSON or pretty
jwt-tui sign --alg HS256 --secret @key.txt --payload @claims.json
jwt-tui verify <token> --jwks https://...
jwt-tui jar list | add | remove | show
jwt-tui --lab attack alg-none <token>
jwt-tui --lab attack hs-confusion <token> --public-key pub.pem
jwt-tui --lab attack kid                                # show templates
jwt-tui --lab attack hs-brute <token> --wordlist words.txt --threads 8
jwt-tui --lab attack jku-redirect <token> --url https://attacker/jwks.json
jwt-tui completions zsh > _jwt-tui
jwt-tui manpage > jwt-tui.1
```

Every subcommand reads stdin if you skip the positional token argument and pipe one in.

## Theming

Respects `NO_COLOR`. Three built-ins (dark / light / high-contrast) and a TOML override at `~/.config/jwt-tui/config.toml`:

```toml
theme = "dark"

[colors]
bg = "#0b0d10"
fg = "#d6d6d6"
accent = "#7eb6ff"
# ...
```

## Safety notes

- Attack subcommands and their TUI counterparts are **gated by `--lab`** and print a "lab use only" banner. They exist because this is a security tool — but you are responsible for what you do with them.
- The `kid` injection templates do not exfiltrate anything; they render annotated payloads for you to drop into a forged token.
- Brute force defaults to a **10 000 000 attempt cap**. Lift it with `--unlimited` when you have a finite wordlist.
- `jku`/`x5u` redirection emits the forged token and a *sample* JWKS — there is no built-in hosting helper.

## Project layout

```
jwt-tui/
├── crates/jwt-core/   # pure JWT primitives (publishable to crates.io)
├── crates/jwt-tui/    # binary (CLI + TUI)
├── docs/              # ATTACKS.md, KEYBINDS.md, DECISIONS.md, PROGRESS.md
├── examples/          # sample tokens + key material
└── .github/workflows/ # ci.yml, release.yml
```

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports and PRs welcome.

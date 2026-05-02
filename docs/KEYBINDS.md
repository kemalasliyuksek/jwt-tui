# Keybindings

Default Vim-style bindings. The `?`-overlay inside the app shows the same content.

## Modal model

- **Normal** mode (default) — keys trigger actions.
- **Insert** mode — typing into a text field. Enter via `i`, leave via `Esc`.
- **Command** mode — `:` prompt. `:q` quit, `:help` show overlay.
- **Pending** mode — after `g`, the next key picks a screen.

## Global

| Key            | Action                                |
|----------------|---------------------------------------|
| `?`            | Toggle help overlay                   |
| `q`            | Quit (or close overlay)               |
| `Esc`          | Close overlay / leave Insert mode     |
| `:`            | Enter command mode                    |
| `Ctrl-S`       | Save current token to jar             |
| `Ctrl-Y`, `y`  | Yank to clipboard                     |

## Screen jumps (after `g`)

| Key            | Screen                                |
|----------------|---------------------------------------|
| `g d`          | **D**ecode                            |
| `g s`          | **S**ign / forge                      |
| `g v`          | **V**erify                            |
| `g a`          | **A**ttack lab                        |
| `g j`          | **J**ar                               |

## Decode view

| Key            | Action                                |
|----------------|---------------------------------------|
| `i`            | Edit the token (insert mode)          |
| `y`            | Yank token to clipboard               |
| `Ctrl-S`       | Save token to jar                     |

## Sign view

| Key            | Action                                |
|----------------|---------------------------------------|
| `←` / `→`      | Cycle algorithm                       |
| `s`            | Sign with current header / payload    |
| `i`            | Edit the payload field                |
| `y`            | Yank generated token                  |

## Verify view

| Key            | Action                                |
|----------------|---------------------------------------|
| `v`            | Run HMAC verification                 |
| `i`            | Edit token / secret                   |

## Jar view

| Key            | Action                                |
|----------------|---------------------------------------|
| `Enter`        | Open selected entry                   |
| `d`            | Delete selected entry                 |

## Command mode

| Command        | Action                                |
|----------------|---------------------------------------|
| `:q`, `:quit`  | Exit                                  |
| `:help`        | Open help overlay                     |

//! Application command modules. The split mirrors the CLI subcommand layout.

pub mod attack_cmd;
pub mod decode_cmd;
pub mod jar_cmd;
pub mod sign_cmd;
pub mod tui_main;
pub mod verify_cmd;

use std::io::Read;
use std::path::PathBuf;

/// Helper used by every subcommand: load a value either inline (`--token foo`)
/// or from stdin (`--token -`) or from a file (`--token-file path`). When
/// neither is given and stdin is a tty, return `None`.
pub fn read_inline_or_stdin(inline: Option<&str>) -> anyhow::Result<Option<String>> {
    if let Some(s) = inline {
        if s == "-" {
            let mut buf = String::new();
            std::io::stdin().read_to_string(&mut buf)?;
            return Ok(Some(buf.trim().to_owned()));
        }
        return Ok(Some(s.to_owned()));
    }
    // No inline arg — try stdin if it's piped.
    use std::io::IsTerminal as _;
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }
    let mut buf = String::new();
    std::io::stdin().read_to_string(&mut buf)?;
    let trimmed = buf.trim().to_owned();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(trimmed))
    }
}

/// Resolve a `@path`-or-inline value: leading `@` reads from a file, leading
/// `env:NAME` reads from an environment variable, anything else is verbatim.
pub fn read_value_spec(spec: &str) -> anyhow::Result<Vec<u8>> {
    if let Some(rest) = spec.strip_prefix('@') {
        let p = PathBuf::from(rest);
        return std::fs::read(&p).map_err(|e| anyhow::anyhow!("read {}: {e}", p.display()));
    }
    if let Some(rest) = spec.strip_prefix("env:") {
        return std::env::var(rest)
            .map(String::into_bytes)
            .map_err(|e| anyhow::anyhow!("env var {rest}: {e}"));
    }
    Ok(spec.as_bytes().to_vec())
}

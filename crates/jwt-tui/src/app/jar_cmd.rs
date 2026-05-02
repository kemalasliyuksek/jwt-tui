//! `jwt-tui jar` — saved-token database commands.

use std::process::ExitCode;

use clap::Subcommand;

use crate::jar::Jar;

use super::read_inline_or_stdin;

#[derive(Debug, Subcommand)]
pub enum JarCommand {
    /// List all saved tokens.
    List,
    /// Save a token.
    Add {
        /// Token (or pipe via stdin).
        token: Option<String>,
        #[arg(long)]
        label: String,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long)]
        notes: Option<String>,
    },
    /// Remove an entry by id.
    Remove { id: i64 },
    /// Show one entry.
    Show { id: i64 },
}

pub fn run(cmd: JarCommand, json: bool) -> anyhow::Result<ExitCode> {
    let mut jar = Jar::open_default()?;
    match cmd {
        JarCommand::List => {
            let entries = jar.list()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("(jar is empty)");
            } else {
                for e in entries {
                    println!(
                        "{:>4}  {:<24} {:<24} [{}]",
                        e.id,
                        truncate(&e.label, 24),
                        e.created_at,
                        e.tags.join(",")
                    );
                }
            }
        }
        JarCommand::Add {
            token,
            label,
            tag,
            notes,
        } => {
            let token = read_inline_or_stdin(token.as_deref())?
                .ok_or_else(|| anyhow::anyhow!("no token provided"))?;
            let id = jar.insert(&label, &token, &tag, notes.as_deref())?;
            if json {
                println!("{}", serde_json::json!({"id": id}));
            } else {
                println!("saved as id {id}");
            }
        }
        JarCommand::Remove { id } => {
            let removed = jar.remove(id)?;
            if json {
                println!("{}", serde_json::json!({"removed": removed}));
            } else if removed {
                println!("removed id {id}");
            } else {
                println!("no entry with id {id}");
            }
        }
        JarCommand::Show { id } => {
            let entry = jar.get(id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entry)?);
            } else {
                match entry {
                    Some(e) => {
                        println!("id: {}", e.id);
                        println!("label: {}", e.label);
                        println!("tags: {}", e.tags.join(","));
                        println!("created: {}", e.created_at);
                        if let Some(n) = e.notes {
                            println!("notes: {n}");
                        }
                        println!();
                        println!("{}", e.token);
                    }
                    None => {
                        println!("no entry with id {id}");
                        return Ok(ExitCode::from(1));
                    }
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

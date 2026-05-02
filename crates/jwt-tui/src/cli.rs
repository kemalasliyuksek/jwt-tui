//! Command-line interface. The TUI launches when no subcommand is given.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "jwt-tui",
    version,
    about = "Inspect, sign, verify, and security-test JSON Web Tokens.",
    long_about = "jwt-tui is an offline-first terminal app for working with JWTs.\n\
                  \n\
                  Run with no arguments to launch the TUI. Use one of the subcommands\n\
                  for scriptable, pipe-friendly access. Pass `--lab` to unlock the\n\
                  attack subcommands."
)]
pub struct Cli {
    /// Increase log verbosity. Repeat up to three times.
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    /// Output JSON instead of human text where applicable.
    #[arg(long, global = true)]
    pub json: bool,

    /// Unlock offensive subcommands. Required for `attack *` and writes a
    /// confirmation banner to stderr on first use.
    #[arg(long, global = true)]
    pub lab: bool,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Decode a token (no signature verification).
    Decode(crate::app::decode_cmd::DecodeArgs),
    /// Sign a JWT.
    Sign(crate::app::sign_cmd::SignArgs),
    /// Verify a JWT against a key, JWKS, or HMAC secret.
    Verify(crate::app::verify_cmd::VerifyArgs),
    /// Token jar (saved tokens database).
    #[command(subcommand)]
    Jar(crate::app::jar_cmd::JarCommand),
    /// Offensive helpers — alg confusion, brute force, kid injection. Lab use only.
    #[command(subcommand)]
    Attack(crate::app::attack_cmd::AttackCommand),
    /// Generate shell completion scripts.
    Completions(CompletionsArgs),
    /// Generate a man page on stdout.
    Manpage,
}

#[derive(Debug, clap::Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Run the parsed command. Returns the desired process exit code.
pub fn dispatch(args: Cli) -> anyhow::Result<ExitCode> {
    let json = args.json;
    let lab = args.lab;
    match args.command {
        None => crate::app::tui_main::run(),
        Some(Command::Decode(a)) => crate::app::decode_cmd::run(a, json),
        Some(Command::Sign(a)) => crate::app::sign_cmd::run(a, json),
        Some(Command::Verify(a)) => crate::app::verify_cmd::run(a, json),
        Some(Command::Jar(c)) => crate::app::jar_cmd::run(c, json),
        Some(Command::Attack(c)) => {
            crate::app::attack_cmd::ensure_lab(lab)?;
            crate::app::attack_cmd::run(c, json)
        }
        Some(Command::Completions(c)) => {
            let mut cmd = <Cli as clap::CommandFactory>::command();
            clap_complete::generate(c.shell, &mut cmd, "jwt-tui", &mut std::io::stdout());
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Manpage) => {
            let cmd = <Cli as clap::CommandFactory>::command();
            let man = clap_mangen::Man::new(cmd);
            man.render(&mut std::io::stdout())?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

//! `jwt-tui` binary entry point. The full CLI/TUI is wired up in the modules
//! linked from this file; `main` itself just bootstraps logging, parses the
//! top-level command, and dispatches.

#![allow(dead_code)]

mod app;
mod cli;
mod config;
mod events;
mod jar;
mod theme;
mod ui;

use std::process::ExitCode;

use clap::Parser as _;

fn main() -> ExitCode {
    let args = cli::Cli::parse();
    setup_tracing(args.verbose);

    match cli::dispatch(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:?}");
            ExitCode::from(2)
        }
    }
}

fn setup_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let default_level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!("jwt_tui={default_level},jwt_core={default_level}"))
    });

    // Logs go to a file in the user's data dir to avoid polluting the TUI.
    let log_dir = directories::ProjectDirs::from("dev", "jwt-tui", "jwt-tui")
        .map(|p| p.data_local_dir().join("logs"))
        .unwrap_or_else(|| std::env::temp_dir().join("jwt-tui-logs"));

    if std::fs::create_dir_all(&log_dir).is_ok() {
        let appender = tracing_appender::rolling::daily(&log_dir, "jwt-tui.log");
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(appender)
            .with_ansi(false)
            .try_init();
    }
}

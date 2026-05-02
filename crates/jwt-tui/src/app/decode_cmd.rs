//! `jwt-tui decode` — pretty-print a token without verifying its signature.

use std::process::ExitCode;

use clap::Args;
use jwt_core::parse::decode_unverified;

use super::read_inline_or_stdin;

#[derive(Debug, Args)]
pub struct DecodeArgs {
    /// Token to decode. Pass `-` (or omit and pipe via stdin) to read from stdin.
    pub token: Option<String>,
    /// Output a verbose human report (the default). Use `--json` for machine output.
    #[arg(long)]
    pub pretty: bool,
}

pub fn run(args: DecodeArgs, json: bool) -> anyhow::Result<ExitCode> {
    let token = read_inline_or_stdin(args.token.as_deref())?
        .ok_or_else(|| anyhow::anyhow!("no token given (pass as argument or pipe via stdin)"))?;
    let decoded = decode_unverified(&token)?;

    if json {
        let out = serde_json::json!({
            "header": decoded.header,
            "payload": decoded.payload,
            "signature_b64url": decoded.raw_signature,
            "signing_input": decoded.signing_input,
            "warnings": decoded.header.dangerous_warnings(),
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(ExitCode::SUCCESS);
    }

    println!("Header:");
    println!("{}", serde_json::to_string_pretty(&decoded.header)?);
    println!();
    println!("Payload:");
    println!("{}", serde_json::to_string_pretty(&decoded.payload)?);
    println!();
    println!("Signature (base64url): {}", decoded.raw_signature);
    if !decoded.signature.is_empty() {
        println!("Signature (hex):       {}", hex::encode(&decoded.signature));
    }

    let warnings = decoded.header.dangerous_warnings();
    if !warnings.is_empty() {
        println!();
        println!("Warnings:");
        for w in warnings {
            println!("  ! {w}");
        }
    }

    Ok(ExitCode::SUCCESS)
}

//! `jwt-tui sign` — produce a JWT.

use std::process::ExitCode;

use clap::Args;
use jwt_core::sign::{self, Algorithm, SigningKey};

use super::read_value_spec;

#[derive(Debug, Args)]
pub struct SignArgs {
    /// Algorithm name (HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, EdDSA, none).
    #[arg(long)]
    pub alg: String,

    /// Inline JSON header object (default: `{"alg":"<alg>","typ":"JWT"}`).
    #[arg(long)]
    pub header: Option<String>,

    /// Inline JSON payload, `@file.json`, or `env:VAR`. Required.
    #[arg(long)]
    pub payload: String,

    /// HMAC secret. Inline string, `@file`, or `env:VAR`.
    #[arg(long, conflicts_with_all=["key", "key_file"])]
    pub secret: Option<String>,

    /// PKCS#8-DER private key bytes (asymmetric algs). `@file` only.
    #[arg(long = "key-file", conflicts_with = "key")]
    pub key_file: Option<String>,

    /// PKCS#8-PEM private key (asymmetric algs). Inline or `@file`.
    #[arg(long)]
    pub key: Option<String>,

    /// Generate an ephemeral key pair (only for ES256/ES384/EdDSA).
    /// The PKCS#8 DER is written to this file.
    #[arg(long)]
    pub keygen_out: Option<String>,
}

pub fn run(args: SignArgs, json: bool) -> anyhow::Result<ExitCode> {
    let alg = Algorithm::from_jose(&args.alg).map_err(|e| anyhow::anyhow!("invalid --alg: {e}"))?;

    let payload_bytes = read_value_spec(&args.payload)?;
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| anyhow::anyhow!("payload is not JSON: {e}"))?;

    let header: serde_json::Value = if let Some(h) = args.header.as_deref() {
        serde_json::from_str(h).map_err(|e| anyhow::anyhow!("header is not JSON: {e}"))?
    } else {
        serde_json::json!({"alg": alg.name(), "typ": "JWT"})
    };

    let key = build_signing_key(alg, &args)?;
    let token = sign::sign(alg, &key, &header, &payload)?;

    if json {
        let decoded = jwt_core::parse::decode_unverified(&token)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "token": token,
                "header": decoded.header,
                "payload": decoded.payload,
                "signature_b64url": decoded.raw_signature,
            }))?
        );
    } else {
        println!("{token}");
    }

    Ok(ExitCode::SUCCESS)
}

fn build_signing_key(alg: Algorithm, args: &SignArgs) -> anyhow::Result<SigningKey> {
    if matches!(alg, Algorithm::None) {
        return Ok(SigningKey::None);
    }
    if alg.is_symmetric() {
        let secret = args
            .secret
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("HS* algorithms require --secret"))?;
        let bytes = read_value_spec(secret)?;
        return Ok(SigningKey::Hmac(bytes));
    }

    // Asymmetric: prefer file-based PKCS#8 DER, fall back to inline PEM.
    if let Some(spec) = &args.key_file {
        let der = read_value_spec(spec)?;
        return key_for_alg(alg, der);
    }
    if let Some(spec) = &args.key {
        let raw = read_value_spec(spec)?;
        let der = pem_to_der(&raw)?;
        return key_for_alg(alg, der);
    }
    if let Some(out) = &args.keygen_out {
        let der = sign::generate_keypair_pkcs8(alg)?;
        std::fs::write(out, &der)?;
        return key_for_alg(alg, der);
    }
    Err(anyhow::anyhow!(
        "asymmetric signing requires --key, --key-file, or --keygen-out"
    ))
}

fn key_for_alg(alg: Algorithm, der: Vec<u8>) -> anyhow::Result<SigningKey> {
    Ok(match alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => SigningKey::RsaPkcs8(der),
        Algorithm::ES256 => SigningKey::EcP256Pkcs8(der),
        Algorithm::ES384 => SigningKey::EcP384Pkcs8(der),
        Algorithm::EdDSA => SigningKey::Ed25519Pkcs8(der),
        _ => unreachable!("symmetric/none cases handled above"),
    })
}

fn pem_to_der(input: &[u8]) -> anyhow::Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let s = std::str::from_utf8(input)?;
    let body: String = s
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    Ok(STANDARD.decode(body.trim())?)
}

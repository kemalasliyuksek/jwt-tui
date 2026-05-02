//! `jwt-tui verify` — verify a token against a key, secret, or JWKS URL.

use std::process::ExitCode;

use clap::Args;
use jwt_core::sign::Algorithm;
use jwt_core::verify::{self, VerificationOptions, VerificationOutcome, VerifyingKey};

use super::{read_inline_or_stdin, read_value_spec};

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Token to verify (or pipe via stdin).
    pub token: Option<String>,
    /// HMAC secret (inline, `@file`, or `env:VAR`).
    #[arg(long)]
    pub secret: Option<String>,
    /// Public key file (DER or PEM, depending on extension).
    #[arg(long)]
    pub key: Option<String>,
    /// JWKS URL — the appropriate key is selected by `kid`.
    #[arg(long)]
    pub jwks: Option<String>,
    /// Expected algorithm. Highly recommended to set this.
    #[arg(long = "expected-alg")]
    pub expected_alg: Option<String>,
    /// Required `iss` claim.
    #[arg(long = "expected-iss")]
    pub expected_iss: Option<String>,
    /// Required `aud` claim.
    #[arg(long = "expected-aud")]
    pub expected_aud: Option<String>,
    /// Required `sub` claim.
    #[arg(long = "expected-sub")]
    pub expected_sub: Option<String>,
    /// Skip `exp` validation.
    #[arg(long = "no-exp")]
    pub no_exp: bool,
    /// Skip `nbf` validation.
    #[arg(long = "no-nbf")]
    pub no_nbf: bool,
    /// Time leeway in seconds for exp/nbf checks.
    #[arg(long, default_value_t = 0)]
    pub leeway: i64,
}

pub fn run(args: VerifyArgs, json: bool) -> anyhow::Result<ExitCode> {
    let token = read_inline_or_stdin(args.token.as_deref())?
        .ok_or_else(|| anyhow::anyhow!("no token given"))?;

    let opts = VerificationOptions {
        expected_iss: args.expected_iss.clone(),
        expected_aud: args.expected_aud.clone(),
        expected_sub: args.expected_sub.clone(),
        expected_alg: args
            .expected_alg
            .as_deref()
            .map(Algorithm::from_jose)
            .transpose()?,
        validate_exp: !args.no_exp,
        validate_nbf: !args.no_nbf,
        leeway_secs: args.leeway,
        now: None,
    };

    let key = build_verifying_key(&token, &args)?;
    let outcome = verify::verify(&token, &key, &opts)?;
    emit_outcome(outcome, json)
}

fn build_verifying_key(token: &str, args: &VerifyArgs) -> anyhow::Result<VerifyingKey> {
    if let Some(s) = &args.secret {
        return Ok(VerifyingKey::Hmac(read_value_spec(s)?));
    }
    if let Some(k) = &args.key {
        let raw = read_value_spec(k)?;
        return key_from_pem_or_der(token, &raw);
    }
    if let Some(url) = &args.jwks {
        return fetch_key_via_jwks(token, url);
    }
    // Maybe alg=none — accept implicit None key only in that case.
    let decoded = jwt_core::parse::decode_unverified(token)?;
    if decoded.header.alg.eq_ignore_ascii_case("none") {
        return Ok(VerifyingKey::None);
    }
    Err(anyhow::anyhow!(
        "no verification material — pass --secret, --key, or --jwks"
    ))
}

fn key_from_pem_or_der(token: &str, raw: &[u8]) -> anyhow::Result<VerifyingKey> {
    let decoded = jwt_core::parse::decode_unverified(token)?;
    let alg = Algorithm::from_jose(&decoded.header.alg)?;

    let der = if let Ok(s) = std::str::from_utf8(raw) {
        if s.contains("-----BEGIN") {
            pem_body_to_der(s)?
        } else {
            raw.to_vec()
        }
    } else {
        raw.to_vec()
    };

    Ok(match alg {
        Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => VerifyingKey::RsaSpkiDer(der),
        Algorithm::ES256 => VerifyingKey::EcP256Raw(extract_ec_raw(&der, 65)?),
        Algorithm::ES384 => VerifyingKey::EcP384Raw(extract_ec_raw(&der, 97)?),
        Algorithm::EdDSA => VerifyingKey::Ed25519Raw(extract_ed25519_raw(&der)?),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            return Err(anyhow::anyhow!("HS* requires --secret, not --key"))
        }
        Algorithm::None => VerifyingKey::None,
    })
}

fn pem_body_to_der(s: &str) -> anyhow::Result<Vec<u8>> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    let body: String = s
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    Ok(STANDARD.decode(body.trim())?)
}

/// Pull the trailing N bytes off a SubjectPublicKeyInfo to get the raw EC point.
fn extract_ec_raw(spki: &[u8], expected_len: usize) -> anyhow::Result<Vec<u8>> {
    if spki.len() >= expected_len && spki.ends_with(&spki[spki.len() - expected_len..]) {
        // SPKI ends with the BIT STRING containing the uncompressed point.
        // The first byte of the point is 0x04, so we just look for the last
        // occurrence of 0x04 followed by the right number of bytes.
        if let Some(pos) = spki.windows(expected_len).rposition(|w| w[0] == 0x04) {
            return Ok(spki[pos..pos + expected_len].to_vec());
        }
    }
    if spki.len() == expected_len && spki[0] == 0x04 {
        return Ok(spki.to_vec());
    }
    Err(anyhow::anyhow!(
        "could not extract {expected_len}-byte EC point from key"
    ))
}

fn extract_ed25519_raw(spki: &[u8]) -> anyhow::Result<Vec<u8>> {
    // SPKI for Ed25519 ends with a 32-byte BIT STRING payload (after a 0x00 unused-bits byte).
    if spki.len() == 32 {
        return Ok(spki.to_vec());
    }
    if spki.len() >= 32 {
        return Ok(spki[spki.len() - 32..].to_vec());
    }
    Err(anyhow::anyhow!(
        "Ed25519 public key must be at least 32 bytes"
    ))
}

fn fetch_key_via_jwks(token: &str, url: &str) -> anyhow::Result<VerifyingKey> {
    let decoded = jwt_core::parse::decode_unverified(token)?;
    let kid = decoded
        .header
        .kid
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("token has no `kid` header — JWKS lookup needs one"))?;

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = reqwest::Client::builder().use_rustls_tls().build()?;
    let jwks = runtime
        .block_on(jwt_core::jwks::fetch_jwks(&client, url, None))
        .map_err(|e| anyhow::anyhow!("JWKS fetch: {e}"))?;
    let jwk = jwks
        .find_by_kid(kid)
        .ok_or_else(|| anyhow::anyhow!("no key with kid `{kid}` in JWKS"))?;
    Ok(jwk.to_verifying_key()?)
}

fn emit_outcome(outcome: VerificationOutcome, json: bool) -> anyhow::Result<ExitCode> {
    if json {
        let j = match &outcome {
            VerificationOutcome::Valid(d) => serde_json::json!({
                "ok": true,
                "header": d.header,
                "payload": d.payload,
            }),
            VerificationOutcome::Invalid { decoded, reason } => serde_json::json!({
                "ok": false,
                "reason": reason,
                "header": decoded.as_ref().map(|d| &d.header),
                "payload": decoded.as_ref().map(|d| &d.payload),
            }),
        };
        println!("{}", serde_json::to_string_pretty(&j)?);
    } else {
        match &outcome {
            VerificationOutcome::Valid(d) => {
                println!("VALID");
                println!("alg: {}", d.header.alg);
            }
            VerificationOutcome::Invalid { reason, .. } => {
                println!("INVALID: {reason}");
            }
        }
    }
    Ok(if outcome.is_valid() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

//! Token verification.
//!
//! Verification is intentionally split into structured *outcomes* rather than
//! a single boolean — both the CLI and the TUI surface the specific reason a
//! token was rejected, and so do downstream consumers.

use std::collections::HashSet;

use ring::hmac;
use ring::signature::{
    UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED, ED25519,
    RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::error::Result;
use crate::parse::{decode_unverified, DecodedToken};
use crate::sign::Algorithm;

/// Public-key material accepted by [`verify`].
pub enum VerifyingKey {
    /// HMAC secret bytes (must match the signing secret exactly).
    Hmac(Vec<u8>),
    /// RSA public key, DER-encoded SubjectPublicKeyInfo.
    RsaSpkiDer(Vec<u8>),
    /// ECDSA P-256 public key, raw uncompressed (0x04 || X || Y, 65 bytes).
    EcP256Raw(Vec<u8>),
    /// ECDSA P-384 public key, raw uncompressed (0x04 || X || Y, 97 bytes).
    EcP384Raw(Vec<u8>),
    /// Ed25519 public key, 32-byte raw.
    Ed25519Raw(Vec<u8>),
    /// No verification (matches `alg: none` only — never use in production).
    None,
}

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hmac(b) => write!(f, "VerifyingKey::Hmac({} bytes)", b.len()),
            Self::RsaSpkiDer(b) => write!(f, "VerifyingKey::RsaSpkiDer({} bytes)", b.len()),
            Self::EcP256Raw(_) => f.write_str("VerifyingKey::EcP256Raw(<65 bytes>)"),
            Self::EcP384Raw(_) => f.write_str("VerifyingKey::EcP384Raw(<97 bytes>)"),
            Self::Ed25519Raw(_) => f.write_str("VerifyingKey::Ed25519Raw(<32 bytes>)"),
            Self::None => f.write_str("VerifyingKey::None"),
        }
    }
}

/// Optional checks beyond the bare signature.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct VerificationOptions {
    /// Required `iss` claim. If `Some`, the token must have a matching `iss`.
    pub expected_iss: Option<String>,
    /// Required `aud` claim. The token may carry `aud` as either a string or
    /// array — both are accepted.
    pub expected_aud: Option<String>,
    /// Required `sub` claim.
    pub expected_sub: Option<String>,
    /// Required algorithm. If `Some`, the token's `alg` header must match.
    /// Defenders almost always want this set to avoid algorithm confusion.
    pub expected_alg: Option<Algorithm>,
    /// Reject the token if `exp` has passed. Default `true`.
    pub validate_exp: bool,
    /// Reject the token if `nbf` is in the future. Default `true`.
    pub validate_nbf: bool,
    /// Tolerance applied to time-based claims, in seconds.
    pub leeway_secs: i64,
    /// "Now" override for testing.
    pub now: Option<i64>,
}

impl VerificationOptions {
    /// Default verifier that enforces signature + time checks.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            validate_exp: true,
            validate_nbf: true,
            leeway_secs: 0,
            ..Self::default()
        }
    }
}

/// Structured reason a verification failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "code", content = "detail")]
pub enum VerifyError {
    /// The token was structurally invalid (parse failure).
    #[error("malformed_token: {0}")]
    MalformedToken(String),
    /// Header `alg` did not match the expected algorithm.
    #[error("algorithm_mismatch: expected {expected}, got {got}")]
    AlgorithmMismatch {
        /// Expected algorithm name.
        expected: String,
        /// Actual algorithm in the token.
        got: String,
    },
    /// The signature did not match.
    #[error("signature_invalid")]
    SignatureInvalid,
    /// `exp` claim is in the past.
    #[error("expired: exp={exp}, now={now}")]
    Expired {
        /// `exp` from the token.
        exp: i64,
        /// Current epoch seconds.
        now: i64,
    },
    /// `nbf` claim is in the future.
    #[error("not_yet_valid: nbf={nbf}, now={now}")]
    NotYetValid {
        /// `nbf` from the token.
        nbf: i64,
        /// Current epoch seconds.
        now: i64,
    },
    /// Issuer mismatch.
    #[error("issuer_mismatch: expected {expected}, got {got:?}")]
    IssuerMismatch {
        /// Expected `iss`.
        expected: String,
        /// `iss` actually carried (or `None`).
        got: Option<String>,
    },
    /// Audience mismatch.
    #[error("audience_mismatch: expected {expected}")]
    AudienceMismatch {
        /// Expected `aud`.
        expected: String,
    },
    /// Subject mismatch.
    #[error("subject_mismatch: expected {expected}, got {got:?}")]
    SubjectMismatch {
        /// Expected `sub`.
        expected: String,
        /// `sub` carried (or `None`).
        got: Option<String>,
    },
    /// Verifier configuration error.
    #[error("verifier_misconfigured: {0}")]
    Misconfigured(String),
}

/// Outcome of [`verify`].
#[derive(Debug, Clone)]
pub enum VerificationOutcome {
    /// Verification succeeded; the decoded token is returned.
    Valid(DecodedToken),
    /// Verification failed with a structured reason.
    Invalid {
        /// The decoded token, if parseable. `None` if even parsing failed.
        decoded: Option<DecodedToken>,
        /// Specific failure reason.
        reason: VerifyError,
    },
}

impl VerificationOutcome {
    /// Convenience: `true` iff the token is valid.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }
}

/// Verify a token end-to-end.
pub fn verify(
    token: &str,
    key: &VerifyingKey,
    options: &VerificationOptions,
) -> Result<VerificationOutcome> {
    let decoded = match decode_unverified(token) {
        Ok(d) => d,
        Err(e) => {
            return Ok(VerificationOutcome::Invalid {
                decoded: None,
                reason: VerifyError::MalformedToken(e.to_string()),
            });
        }
    };

    let alg = match Algorithm::from_jose(&decoded.header.alg) {
        Ok(a) => a,
        Err(e) => {
            return Ok(VerificationOutcome::Invalid {
                decoded: Some(decoded),
                reason: VerifyError::MalformedToken(e.to_string()),
            });
        }
    };

    if let Some(expected) = options.expected_alg {
        if expected != alg {
            return Ok(VerificationOutcome::Invalid {
                reason: VerifyError::AlgorithmMismatch {
                    expected: expected.name().to_owned(),
                    got: alg.name().to_owned(),
                },
                decoded: Some(decoded),
            });
        }
    }

    if let Err(reason) = verify_signature(alg, key, &decoded) {
        return Ok(VerificationOutcome::Invalid {
            decoded: Some(decoded),
            reason,
        });
    }

    if let Err(reason) = verify_claims(&decoded, options) {
        return Ok(VerificationOutcome::Invalid {
            decoded: Some(decoded),
            reason,
        });
    }

    Ok(VerificationOutcome::Valid(decoded))
}

fn verify_signature(
    alg: Algorithm,
    key: &VerifyingKey,
    decoded: &DecodedToken,
) -> std::result::Result<(), VerifyError> {
    let input = decoded.signing_input.as_bytes();
    let sig = decoded.signature.as_slice();

    match (alg, key) {
        (Algorithm::None, VerifyingKey::None) => {
            // Per spec, `none` requires an empty signature segment.
            if sig.is_empty() {
                Ok(())
            } else {
                Err(VerifyError::SignatureInvalid)
            }
        }
        (Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512, VerifyingKey::Hmac(secret)) => {
            let alg_inner = match alg {
                Algorithm::HS256 => hmac::HMAC_SHA256,
                Algorithm::HS384 => hmac::HMAC_SHA384,
                _ => hmac::HMAC_SHA512,
            };
            let key = hmac::Key::new(alg_inner, secret);
            let expected = hmac::sign(&key, input);
            if expected.as_ref().ct_eq(sig).into() {
                Ok(())
            } else {
                Err(VerifyError::SignatureInvalid)
            }
        }
        (
            Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512,
            VerifyingKey::RsaSpkiDer(spki),
        ) => {
            let params: &dyn ring::signature::VerificationAlgorithm = match alg {
                Algorithm::RS256 => &RSA_PKCS1_2048_8192_SHA256,
                Algorithm::RS384 => &RSA_PKCS1_2048_8192_SHA384,
                _ => &RSA_PKCS1_2048_8192_SHA512,
            };
            let pk_der = strip_spki_to_rsa(spki).unwrap_or_else(|| spki.clone());
            let pk = UnparsedPublicKey::new(params, pk_der);
            pk.verify(input, sig)
                .map_err(|_| VerifyError::SignatureInvalid)
        }
        (Algorithm::ES256, VerifyingKey::EcP256Raw(raw)) => {
            UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, raw)
                .verify(input, sig)
                .map_err(|_| VerifyError::SignatureInvalid)
        }
        (Algorithm::ES384, VerifyingKey::EcP384Raw(raw)) => {
            UnparsedPublicKey::new(&ECDSA_P384_SHA384_FIXED, raw)
                .verify(input, sig)
                .map_err(|_| VerifyError::SignatureInvalid)
        }
        (Algorithm::EdDSA, VerifyingKey::Ed25519Raw(raw)) => UnparsedPublicKey::new(&ED25519, raw)
            .verify(input, sig)
            .map_err(|_| VerifyError::SignatureInvalid),
        (alg, key) => Err(VerifyError::Misconfigured(format!(
            "key type does not match algorithm {alg} (got {key:?})"
        ))),
    }
}

/// `ring`'s `RSA_PKCS1_*` verification routines want a raw `RSAPublicKey`
/// DER (PKCS#1), not a SubjectPublicKeyInfo wrapper. Most users have SPKI
/// (the contents of a `-----BEGIN PUBLIC KEY-----` block), so we strip the
/// wrapper here. If parsing fails we fall back to the raw bytes — ring will
/// reject mismatched encodings.
fn strip_spki_to_rsa(spki: &[u8]) -> Option<Vec<u8>> {
    // Minimal DER walker: SEQUENCE { AlgorithmIdentifier, BIT STRING }.
    // We don't validate the algorithm OID — a wrong key fails verification
    // anyway, and proper SPKI parsing belongs in a dedicated crate.
    let mut idx = 0usize;
    if *spki.first()? != 0x30 {
        return None;
    }
    idx += 1;
    let (_outer_len, n) = read_der_len(spki, idx)?;
    idx += n;
    // skip AlgorithmIdentifier (SEQUENCE)
    if *spki.get(idx)? != 0x30 {
        return None;
    }
    idx += 1;
    let (algo_len, n) = read_der_len(spki, idx)?;
    idx += n + algo_len;
    // BIT STRING
    if *spki.get(idx)? != 0x03 {
        return None;
    }
    idx += 1;
    let (_bit_len, n) = read_der_len(spki, idx)?;
    idx += n;
    // skip unused-bits byte
    let unused = *spki.get(idx)?;
    if unused != 0 {
        return None;
    }
    idx += 1;
    Some(spki.get(idx..)?.to_vec())
}

fn read_der_len(buf: &[u8], idx: usize) -> Option<(usize, usize)> {
    let first = *buf.get(idx)?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for byte in buf.get(idx + 1..idx + 1 + n)? {
        len = (len << 8) | usize::from(*byte);
    }
    Some((len, 1 + n))
}

fn verify_claims(
    decoded: &DecodedToken,
    options: &VerificationOptions,
) -> std::result::Result<(), VerifyError> {
    let Some(obj) = decoded.payload.as_object() else {
        return Ok(());
    };

    let now = options
        .now
        .unwrap_or_else(|| chrono::Utc::now().timestamp());

    if options.validate_exp {
        if let Some(exp) = claim_i64(obj.get("exp")) {
            if now - options.leeway_secs > exp {
                return Err(VerifyError::Expired { exp, now });
            }
        }
    }
    if options.validate_nbf {
        if let Some(nbf) = claim_i64(obj.get("nbf")) {
            if now + options.leeway_secs < nbf {
                return Err(VerifyError::NotYetValid { nbf, now });
            }
        }
    }

    if let Some(expected) = &options.expected_iss {
        let got = obj.get("iss").and_then(|v| v.as_str()).map(String::from);
        if got.as_deref() != Some(expected) {
            return Err(VerifyError::IssuerMismatch {
                expected: expected.clone(),
                got,
            });
        }
    }

    if let Some(expected) = &options.expected_aud {
        let ok = match obj.get("aud") {
            Some(serde_json::Value::String(s)) => s == expected,
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .collect::<HashSet<_>>()
                .contains(expected.as_str()),
            _ => false,
        };
        if !ok {
            return Err(VerifyError::AudienceMismatch {
                expected: expected.clone(),
            });
        }
    }

    if let Some(expected) = &options.expected_sub {
        let got = obj.get("sub").and_then(|v| v.as_str()).map(String::from);
        if got.as_deref() != Some(expected) {
            return Err(VerifyError::SubjectMismatch {
                expected: expected.clone(),
                got,
            });
        }
    }

    Ok(())
}

fn claim_i64(v: Option<&serde_json::Value>) -> Option<i64> {
    let v = v?;
    if let Some(i) = v.as_i64() {
        return Some(i);
    }
    if let Some(u) = v.as_u64() {
        return i64::try_from(u).ok();
    }
    if let Some(f) = v.as_f64() {
        return Some(f as i64);
    }
    None
}

// Re-export so callers can build `Result` types easily.
pub use crate::error::Result as VerifyResult;

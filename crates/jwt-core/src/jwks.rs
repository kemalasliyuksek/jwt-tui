//! JSON Web Key Set support.
//!
//! `Jwks` and `Jwk` structs are pure data; the only network code lives in
//! `fetch_jwks`, which is gated behind the `jwks` cargo feature.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// One key from a JWKS document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    /// Key type (`RSA`, `EC`, `OKP`, `oct`).
    pub kty: String,
    /// Algorithm hint, when present.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<String>,
    /// Intended usage (`sig`, `enc`, ...).
    #[serde(skip_serializing_if = "Option::is_none", default, rename = "use")]
    pub use_: Option<String>,
    /// Key id used for selection.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,
    /// RSA modulus (base64url-without-padding).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub n: Option<String>,
    /// RSA exponent (base64url-without-padding).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub e: Option<String>,
    /// EC curve.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub crv: Option<String>,
    /// EC `x` coordinate.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub x: Option<String>,
    /// EC `y` coordinate.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub y: Option<String>,
    /// `oct` symmetric key bytes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub k: Option<String>,
}

impl Jwk {
    /// Sha-256 thumbprint per RFC 7638, hex-encoded.
    pub fn thumbprint(&self) -> Result<String> {
        let json = match self.kty.as_str() {
            "RSA" => format!(
                "{{\"e\":\"{}\",\"kty\":\"RSA\",\"n\":\"{}\"}}",
                self.e.as_deref().unwrap_or(""),
                self.n.as_deref().unwrap_or("")
            ),
            "EC" => format!(
                "{{\"crv\":\"{}\",\"kty\":\"EC\",\"x\":\"{}\",\"y\":\"{}\"}}",
                self.crv.as_deref().unwrap_or(""),
                self.x.as_deref().unwrap_or(""),
                self.y.as_deref().unwrap_or(""),
            ),
            "OKP" => format!(
                "{{\"crv\":\"{}\",\"kty\":\"OKP\",\"x\":\"{}\"}}",
                self.crv.as_deref().unwrap_or(""),
                self.x.as_deref().unwrap_or("")
            ),
            "oct" => format!(
                "{{\"k\":\"{}\",\"kty\":\"oct\"}}",
                self.k.as_deref().unwrap_or("")
            ),
            other => return Err(Error::InvalidInput(format!("unknown JWK kty `{other}`"))),
        };
        let digest = ring::digest::digest(&ring::digest::SHA256, json.as_bytes());
        Ok(hex::encode(digest.as_ref()))
    }

    /// Convert this JWK into a [`crate::verify::VerifyingKey`].
    pub fn to_verifying_key(&self) -> Result<crate::verify::VerifyingKey> {
        match self.kty.as_str() {
            "RSA" => {
                let n = URL_SAFE_NO_PAD
                    .decode(self.n.as_deref().unwrap_or(""))
                    .map_err(|e| Error::InvalidInput(format!("bad RSA n: {e}")))?;
                let e = URL_SAFE_NO_PAD
                    .decode(self.e.as_deref().unwrap_or(""))
                    .map_err(|err| Error::InvalidInput(format!("bad RSA e: {err}")))?;
                let der = encode_rsa_pkcs1(&n, &e);
                Ok(crate::verify::VerifyingKey::RsaSpkiDer(der))
            }
            "EC" => {
                let x = URL_SAFE_NO_PAD
                    .decode(self.x.as_deref().unwrap_or(""))
                    .map_err(|e| Error::InvalidInput(format!("bad EC x: {e}")))?;
                let y = URL_SAFE_NO_PAD
                    .decode(self.y.as_deref().unwrap_or(""))
                    .map_err(|e| Error::InvalidInput(format!("bad EC y: {e}")))?;
                let mut raw = vec![0x04];
                raw.extend_from_slice(&x);
                raw.extend_from_slice(&y);
                match self.crv.as_deref() {
                    Some("P-256") => Ok(crate::verify::VerifyingKey::EcP256Raw(raw)),
                    Some("P-384") => Ok(crate::verify::VerifyingKey::EcP384Raw(raw)),
                    other => Err(Error::InvalidInput(format!(
                        "unsupported EC curve {other:?}"
                    ))),
                }
            }
            "OKP" => {
                let x = URL_SAFE_NO_PAD
                    .decode(self.x.as_deref().unwrap_or(""))
                    .map_err(|e| Error::InvalidInput(format!("bad OKP x: {e}")))?;
                Ok(crate::verify::VerifyingKey::Ed25519Raw(x))
            }
            "oct" => {
                let k = URL_SAFE_NO_PAD
                    .decode(self.k.as_deref().unwrap_or(""))
                    .map_err(|e| Error::InvalidInput(format!("bad oct k: {e}")))?;
                Ok(crate::verify::VerifyingKey::Hmac(k))
            }
            other => Err(Error::InvalidInput(format!("unsupported kty {other}"))),
        }
    }
}

/// Encode RSA n/e as a bare PKCS#1 `RSAPublicKey` SEQUENCE — the format ring
/// expects when you skip the SubjectPublicKeyInfo wrapper.
fn encode_rsa_pkcs1(n: &[u8], e: &[u8]) -> Vec<u8> {
    fn der_int(buf: &mut Vec<u8>, raw: &[u8]) {
        // strip leading zeros, then re-prepend 0x00 if MSB is set
        let mut start = 0;
        while start < raw.len() - 1 && raw[start] == 0 {
            start += 1;
        }
        let body = &raw[start..];
        let mut content: Vec<u8> = Vec::with_capacity(body.len() + 1);
        if body[0] & 0x80 != 0 {
            content.push(0x00);
        }
        content.extend_from_slice(body);
        buf.push(0x02);
        encode_len(buf, content.len());
        buf.extend_from_slice(&content);
    }
    fn encode_len(buf: &mut Vec<u8>, len: usize) {
        if len < 0x80 {
            buf.push(len as u8);
        } else if len < 0x100 {
            buf.push(0x81);
            buf.push(len as u8);
        } else if len < 0x10000 {
            buf.push(0x82);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        } else {
            buf.push(0x83);
            buf.push((len >> 16) as u8);
            buf.push((len >> 8) as u8);
            buf.push(len as u8);
        }
    }
    let mut inner = Vec::with_capacity(n.len() + e.len() + 16);
    der_int(&mut inner, n);
    der_int(&mut inner, e);
    let mut out = Vec::with_capacity(inner.len() + 4);
    out.push(0x30);
    encode_len(&mut out, inner.len());
    out.extend_from_slice(&inner);
    out
}

/// Top-level JWKS document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    /// Available keys.
    pub keys: Vec<Jwk>,
}

impl Jwks {
    /// Look up a key by `kid`.
    #[must_use]
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid.as_deref() == Some(kid))
    }
}

/// Per-host TTL cache for fetched JWKS documents.
#[derive(Debug, Default)]
pub struct JwksCache {
    inner: HashMap<String, (Instant, Duration, Jwks)>,
}

impl JwksCache {
    /// Empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Get a cached entry if still fresh.
    pub fn get(&self, url: &str) -> Option<&Jwks> {
        let (inserted, ttl, jwks) = self.inner.get(url)?;
        if inserted.elapsed() < *ttl {
            Some(jwks)
        } else {
            None
        }
    }

    /// Store an entry with explicit TTL.
    pub fn put(&mut self, url: String, ttl: Duration, jwks: Jwks) {
        self.inner.insert(url, (Instant::now(), ttl, jwks));
    }
}

#[cfg(feature = "jwks")]
mod fetch {
    use super::{Jwks, JwksCache};
    use crate::error::{Error, Result};
    use std::time::Duration;

    /// Fetch a JWKS document over HTTPS using the provided `reqwest` client.
    /// Respects `Cache-Control: max-age` when populating the cache.
    pub async fn fetch_jwks(
        client: &reqwest::Client,
        url: &str,
        cache: Option<&mut JwksCache>,
    ) -> Result<Jwks> {
        if let Some(c) = cache.as_deref() {
            if let Some(j) = c.get(url) {
                return Ok(j.clone());
            }
        }
        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::InvalidInput(format!("jwks fetch failed: {e}")))?
            .error_for_status()
            .map_err(|e| Error::InvalidInput(format!("jwks fetch http error: {e}")))?;

        let ttl = parse_max_age(resp.headers()).unwrap_or(Duration::from_secs(300));
        let jwks: Jwks = resp
            .json()
            .await
            .map_err(|e| Error::InvalidInput(format!("jwks json parse failed: {e}")))?;

        if let Some(c) = cache {
            c.put(url.to_owned(), ttl, jwks.clone());
        }
        Ok(jwks)
    }

    fn parse_max_age(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
        let cc = headers.get(reqwest::header::CACHE_CONTROL)?.to_str().ok()?;
        for part in cc.split(',') {
            let p = part.trim();
            if let Some(v) = p.strip_prefix("max-age=") {
                if let Ok(secs) = v.parse::<u64>() {
                    return Some(Duration::from_secs(secs));
                }
            }
        }
        None
    }
}

#[cfg(feature = "jwks")]
pub use fetch::fetch_jwks;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_rsa_jwks() {
        let json = r#"{
            "keys": [{
                "kty":"RSA","kid":"k1","alg":"RS256","use":"sig",
                "n":"sXchOH","e":"AQAB"
            }]
        }"#;
        let j: Jwks = serde_json::from_str(json).unwrap();
        assert_eq!(j.keys.len(), 1);
        assert_eq!(j.keys[0].kid.as_deref(), Some("k1"));
        assert_eq!(j.find_by_kid("k1").unwrap().kty, "RSA");
        assert!(j.find_by_kid("missing").is_none());
    }

    #[test]
    fn thumbprint_is_stable_for_same_jwk() {
        let j: Jwks = serde_json::from_str(r#"{"keys":[{"kty":"oct","k":"YWJj"}]}"#).unwrap();
        let t1 = j.keys[0].thumbprint().unwrap();
        let t2 = j.keys[0].thumbprint().unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64);
    }
}

//! End-to-end RFC vector + round-trip tests for `jwt-core`.

use jwt_core::parse::{decode_unverified, MAX_SEGMENT_BYTES};
use jwt_core::sign::{self, Algorithm, SigningKey};
use jwt_core::verify::{self, VerificationOptions, VerifyingKey};
use proptest::prelude::*;
use serde_json::json;

#[test]
fn rfc_7519_section_3_1_canonical_example() {
    // RFC 7519 §3.1 reference token; secret is the canonical jwt.io demo value.
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                 eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
                 SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    let outcome = verify::verify(
        token,
        &VerifyingKey::Hmac(b"your-256-bit-secret".to_vec()),
        &VerificationOptions::default(),
    )
    .unwrap();
    assert!(outcome.is_valid(), "{outcome:?}");
}

#[test]
fn round_trip_hs256() {
    let header = json!({"alg":"HS256","typ":"JWT"});
    let payload = json!({"sub":"a","iat":1_700_000_000});
    let token = sign::sign(
        Algorithm::HS256,
        &SigningKey::Hmac(b"secret".to_vec()),
        &header,
        &payload,
    )
    .unwrap();
    let outcome = verify::verify(
        &token,
        &VerifyingKey::Hmac(b"secret".to_vec()),
        &VerificationOptions::default(),
    )
    .unwrap();
    assert!(outcome.is_valid());
}

#[test]
fn round_trip_eddsa() {
    let pkcs8 = sign::generate_keypair_pkcs8(Algorithm::EdDSA).unwrap();
    let header = json!({"alg":"EdDSA"});
    let payload = json!({"sub":"a"});
    use ring::signature::{Ed25519KeyPair, KeyPair};
    let kp = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
    let token = sign::sign(
        Algorithm::EdDSA,
        &SigningKey::Ed25519Pkcs8(pkcs8),
        &header,
        &payload,
    )
    .unwrap();
    let pubkey = kp.public_key().as_ref().to_vec();
    let outcome = verify::verify(
        &token,
        &VerifyingKey::Ed25519Raw(pubkey),
        &VerificationOptions::default(),
    )
    .unwrap();
    assert!(outcome.is_valid());
}

#[test]
fn round_trip_es256() {
    let pkcs8 = sign::generate_keypair_pkcs8(Algorithm::ES256).unwrap();
    let header = json!({"alg":"ES256"});
    let payload = json!({"sub":"a"});
    use ring::rand::SystemRandom;
    use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
    let kp = EcdsaKeyPair::from_pkcs8(
        &ECDSA_P256_SHA256_FIXED_SIGNING,
        &pkcs8,
        &SystemRandom::new(),
    )
    .unwrap();
    let token = sign::sign(
        Algorithm::ES256,
        &SigningKey::EcP256Pkcs8(pkcs8),
        &header,
        &payload,
    )
    .unwrap();
    let pubkey = kp.public_key().as_ref().to_vec();
    let outcome = verify::verify(
        &token,
        &VerifyingKey::EcP256Raw(pubkey),
        &VerificationOptions::default(),
    )
    .unwrap();
    assert!(outcome.is_valid());
}

#[test]
fn flipping_a_signature_byte_invalidates_token() {
    let header = json!({"alg":"HS256"});
    let payload = json!({"sub":"a"});
    let token = sign::sign(
        Algorithm::HS256,
        &SigningKey::Hmac(b"k".to_vec()),
        &header,
        &payload,
    )
    .unwrap();
    let mut bytes = token.into_bytes();
    *bytes.last_mut().unwrap() ^= 0x01;
    let tampered = String::from_utf8(bytes).unwrap();
    let outcome = verify::verify(
        &tampered,
        &VerifyingKey::Hmac(b"k".to_vec()),
        &VerificationOptions::default(),
    )
    .unwrap();
    assert!(!outcome.is_valid());
}

#[test]
fn expired_token_is_rejected() {
    let header = json!({"alg":"HS256"});
    let payload = json!({"sub":"a","exp": 1});
    let token = sign::sign(
        Algorithm::HS256,
        &SigningKey::Hmac(b"k".to_vec()),
        &header,
        &payload,
    )
    .unwrap();
    let outcome = verify::verify(
        &token,
        &VerifyingKey::Hmac(b"k".to_vec()),
        &VerificationOptions::strict(),
    )
    .unwrap();
    assert!(!outcome.is_valid());
}

#[test]
fn algorithm_pinning_rejects_alg_confusion() {
    // Build a HS256 token, then verify with `expected_alg = RS256` — must fail.
    let token = sign::sign(
        Algorithm::HS256,
        &SigningKey::Hmac(b"k".to_vec()),
        &json!({"alg":"HS256"}),
        &json!({"sub":"a"}),
    )
    .unwrap();
    let opts = VerificationOptions {
        expected_alg: Some(Algorithm::RS256),
        ..VerificationOptions::default()
    };
    let outcome = verify::verify(&token, &VerifyingKey::Hmac(b"k".to_vec()), &opts).unwrap();
    assert!(!outcome.is_valid());
}

#[test]
fn segment_size_limit_is_enforced() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    let header = "eyJhbGciOiJIUzI1NiJ9";
    let body = "A".repeat(MAX_SEGMENT_BYTES + 1024);
    let payload = URL_SAFE_NO_PAD.encode(format!("\"{body}\""));
    let token = format!("{header}.{payload}.");
    assert!(decode_unverified(&token).is_err());
}

proptest! {
    /// Any valid JSON object signed and decoded must round-trip exactly.
    #[test]
    fn payload_round_trip(
        sub in "[a-zA-Z0-9_-]{0,64}",
        iat in 0i64..4_611_686_018_427_387_904i64,
    ) {
        let header = json!({"alg":"HS256"});
        let payload = json!({"sub": sub, "iat": iat});
        let token = sign::sign(
            Algorithm::HS256,
            &SigningKey::Hmac(b"k".to_vec()),
            &header,
            &payload,
        ).unwrap();
        let decoded = decode_unverified(&token).unwrap();
        prop_assert_eq!(decoded.payload["sub"].as_str().unwrap_or(""), sub);
        prop_assert_eq!(decoded.payload["iat"].as_i64().unwrap_or(-1), iat);
    }

    /// Random non-token bytes must produce a structured error, never panic.
    #[test]
    fn fuzz_decoder_does_not_panic(s in "\\PC{0,200}") {
        let _ = decode_unverified(&s);
    }
}

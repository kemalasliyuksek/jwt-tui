//! Core JWT primitives shared by the `jwt-tui` binary.
//!
//! This crate is intentionally pure (no I/O, no UI) so it can be embedded in
//! other tools, fuzzed, and audited independently.
//!
//! # Layout
//!
//! - [`parse`] — tokenize a compact JWS, base64url-decode the segments, and
//!   surface a structured [`DecodedToken`].
//! - [`sign`] — produce JWS signatures across HS/RS/ES/EdDSA and `none`.
//! - [`verify`] — verify a token against a key/JWKS with structured failure
//!   reasons.
//! - [`attacks`] — gated security-testing helpers (alg confusion, brute force,
//!   `kid` injection templates, etc.). All of these are explicit opt-ins and
//!   the binary surfaces them only behind `--lab`.
//! - [`jwks`] — JWKS document model and key selection helpers.
//!
//! # Example
//!
//! ```
//! use jwt_core::parse::decode_unverified;
//!
//! let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
//!              eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.\
//!              SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
//! let decoded = decode_unverified(token).unwrap();
//! assert_eq!(decoded.header.alg, "HS256");
//! ```

#![deny(missing_docs)]

pub mod attacks;
pub mod error;
pub mod jwks;
pub mod parse;
pub mod sign;
pub mod verify;

pub use error::{Error, Result};
pub use parse::{DecodedToken, Header, Payload};
pub use sign::{Algorithm, SigningKey};
pub use verify::{VerificationOptions, VerificationOutcome, VerifyError};

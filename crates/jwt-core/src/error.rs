//! Error types for `jwt-core`.

use thiserror::Error;

/// Convenience alias for results returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// All errors that the public API of [`crate`] can return.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The token did not have exactly two `.` separators.
    #[error("malformed token: expected 3 segments, got {0}")]
    SegmentCount(usize),

    /// One of the segments was empty when it shouldn't have been.
    #[error("malformed token: segment {segment} is empty")]
    EmptySegment {
        /// Which segment was empty (`header`, `payload`, or `signature`).
        segment: &'static str,
    },

    /// A segment did not decode as base64url.
    #[error("malformed token: segment {segment} is not valid base64url: {source}")]
    Base64 {
        /// Which segment failed to decode.
        segment: &'static str,
        /// Underlying decoder error.
        source: base64::DecodeError,
    },

    /// The header or payload was not valid UTF-8.
    #[error("malformed token: segment {segment} is not valid UTF-8")]
    Utf8 {
        /// Which segment failed UTF-8 conversion.
        segment: &'static str,
    },

    /// The header or payload was not valid JSON.
    #[error("malformed token: segment {segment} is not valid JSON: {source}")]
    Json {
        /// Which segment failed JSON parsing.
        segment: &'static str,
        /// Underlying serde error.
        source: serde_json::Error,
    },

    /// Header or payload exceeded the configured size limit.
    #[error("malformed token: segment {segment} exceeds {limit} byte limit")]
    SegmentTooLarge {
        /// Which segment was oversized.
        segment: &'static str,
        /// Maximum allowed size in bytes.
        limit: usize,
    },

    /// The header object was missing a required member.
    #[error("invalid header: missing field `{0}`")]
    HeaderMissing(&'static str),

    /// A user-supplied input was wrong (e.g. unknown algorithm).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// A signature operation failed.
    #[error("signing error: {0}")]
    Signing(String),

    /// I/O or file related error (used in higher layers).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Generic JSON encoding error during signing.
    #[error("json encoding error: {0}")]
    JsonEncode(#[from] serde_json::Error),
}

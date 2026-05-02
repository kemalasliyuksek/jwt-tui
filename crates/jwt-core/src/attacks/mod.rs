//! Security-testing helpers.
//!
//! **Lab use only.** The binary surfaces these only behind `--lab` and prints
//! a banner before invoking them. The functions themselves do not enforce
//! that gating — that is the responsibility of the caller — but every public
//! item here is documented as offensive in nature.

pub mod alg_confusion;
pub mod alg_none;
pub mod hs_brute;
pub mod kid_injection;

/// The disclaimer string emitted by every CLI/TUI invocation of an attack.
pub const LAB_BANNER: &str = "[LAB MODE] This feature is for authorized security testing only. \
You are responsible for compliance with applicable laws.";

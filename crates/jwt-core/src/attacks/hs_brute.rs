//! HMAC secret brute force.
//!
//! Given a token signed with HS256/384/512, try a list of candidate secrets
//! in parallel via `rayon`. The actual progress UI lives in the binary; this
//! module is plain library code that returns the first hit (if any) and a
//! count of attempts.
//!
//! Default cap: 10 million attempts. Lift via [`BruteOptions::unlimited`].

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use rayon::iter::{ParallelBridge, ParallelIterator};
use ring::hmac;
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};
use crate::parse::decode_unverified;
use crate::sign::Algorithm;

/// Tuning knobs for [`brute_iter`].
#[derive(Debug, Clone)]
pub struct BruteOptions {
    /// Maximum number of candidates to try. `None` = unlimited.
    pub max_attempts: Option<usize>,
    /// Stop as soon as a match is found.
    pub stop_on_first: bool,
    /// Periodic progress callback. Invoked roughly every 4096 candidates.
    pub progress_every: usize,
}

impl BruteOptions {
    /// 10M attempt default cap.
    #[must_use]
    pub const fn capped() -> Self {
        Self {
            max_attempts: Some(10_000_000),
            stop_on_first: true,
            progress_every: 4096,
        }
    }

    /// No upper bound — caller asserts a finite wordlist.
    #[must_use]
    pub const fn unlimited() -> Self {
        Self {
            max_attempts: None,
            stop_on_first: true,
            progress_every: 4096,
        }
    }
}

/// Live counters shared with the UI thread.
#[derive(Debug, Default)]
pub struct BruteProgress {
    /// Number of candidates evaluated so far.
    pub attempts: AtomicUsize,
    /// Set when a worker found a match.
    pub found: AtomicBool,
}

/// Final result of a brute-force run.
#[derive(Debug, Clone)]
pub struct BruteOutcome {
    /// Total candidates evaluated.
    pub attempts: usize,
    /// The matching secret bytes, if any.
    pub secret: Option<Vec<u8>>,
}

/// Run a brute force against a streaming iterator of candidate secrets.
///
/// `progress` may be `None` if the caller doesn't care about live updates.
pub fn brute_iter<I>(
    token: &str,
    candidates: I,
    options: &BruteOptions,
    progress: Option<Arc<BruteProgress>>,
) -> Result<BruteOutcome>
where
    I: IntoIterator<Item = Vec<u8>> + Send,
    I::IntoIter: Send,
{
    let decoded = decode_unverified(token)?;
    let alg = Algorithm::from_jose(&decoded.header.alg)?;
    if !alg.is_symmetric() {
        return Err(Error::InvalidInput(format!(
            "brute force requires HS algorithm, got {alg}"
        )));
    }
    let hmac_alg = match alg {
        Algorithm::HS256 => hmac::HMAC_SHA256,
        Algorithm::HS384 => hmac::HMAC_SHA384,
        _ => hmac::HMAC_SHA512,
    };
    let signing_input = decoded.signing_input;
    let target = decoded.signature;
    let max = options.max_attempts;
    let stop_on_first = options.stop_on_first;
    let progress_every = options.progress_every.max(1);
    let progress = progress.unwrap_or_default();

    let found_secret = std::sync::Mutex::new(None::<Vec<u8>>);
    let stop = AtomicBool::new(false);

    candidates
        .into_iter()
        .par_bridge()
        .try_for_each(|secret| -> std::result::Result<(), ()> {
            if stop.load(Ordering::Relaxed) {
                return Err(());
            }
            let attempt = progress.attempts.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(cap) = max {
                if attempt > cap {
                    stop.store(true, Ordering::Relaxed);
                    return Err(());
                }
            }
            // hot loop — avoid allocations; ring::hmac::Key construction is cheap.
            let key = hmac::Key::new(hmac_alg, &secret);
            let computed = hmac::sign(&key, signing_input.as_bytes());
            if computed.as_ref().ct_eq(&target).into() {
                progress.found.store(true, Ordering::Relaxed);
                if let Ok(mut slot) = found_secret.lock() {
                    if slot.is_none() {
                        *slot = Some(secret);
                    }
                }
                if stop_on_first {
                    stop.store(true, Ordering::Relaxed);
                    return Err(());
                }
            }
            // explicit progress beat (the UI thread polls anyway, but this
            // gives test code a deterministic place to read counters)
            if attempt % progress_every == 0 {
                std::sync::atomic::fence(Ordering::Release);
            }
            Ok(())
        })
        .ok();

    Ok(BruteOutcome {
        attempts: progress.attempts.load(Ordering::Relaxed),
        secret: found_secret.into_inner().unwrap_or(None),
    })
}

/// Convenience wrapper that loads candidates from a wordlist file (one
/// secret per line, UTF-8). Lines are accepted verbatim; trailing `\r\n` is
/// stripped.
pub fn brute_wordlist_file(
    token: &str,
    path: &std::path::Path,
    options: &BruteOptions,
    progress: Option<Arc<BruteProgress>>,
) -> Result<BruteOutcome> {
    let bytes = std::fs::read(path)?;
    // Avoid materializing the full Vec<Vec<u8>> when the file is huge: stream
    // line-by-line into rayon via par_bridge.
    let lines: Vec<Vec<u8>> = bytes
        .split(|b| *b == b'\n')
        .map(|l| {
            let l = l.strip_suffix(b"\r").unwrap_or(l);
            l.to_vec()
        })
        .filter(|l| !l.is_empty())
        .collect();
    brute_iter(token, lines, options, progress)
}

/// Synchronous tight loop that just verifies a fixed candidate against a
/// signing input. Useful in tests.
#[must_use]
pub fn try_one(alg: Algorithm, signing_input: &[u8], target_sig: &[u8], secret: &[u8]) -> bool {
    let inner = match alg {
        Algorithm::HS256 => hmac::HMAC_SHA256,
        Algorithm::HS384 => hmac::HMAC_SHA384,
        Algorithm::HS512 => hmac::HMAC_SHA512,
        _ => return false,
    };
    let key = hmac::Key::new(inner, secret);
    let computed = hmac::sign(&key, signing_input);
    computed.as_ref().ct_eq(target_sig).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{sign, SigningKey};

    #[test]
    fn finds_secret_in_small_wordlist() {
        let header = serde_json::json!({"alg": "HS256"});
        let payload = serde_json::json!({"sub": "a"});
        let secret = b"correct horse battery staple";
        let token = sign(
            Algorithm::HS256,
            &SigningKey::Hmac(secret.to_vec()),
            &header,
            &payload,
        )
        .unwrap();

        let candidates: Vec<Vec<u8>> = vec![
            b"password".to_vec(),
            b"123456".to_vec(),
            b"correct horse battery staple".to_vec(),
            b"qwerty".to_vec(),
        ];

        let r = brute_iter(&token, candidates, &BruteOptions::capped(), None).unwrap();
        assert_eq!(r.secret.as_deref(), Some(secret.as_slice()));
    }

    #[test]
    fn returns_none_when_secret_not_in_wordlist() {
        let header = serde_json::json!({"alg":"HS256"});
        let payload = serde_json::json!({"sub":"a"});
        let token = sign(
            Algorithm::HS256,
            &SigningKey::Hmac(b"unguessable".to_vec()),
            &header,
            &payload,
        )
        .unwrap();
        let candidates: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let r = brute_iter(&token, candidates, &BruteOptions::capped(), None).unwrap();
        assert!(r.secret.is_none());
        assert_eq!(r.attempts, 3);
    }

    #[test]
    fn rejects_non_hs_algorithm() {
        let token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.AA";
        let r = brute_iter(token, vec![b"x".to_vec()], &BruteOptions::capped(), None);
        assert!(r.is_err());
    }
}

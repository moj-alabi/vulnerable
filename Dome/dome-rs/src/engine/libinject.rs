/// libinjection-based SQL and XSS detection.
///
/// This module uses `libinjectionrs` – a pure-Rust port of the same
/// libinjection library used by ModSecurity, Nginx naxsi, and
/// Cloudflare's WAF.  It operates as a real tokeniser/parser rather
/// than a regex, which means:
///
///   - Catches heavily obfuscated injections that regex misses
///     (e.g. /*!UNION*/ SELECT, 0x53454c454354, CONCAT(0x41,0x42))
///   - Far fewer false positives on normal application data
///   - Produces a human-readable "fingerprint" string (e.g. "s&1o")
///     which categorises the injection type (same as CRS uses for logging)
///
/// Strategy:
///   - Run libinjection FIRST as the authoritative yes/no decision
///   - Keep the regex modules as a secondary fallback / supplementary
///     signal (they catch things libinjection misses, e.g. time-based
///     blind patterns with no SQL structure)

use libinjectionrs::{detect_sqli, detect_xss};
use super::Hit;

const SQLI_SCORE: u32 = 50;
const XSS_SCORE:  u32 = 45;

/// Run libinjection SQLi tokeniser against a single input value.
/// Returns a Hit if injection is detected, including the fingerprint.
pub fn check_sqli(input: &str) -> Option<Hit> {
    if input.len() < 3 { return None; }
    let result = detect_sqli(input.as_bytes());
    if result.is_injection() {
        // Extract fingerprint string for description
        // fingerprint is Option<Fingerprint> – format it as a string
        Some(Hit {
            rule_id:     "LI-SQLI",
            description: "libinjection: SQL injection fingerprint detected",
            category:    "sqli",
            score:       SQLI_SCORE,
        })
    } else {
        None
    }
}

/// Run libinjection XSS tokeniser against a single input value.
pub fn check_xss(input: &str) -> Option<Hit> {
    if input.len() < 3 { return None; }
    let result = detect_xss(input.as_bytes());
    if result.is_injection() {
        Some(Hit {
            rule_id:     "LI-XSS",
            description: "libinjection: XSS payload detected",
            category:    "xss",
            score:       XSS_SCORE,
        })
    } else {
        None
    }
}

/// Convenience: run both SQLi and XSS checks and return all hits.
pub fn check(input: &str) -> Vec<Hit> {
    let mut hits = Vec::with_capacity(2);
    if let Some(h) = check_sqli(input) { hits.push(h); }
    if let Some(h) = check_xss(input)  { hits.push(h); }
    hits
}

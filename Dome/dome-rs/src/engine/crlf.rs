/// CRLF injection / HTTP response splitting detection.
/// Also covers open redirect detection.
use once_cell::sync::Lazy;
use regex::Regex;
use super::Hit;

const SCORE_CRLF: u32 = 35;
const SCORE_REDIRECT: u32 = 20;

static RULES: Lazy<Vec<(Regex, &'static str, &'static str, u32)>> = Lazy::new(|| {
    vec![
        // Literal CRLF / LF injection
        (Regex::new(r"(%0d%0a|%0a%0d|%0d|%0a|\r\n|\r|\n)\s*(set-cookie|location|content-type|x-|status:)").unwrap(),
         "CRLF-001", "CRLF injection with HTTP header name", SCORE_CRLF),

        // URL-encoded variants
        (Regex::new(r"%0[da].*%(3[aA]|3[dD])").unwrap(),
         "CRLF-002", "URL-encoded CRLF with colon/equals (header injection)", SCORE_CRLF),

        // Double-encoded
        (Regex::new(r"%250[da]").unwrap(),
         "CRLF-003", "Double-encoded CRLF", SCORE_CRLF),

        // Unicode/UTF-8 newline variants (U+2028 line separator, U+2029 paragraph separator)
        (Regex::new(r"(\xe2\x80\xa8|\xe2\x80\xa9)").unwrap(),
         "CRLF-004", "Unicode line/paragraph separator injection", SCORE_CRLF),

        // ── Open Redirect ──────────────────────────────────────────────────────
        // ?next= / ?redirect= / ?url= pointing to external domain
        (Regex::new(r"(next|redirect|return|redir|target|url|to|dest|destination|location)\s*=\s*https?://(?!localhost)").unwrap(),
         "REDIR-001", "Open redirect: external URL in redirect parameter", SCORE_REDIRECT),

        // Protocol-relative redirect
        (Regex::new(r"(next|redirect|return|url|to|dest)\s*=\s*//[a-z0-9-]+\.[a-z]{2,}").unwrap(),
         "REDIR-002", "Open redirect: protocol-relative URL", SCORE_REDIRECT),

        // Backslash bypass: ?next=\\evil.com
        (Regex::new(r"(next|redirect|url|to)\s*=\s*(\\\\|%5c%5c|%2f%2f)").unwrap(),
         "REDIR-003", "Open redirect bypass with backslash or double-slash", SCORE_REDIRECT),
    ]
});

pub fn check(normalised: &str) -> Vec<Hit> {
    RULES.iter().filter_map(|(re, id, desc, score)| {
        if re.is_match(normalised) {
            Some(Hit { rule_id: id, description: desc, category: "crlf", score: *score })
        } else {
            None
        }
    }).collect()
}

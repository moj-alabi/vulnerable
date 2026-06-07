/// JA3 / JA4 TLS fingerprint blocklist inspection.
///
/// Dome reads fingerprints from headers injected by a TLS-terminating
/// upstream (nginx, Caddy, HAProxy, Envoy, Cloudflare, etc.).
///
/// nginx example:
///   add_header X-JA3-Fingerprint  $ssl_ja3_hash;
///   add_header X-JA4-Fingerprint  $ssl_ja4;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use super::Hit;

const SCORE: u32 = 40;

// ── Built-in JA3 blocklist ────────────────────────────────────────────────────
static KNOWN_BAD_JA3: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    [
        ("6734f37431670b3ab4292b8f60f29984", "Metasploit Framework"),
        ("bc6c386f480f96b3b6c57ba0b4eb037c", "Metasploit (Ruby SSL)"),
        ("de350869b8c85de67a350c8d186f11e6", "Metasploit (Python)"),
        ("72a589da586844d7f0818ce684948eea", "Cobalt Strike default"),
        ("1d0e413e15f9a5f773b97fce6b3a00ed", "Cobalt Strike (Java)"),
        ("a0e9f5d64349fb13191bc781f81f42e1", "SQLMap"),
        ("3b5074b1b5d032e5620f69f9f700ff0e", "Nmap NSE TLS scan"),
        ("6597d2e0a4d43ff60dc0c4f5d5dc5d35", "Python-requests"),
        ("4e4f44af4f44db17b1a4a2ca7ababf25", "curl"),
    ].iter().cloned().collect()
});

// ── Built-in JA4 prefix blocklist ────────────────────────────────────────────
static KNOWN_BAD_JA4: &[(&str, &str)] = &[
    ("t13d190900_", "Cobalt Strike beacon (JA4 prefix)"),
];

static JA3_HEADERS: &[&str] = &["x-ja3-fingerprint", "x-ja3", "cf-ja3", "fastly-ja3"];
static JA4_HEADERS: &[&str] = &["x-ja4-fingerprint", "x-ja4", "cf-ja4"];

fn get_header<'a>(headers: &'a axum::http::HeaderMap, names: &[&str]) -> Option<&'a str> {
    for name in names {
        if let Some(val) = headers.get(*name).and_then(|v| v.to_str().ok()) {
            return Some(val);
        }
    }
    None
}

pub fn check(
    headers: &axum::http::HeaderMap,
    extra_ja3: &[String],
    extra_ja4_prefixes: &[String],
) -> Vec<Hit> {
    let mut hits = vec![];

    // JA3
    if let Some(ja3) = get_header(headers, JA3_HEADERS) {
        let ja3_lower = ja3.trim().to_lowercase();
        let label = KNOWN_BAD_JA3.get(ja3_lower.as_str())
            .copied()
            .or_else(|| {
                extra_ja3.iter()
                    .find(|h| h.to_lowercase() == ja3_lower)
                    .map(|_| "Custom JA3 blocklist")
            });
        if let Some(label) = label {
            hits.push(Hit {
                rule_id:     "JA3-001",
                description: "Blocked JA3 TLS fingerprint",
                category:    "fingerprint",
                score:       SCORE,
            });
            tracing::warn!(ja3 = %ja3_lower, label = %label, "JA3 fingerprint blocked");
        }
    }

    // JA4
    if let Some(ja4) = get_header(headers, JA4_HEADERS) {
        let ja4 = ja4.trim();
        let blocked = KNOWN_BAD_JA4.iter().any(|(prefix, _)| ja4.starts_with(prefix))
            || extra_ja4_prefixes.iter().any(|p| ja4.starts_with(p.as_str()));
        if blocked {
            hits.push(Hit {
                rule_id:     "JA4-001",
                description: "Blocked JA4 TLS fingerprint",
                category:    "fingerprint",
                score:       SCORE,
            });
        }
    }

    hits
}

/// Server-Side Request Forgery (SSRF) detection.
/// Catches attempts to make the server issue requests to internal/cloud metadata endpoints.
use once_cell::sync::Lazy;
use regex::Regex;
use super::Hit;

const SCORE: u32 = 40;

static RULES: Lazy<Vec<(Regex, &'static str, &'static str)>> = Lazy::new(|| {
    vec![
        // Cloud metadata services
        (Regex::new(r"169\.254\.169\.254").unwrap(),
         "SSRF-001", "AWS/GCP/Azure IMDS endpoint (169.254.169.254)"),
        (Regex::new(r"metadata\.google\.internal").unwrap(),
         "SSRF-002", "GCP metadata endpoint"),
        (Regex::new(r"fd00:ec2::254").unwrap(),
         "SSRF-003", "AWS IPv6 IMDS endpoint"),

        // Private/loopback ranges in URL parameters
        (Regex::new(r"https?://(127\.|10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)").unwrap(),
         "SSRF-004", "URL targeting private IP range"),
        (Regex::new(r"https?://(localhost|local|127\.0\.0\.1)(:\d+)?[/?]").unwrap(),
         "SSRF-005", "URL targeting localhost"),

        // Protocol smuggling
        (Regex::new(r"(dict|gopher|ldap|ldaps|sftp|tftp|ftp|jar)://").unwrap(),
         "SSRF-006", "Non-HTTP protocol in URL parameter"),

        // Decimal/hex/octal IP encoding bypasses
        (Regex::new(r"https?://0x[a-f0-9]{6,8}(/|$)").unwrap(),
         "SSRF-007", "Hex-encoded IP in URL"),
        (Regex::new(r"https?://\d{8,10}(/|$)").unwrap(),
         "SSRF-008", "Decimal-encoded IP in URL"),
        (Regex::new(r"https?://0[0-7]{3}\.[0-7]+\.[0-7]+\.[0-7]+").unwrap(),
         "SSRF-009", "Octal-encoded IP in URL"),

        // DNS rebinding hints
        (Regex::new(r"nip\.io|xip\.io|sslip\.io").unwrap(),
         "SSRF-010", "DNS rebinding service domain"),

        // Cloud metadata path fragments
        (Regex::new(r"/(latest/meta-data|computeMetadata/v1|metadata/instance)").unwrap(),
         "SSRF-011", "Cloud metadata path in parameter"),
    ]
});

pub fn check(normalised: &str) -> Vec<Hit> {
    RULES.iter().filter_map(|(re, id, desc)| {
        if re.is_match(normalised) {
            Some(Hit { rule_id: id, description: desc, category: "ssrf", score: SCORE })
        } else {
            None
        }
    }).collect()
}

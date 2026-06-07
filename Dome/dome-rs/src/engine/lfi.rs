/// Local/Remote File Inclusion detection.
use once_cell::sync::Lazy;
use regex::Regex;
use super::Hit;

const SCORE: u32 = 20;

static RULES: Lazy<Vec<(Regex, &'static str, &'static str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"(\.\./|\.\.\\){2,}").unwrap(),
         "LFI-001", "Directory traversal"),
        (Regex::new(r"(%2e%2e%2f|%2e%2e/|\.\.%2f)+").unwrap(),
         "LFI-002", "URL-encoded path traversal"),
        (Regex::new(r"(%252e%252e|%252f)").unwrap(),
         "LFI-003", "Double URL-encoded traversal"),
        (Regex::new(r"%00").unwrap(),
         "LFI-004", "Null byte injection"),
        (Regex::new(r"(etc/passwd|etc/shadow|etc/hosts|proc/self|win\.ini|boot\.ini|system32)").unwrap(),
         "LFI-005", "Sensitive file path"),
        (Regex::new(r"(php://|phar://|zip://|data://|expect://|file://)").unwrap(),
         "LFI-006", "PHP stream wrapper"),
        (Regex::new(r"\\\\[\w.]+\\").unwrap(),
         "LFI-007", "Windows UNC path"),
        (Regex::new(r"(%c0%ae|%c0af|%e0%80%ae)").unwrap(),
         "LFI-008", "Overlong UTF-8 dot encoding"),
        (Regex::new(r"=\s*https?://").unwrap(),
         "RFI-001", "Remote file inclusion via HTTP"),
        (Regex::new(r"=\s*ftp://").unwrap(),
         "RFI-002", "Remote file inclusion via FTP"),
    ]
});

pub fn check(normalised: &str) -> Vec<Hit> {
    RULES.iter().filter_map(|(re, id, desc)| {
        if re.is_match(normalised) {
            Some(Hit { rule_id: id, description: desc, category: "lfi", score: SCORE })
        } else {
            None
        }
    }).collect()
}

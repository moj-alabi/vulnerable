/// XML External Entity (XXE) injection detection.
/// Catches DOCTYPE declarations and external entity references in XML bodies.
use once_cell::sync::Lazy;
use regex::Regex;
use super::Hit;

const SCORE: u32 = 40;

static RULES: Lazy<Vec<(Regex, &'static str, &'static str)>> = Lazy::new(|| {
    vec![
        // DOCTYPE with SYSTEM or PUBLIC
        (Regex::new(r"<!doctype[^>]*\bsystem\b").unwrap(),
         "XXE-001", "DOCTYPE SYSTEM entity declaration"),
        (Regex::new(r"<!doctype[^>]*\bpublic\b").unwrap(),
         "XXE-002", "DOCTYPE PUBLIC entity declaration"),

        // External entity declaration
        (Regex::new(r"<!entity\s+\S+\s+system\s+").unwrap(),
         "XXE-003", "XML ENTITY SYSTEM declaration"),
        (Regex::new(r"<!entity\s+%\s+\S+\s+system\s+").unwrap(),
         "XXE-004", "XML parameter entity (% entity)"),

        // Sensitive file references in XML
        (Regex::new(r"file:///etc/(passwd|shadow|hosts|hostname)").unwrap(),
         "XXE-005", "XXE targeting sensitive file"),
        (Regex::new(r"file:///proc/(self|version|cmdline)").unwrap(),
         "XXE-006", "XXE targeting /proc"),
        (Regex::new(r"file:///[Cc]:/[Ww]indows/").unwrap(),
         "XXE-007", "XXE targeting Windows system files"),

        // XInclude
        (Regex::new(r"<xi:include\s+href=").unwrap(),
         "XXE-008", "XInclude external reference"),

        // SSRF via XML
        (Regex::new(r"<!entity[^>]*(http|ftp|gopher|dict)://").unwrap(),
         "XXE-009", "XXE with remote URL (SSRF via XML)"),
    ]
});

pub fn check(body: &str) -> Vec<Hit> {
    // Only run on XML-like content (cheap heuristic)
    if !body.contains('<') { return vec![]; }
    let lower = body.to_lowercase();
    RULES.iter().filter_map(|(re, id, desc)| {
        if re.is_match(&lower) {
            Some(Hit { rule_id: id, description: desc, category: "xxe", score: SCORE })
        } else {
            None
        }
    }).collect()
}

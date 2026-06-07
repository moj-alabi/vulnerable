/// Cross-Site Scripting detection – operates on already-normalised input.
use once_cell::sync::Lazy;
use regex::Regex;
use super::Hit;

const SCORE: u32 = 20;

// (pattern, rule_id, description)
static RULES: Lazy<Vec<(Regex, &'static str, &'static str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"<\s*script[^>]*>").unwrap(),
         "XSS-001", "Script tag injection"),
        (Regex::new(r"\bon\w+\s*=\s*['\x22]?").unwrap(),
         "XSS-002", "Inline event handler (on*=)"),
        (Regex::new(r"javascript\s*:").unwrap(),
         "XSS-003", "javascript: URI"),
        (Regex::new(r"vbscript\s*:").unwrap(),
         "XSS-004", "vbscript: URI"),
        (Regex::new(r"data\s*:.*?(base64|text/html)").unwrap(),
         "XSS-005", "data: URI with HTML/script content"),
        (Regex::new(r"expression\s*\(").unwrap(),
         "XSS-006", "CSS expression()"),
        (Regex::new(r"document\.(cookie|write|location|domain)").unwrap(),
         "XSS-007", "DOM manipulation"),
        (Regex::new(r"\b(alert|confirm|prompt)\s*\(").unwrap(),
         "XSS-008", "JS dialog function"),
        (Regex::new(r"<\s*(svg|img|body|iframe|embed|object)[^>]*(on\w+|src\s*=\s*javascript)").unwrap(),
         "XSS-009", "Tag with event/JS attribute"),
        (Regex::new(r"</\s*script\s*>").unwrap(),
         "XSS-010", "Closing script tag"),
        (Regex::new(r"srcdoc\s*=").unwrap(),
         "XSS-011", "srcdoc iframe injection"),
        (Regex::new(r"\b(innerhtml|outerhtml)\s*=").unwrap(),
         "XSS-012", "innerHTML/outerHTML assignment"),
        (Regex::new(r"\beval\s*\(").unwrap(),
         "XSS-013", "eval() call"),
        (Regex::new(r"\$\{[^}]+\}").unwrap(),
         "XSS-014", "Template literal injection"),
    ]
});

pub fn check(normalised: &str) -> Vec<Hit> {
    RULES.iter().filter_map(|(re, id, desc)| {
        if re.is_match(normalised) {
            Some(Hit { rule_id: id, description: desc, category: "xss", score: SCORE })
        } else {
            None
        }
    }).collect()
}

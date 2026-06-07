/// Remote Code / Command Execution detection.
use once_cell::sync::Lazy;
use regex::Regex;
use super::Hit;

const SCORE: u32 = 35;

static RULES: Lazy<Vec<(Regex, &'static str, &'static str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"[;&|`$]\s*(ls|cat|pwd|id|whoami|uname|curl|wget|bash|sh|python|perl|ruby|nc|ncat)\b").unwrap(),
         "RCE-001", "Shell command in parameter"),
        (Regex::new(r"`[^`]+`|\$\([^)]+\)").unwrap(),
         "RCE-002", "Command substitution"),
        (Regex::new(r"\|\s*(bash|sh|zsh|ksh|csh)\b").unwrap(),
         "RCE-003", "Pipe to shell"),
        (Regex::new(r"\beval\s*\(").unwrap(),
         "RCE-004", "eval() call"),
        (Regex::new(r"\b(system|passthru|popen|proc_open|shell_exec|exec|subprocess)\s*\(").unwrap(),
         "RCE-005", "OS command function"),
        (Regex::new(r"base64\s*(-d|--decode).*\|\s*(bash|sh)").unwrap(),
         "RCE-006", "Base64-decoded shell execution"),
        (Regex::new(r"(curl|wget)[^|]+\|\s*(bash|sh|python)").unwrap(),
         "RCE-007", "Download and execute dropper"),
        (Regex::new(r"/dev/tcp/").unwrap(),
         "RCE-008", "Bash /dev/tcp reverse shell"),
        (Regex::new(r"%\{[^}]*\}|#\{[^}]*\}").unwrap(),
         "RCE-009", "OGNL/EL expression injection"),
        (Regex::new(r"\$\{jndi:").unwrap(),
         "RCE-010", "Log4Shell JNDI injection"),
        (Regex::new(r"(\{\{[^}]+\}\}|\{%[^%]+%\})").unwrap(),
         "RCE-011", "Server-side template injection"),
        (Regex::new(r"#\{T\s*\(").unwrap(),
         "RCE-012", "Spring SpEL injection"),
        (Regex::new(r"\b(require|__import__)\s*\(\s*['\x22](os|subprocess|socket)['\x22]\s*\)").unwrap(),
         "RCE-013", "Python/Ruby import exec"),
    ]
});

pub fn check(normalised: &str) -> Vec<Hit> {
    RULES.iter().filter_map(|(re, id, desc)| {
        if re.is_match(normalised) {
            Some(Hit { rule_id: id, description: desc, category: "rce", score: SCORE })
        } else {
            None
        }
    }).collect()
}

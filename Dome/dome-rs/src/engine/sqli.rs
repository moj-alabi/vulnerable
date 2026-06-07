/// SQL injection detection – operates on already-normalised input.
use once_cell::sync::Lazy;
use regex::Regex;
use super::Hit;

const SCORE: u32 = 25;

static RULES: Lazy<Vec<(Regex, &'static str, &'static str)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"union\s.{0,30}select").unwrap(),
         "SQLI-001", "UNION SELECT injection"),
        (Regex::new(r"(and|or)\s+[\w']+\s*[=<>!]+\s*[\w']+").unwrap(),
         "SQLI-002", "Boolean tautology"),
        (Regex::new(r"(--|#)\s*$").unwrap(),
         "SQLI-003", "SQL comment terminator"),
        (Regex::new(r"\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(").unwrap(),
         "SQLI-004", "Time-based blind injection"),
        (Regex::new(r"\binformation_schema\b").unwrap(),
         "SQLI-005", "Information schema enumeration"),
        (Regex::new(r"'?\s*(or|and)\s+'?1'?\s*=\s*'?1").unwrap(),
         "SQLI-006", "Classic tautology or 1=1"),
        (Regex::new(r"[';]\s*(drop|alter|insert|update|delete|exec)\b").unwrap(),
         "SQLI-007", "Destructive statement after quote"),
        (Regex::new(r"\b(xp_cmdshell|sp_executesql)\b").unwrap(),
         "SQLI-008", "MSSQL stored procedure abuse"),
        (Regex::new(r"\b(load_file|into\s+outfile|into\s+dumpfile)\b").unwrap(),
         "SQLI-009", "SQL file read/write"),
        (Regex::new(r"0x[0-9a-f]{4,}").unwrap(),
         "SQLI-010", "Hex-encoded payload"),
        (Regex::new(r";\s*(select|insert|update|delete|drop|exec)\b").unwrap(),
         "SQLI-011", "Stacked queries"),
        (Regex::new(r"\bcase\s+when\b.{0,60}\bthen\b").unwrap(),
         "SQLI-012", "CASE WHEN blind injection"),
        (Regex::new(r"\border\s+by\s+\d+").unwrap(),
         "SQLI-013", "ORDER BY column index probe"),
        (Regex::new(r"(@@version|version\s*\(\s*\)|database\s*\(\s*\)|user\s*\(\s*\))").unwrap(),
         "SQLI-014", "Database fingerprinting"),
    ]
});

pub fn check(normalised: &str) -> Vec<Hit> {
    RULES.iter().filter_map(|(re, id, desc)| {
        if re.is_match(normalised) {
            Some(Hit { rule_id: id, description: desc, category: "sqli", score: SCORE })
        } else {
            None
        }
    }).collect()
}

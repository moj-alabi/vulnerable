/// Response body inspection – data leakage prevention (DLP).
///
/// Scans upstream responses for accidental leakage of:
///   - Stack traces / debug output
///   - SQL / database error messages
///   - API keys, tokens, secrets
///   - Private IPs in responses
///   - Software version banners
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ResponseLeak {
    pub rule_id:     &'static str,
    pub description: &'static str,
    pub category:    &'static str,
}

static RULES: Lazy<Vec<(Regex, &'static str, &'static str)>> = Lazy::new(|| {
    vec![
        // ── Stack traces / debug output ────────────────────────────────────
        (Regex::new(r"(?i)(stack\s*trace|traceback|at\s+\w+\.\w+\(.*:\d+\))").unwrap(),
         "RESP-001", "Stack trace in response body"),
        (Regex::new(r"(?i)(exception|fatal error|unhandled\s+exception)[\s:]").unwrap(),
         "RESP-002", "Exception/fatal error message in response"),
        (Regex::new(r"(?i)debug\s*=\s*true").unwrap(),
         "RESP-003", "Debug mode enabled in response"),

        // ── SQL / DB error messages ────────────────────────────────────────
        (Regex::new(r"(?i)(sql syntax|mysql_fetch|pg_query|sqlite_error|ORA-\d{5}|SQLSTATE\[)").unwrap(),
         "RESP-004", "SQL/database error message in response"),
        (Regex::new(r"(?i)(you have an error in your sql syntax)").unwrap(),
         "RESP-005", "MySQL syntax error in response"),
        (Regex::new(r"(?i)(microsoft OLE DB|ODBC SQL Server driver|SQL Server.*Error)").unwrap(),
         "RESP-006", "MSSQL/ODBC error in response"),

        // ── API keys / tokens ──────────────────────────────────────────────
        (Regex::new(r#"(?i)(api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']?[a-z0-9_\-]{20,}"#).unwrap(),
         "RESP-007", "Possible API key/token leaked in response"),
        // AWS access key pattern
        (Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
         "RESP-008", "AWS access key ID in response"),
        // Private key header
        (Regex::new(r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----").unwrap(),
         "RESP-009", "Private key material in response"),

        // ── Internal IP exposure ───────────────────────────────────────────
        (Regex::new(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b").unwrap(),
         "RESP-010", "Private IP address exposed in response"),

        // ── Software version banners ───────────────────────────────────────
        (Regex::new(r"(?i)(powered\s+by|server:|x-powered-by:)\s*(php|apache|nginx|iis|tomcat|express|rails|django|laravel|wordpress)[/ v\d.]+").unwrap(),
         "RESP-011", "Software version banner in response"),

        // ── Sensitive paths ────────────────────────────────────────────────
        (Regex::new(r"(?i)/etc/(passwd|shadow|hosts)").unwrap(),
         "RESP-012", "Sensitive file path in response"),
    ]
});

pub fn check(body: &str, _status: u16) -> Vec<ResponseLeak> {
    if body.is_empty() { return vec![]; }
    RULES.iter().filter_map(|(re, id, desc)| {
        if re.is_match(body) {
            Some(ResponseLeak { rule_id: id, description: desc, category: "dlp" })
        } else {
            None
        }
    }).collect()
}

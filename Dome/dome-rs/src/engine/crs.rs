/// CRS-equivalent ruleset – OWASP Core Rule Set inspired rules.
///
/// Organised into 4 paranoia levels (matching CRS PL1-PL4):
///   PL1 – High-confidence, very low false-positive rate (production safe)
///   PL2 – Broader patterns, slightly higher FP risk  
///   PL3 – Aggressive detection, needs tuning in production
///   PL4 – Maximum detection, high FP risk (research/lab use)
///
/// Uses Aho-Corasick for substring matching (same approach as CRS's @pmFromFile)
/// and regex for structural patterns.
///
/// Rule categories (matching CRS naming):
///   920 – Protocol enforcement
///   930 – LFI / path traversal
///   931 – RFI
///   932 – RCE / shell injection
///   933 – PHP injection
///   934 – Node.js injection
///   941 – XSS
///   942 – SQLi
///   943 – Session fixation
///   944 – Java deserialization / OGNL
///   949 – Blocking evaluation (score threshold)

use once_cell::sync::Lazy;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::Regex;
use super::Hit;

// ── Aho-Corasick patterns per category ───────────────────────────────────────

/// PL1: High-confidence SQL injection keywords (case-insensitive substring match)
static SQLI_AC_PL1: Lazy<(AhoCorasick, Vec<(&'static str, &'static str, u32)>)> = Lazy::new(|| {
    let patterns: Vec<(&str, &str, u32)> = vec![
        ("union select",     "CRS-942100", 15),
        ("union all select", "CRS-942100", 15),
        ("union distinct select", "CRS-942100", 15),
        ("exec(",            "CRS-942110", 15),
        ("exec xp_",         "CRS-942110", 15),
        ("exec sp_",         "CRS-942110", 15),
        ("insert into",      "CRS-942120", 10),
        ("delete from",      "CRS-942120", 10),
        ("drop table",       "CRS-942130", 20),
        ("drop database",    "CRS-942130", 20),
        ("xp_cmdshell",      "CRS-942140", 25),
        ("sp_executesql",    "CRS-942140", 25),
        ("information_schema", "CRS-942150", 15),
        ("sys.objects",      "CRS-942150", 15),
        ("sys.columns",      "CRS-942150", 15),
        ("load_file(",       "CRS-942160", 20),
        ("into outfile",     "CRS-942160", 20),
        ("into dumpfile",    "CRS-942160", 20),
        ("benchmark(",       "CRS-942170", 15),
        ("sleep(",           "CRS-942170", 10),
        ("waitfor delay",    "CRS-942170", 15),
        ("pg_sleep(",        "CRS-942170", 15),
        ("@@version",        "CRS-942180", 10),
        ("@@datadir",        "CRS-942180", 10),
        ("@@hostname",       "CRS-942180", 10),
        ("char(0x",          "CRS-942190", 15),
        ("0x53454c454354",   "CRS-942190", 20),  // hex "SELECT"
        ("0x554e494f4e",     "CRS-942190", 20),  // hex "UNION"
    ];
    let strs: Vec<&str> = patterns.iter().map(|(p, _, _)| *p).collect();
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&strs)
        .unwrap();
    (ac, patterns)
});

/// PL1: High-confidence XSS patterns (AC substring)
static XSS_AC_PL1: Lazy<(AhoCorasick, Vec<(&'static str, &'static str, u32)>)> = Lazy::new(|| {
    let patterns: Vec<(&str, &str, u32)> = vec![
        ("<script",              "CRS-941100", 15),
        ("</script>",            "CRS-941100", 15),
        ("javascript:",          "CRS-941110", 15),
        ("vbscript:",            "CRS-941110", 15),
        ("onload=",              "CRS-941120", 10),
        ("onerror=",             "CRS-941120", 10),
        ("onclick=",             "CRS-941120", 10),
        ("onmouseover=",         "CRS-941120", 10),
        ("onfocus=",             "CRS-941120", 10),
        ("onblur=",              "CRS-941120", 10),
        ("expression(",          "CRS-941130", 15),
        ("document.cookie",      "CRS-941140", 15),
        ("document.write(",      "CRS-941140", 15),
        ("document.location",    "CRS-941140", 10),
        ("window.location",      "CRS-941140", 10),
        ("<iframe",              "CRS-941150", 10),
        ("<object",              "CRS-941150", 10),
        ("<embed",               "CRS-941150", 10),
        ("<applet",              "CRS-941150", 10),
        ("srcdoc=",              "CRS-941160", 15),
        ("data:text/html",       "CRS-941170", 15),
        ("data:application/x-javascript", "CRS-941170", 20),
        ("&#x",                  "CRS-941180", 10),
        ("\\u003c",              "CRS-941180", 10),  // \u003c = <
        ("\\u003e",              "CRS-941180", 10),  // \u003e = >
        (".innerHTML",           "CRS-941190", 15),
        (".outerHTML",           "CRS-941190", 15),
        ("insertAdjacentHTML",   "CRS-941190", 15),
    ];
    let strs: Vec<&str> = patterns.iter().map(|(p, _, _)| *p).collect();
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&strs)
        .unwrap();
    (ac, patterns)
});

/// PL1: RCE / shell injection (AC)
static RCE_AC_PL1: Lazy<(AhoCorasick, Vec<(&'static str, &'static str, u32)>)> = Lazy::new(|| {
    let patterns: Vec<(&str, &str, u32)> = vec![
        (";cat ",            "CRS-932100", 20),
        (";id;",             "CRS-932100", 20),
        (";id ",             "CRS-932100", 20),
        (";whoami",          "CRS-932100", 20),
        ("|cat ",            "CRS-932100", 15),
        ("|id ",             "CRS-932100", 15),
        ("|whoami",          "CRS-932100", 15),
        ("$(id)",            "CRS-932110", 25),
        ("$(whoami)",        "CRS-932110", 25),
        ("`id`",             "CRS-932110", 25),
        ("`whoami`",         "CRS-932110", 25),
        ("/etc/passwd",      "CRS-932120", 20),
        ("/etc/shadow",      "CRS-932120", 25),
        ("/bin/bash",        "CRS-932130", 15),
        ("/bin/sh",          "CRS-932130", 15),
        ("/dev/tcp/",        "CRS-932140", 25),
        ("/dev/udp/",        "CRS-932140", 25),
        ("${jndi:",          "CRS-932150", 40),  // Log4Shell
        ("${${::-j}",        "CRS-932150", 40),  // Log4Shell obfuscated
        ("${${lower:j}",     "CRS-932150", 40),
        ("passthru(",        "CRS-932160", 20),
        ("system(",          "CRS-932160", 15),
        ("shell_exec(",      "CRS-932160", 20),
        ("proc_open(",       "CRS-932160", 20),
        ("popen(",           "CRS-932160", 15),
    ];
    let strs: Vec<&str> = patterns.iter().map(|(p, _, _)| *p).collect();
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&strs)
        .unwrap();
    (ac, patterns)
});

/// PL1: PHP injection (AC)
static PHP_AC_PL1: Lazy<(AhoCorasick, Vec<(&'static str, &'static str, u32)>)> = Lazy::new(|| {
    let patterns: Vec<(&str, &str, u32)> = vec![
        ("<?php",            "CRS-933100", 20),
        ("<?=",              "CRS-933100", 15),
        ("base64_decode(",   "CRS-933110", 15),
        ("str_rot13(",       "CRS-933110", 10),
        ("gzinflate(",       "CRS-933110", 15),
        ("gzuncompress(",    "CRS-933110", 15),
        ("eval(",            "CRS-933120", 15),
        ("assert(",          "CRS-933120", 10),
        ("preg_replace(",    "CRS-933130", 10),
        ("call_user_func(",  "CRS-933130", 15),
        ("call_user_func_array(", "CRS-933130", 15),
        ("create_function(", "CRS-933130", 20),
        ("include(",         "CRS-933140", 10),
        ("include_once(",    "CRS-933140", 10),
        ("require(",         "CRS-933140", 10),
        ("require_once(",    "CRS-933140", 10),
        ("file_get_contents(", "CRS-933150", 15),
        ("file_put_contents(", "CRS-933150", 15),
        ("phpinfo()",        "CRS-933160", 20),
        ("phpinfo (",        "CRS-933160", 20),
    ];
    let strs: Vec<&str> = patterns.iter().map(|(p, _, _)| *p).collect();
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&strs)
        .unwrap();
    (ac, patterns)
});

/// PL1: Java deserialization / OGNL / Spring SpEL (AC)
static JAVA_AC_PL1: Lazy<(AhoCorasick, Vec<(&'static str, &'static str, u32)>)> = Lazy::new(|| {
    let patterns: Vec<(&str, &str, u32)> = vec![
        ("java.lang.runtime",        "CRS-944100", 30),
        ("java.lang.processbuilder", "CRS-944100", 30),
        ("java.io.fileinputstream",  "CRS-944110", 25),
        ("java.io.fileoutputstream","CRS-944110", 25),
        ("(runtime.getruntime()",   "CRS-944120", 30),
        ("#{t(",                    "CRS-944130", 30),  // SpEL
        ("%{(#",                    "CRS-944140", 30),  // OGNL
        ("ognl.ognl",               "CRS-944140", 30),
        ("com.opensymphony.xwork2", "CRS-944140", 25),
        ("weblogic",                "CRS-944150", 20),
        ("jndi:ldap://",            "CRS-944160", 40),
        ("jndi:rmi://",             "CRS-944160", 40),
        ("jndi:dns://",             "CRS-944160", 35),
    ];
    let strs: Vec<&str> = patterns.iter().map(|(p, _, _)| *p).collect();
    let ac = AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::LeftmostFirst)
        .build(&strs)
        .unwrap();
    (ac, patterns)
});

/// PL2: Additional SQLi patterns (structural, higher FP risk)
static SQLI_REGEX_PL2: Lazy<Vec<(Regex, &'static str, &'static str, u32)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"(?i)\b(select|insert|update|delete|replace|truncate)\b.{0,20}\bfrom\b").unwrap(),
         "CRS-942200", "SQL DML with FROM clause", 10),
        (Regex::new(r"(?i)'[^']*'\s*=\s*'[^']*'").unwrap(),
         "CRS-942210", "SQL string comparison tautology", 15),
        (Regex::new(r"(?i)\b(having|group\s+by|order\s+by)\b.{0,30}\d").unwrap(),
         "CRS-942220", "SQL aggregation in parameter", 10),
        (Regex::new(r"(?i)\bconvert\s*\(.*using\b").unwrap(),
         "CRS-942230", "SQL CONVERT with charset bypass", 15),
        (Regex::new(r"(?i)collate\s+\w+_bin").unwrap(),
         "CRS-942240", "SQL COLLATE binary bypass", 15),
        (Regex::new(r"(?i)\bwhere\b.{0,50}\blike\b.{0,10}['%_]").unwrap(),
         "CRS-942250", "SQL LIKE pattern injection", 10),
    ]
});

/// PL2: Additional XSS patterns
static XSS_REGEX_PL2: Lazy<Vec<(Regex, &'static str, &'static str, u32)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"(?i)<\s*(svg|math)\b[^>]*>").unwrap(),
         "CRS-941200", "SVG/MathML tag (potential XSS vector)", 10),
        (Regex::new(r"(?i)\bsetTimeout\s*\(").unwrap(),
         "CRS-941210", "setTimeout XSS", 10),
        (Regex::new(r"(?i)\bsetInterval\s*\(").unwrap(),
         "CRS-941210", "setInterval XSS", 10),
        (Regex::new(r"(?i)\bFunction\s*\(").unwrap(),
         "CRS-941220", "Function constructor XSS", 15),
        (Regex::new("(?i)\\[['\"](src|href|action)['\"]").unwrap(),
         "CRS-941230", "DOM property access via bracket notation", 10),
        (Regex::new(r#"(?i)url\s*\(\s*['"]?javascript:"#).unwrap(),
         "CRS-941240", "CSS url() with javascript:", 20),
    ]
});

/// PL3: Protocol anomalies (higher paranoia)
static PROTO_REGEX_PL3: Lazy<Vec<(Regex, &'static str, &'static str, u32)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"(?i)%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}").unwrap(),
         "CRS-920300", "Excessive URL encoding (4+ consecutive encoded chars)", 10),
        (Regex::new(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]").unwrap(),
         "CRS-920300", "Non-printable ASCII control character in request", 15),
        (Regex::new(r"(?i)(http|https)://[^/]*@").unwrap(),
         "CRS-920310", "HTTP URL with @ (credential bypass)", 20),
        (Regex::new(r"(?i)\.\./.*\.\./.*\.\./").unwrap(),
         "CRS-920320", "Triple path traversal sequence", 20),
    ]
});

/// PL4: SSTI patterns (aggressive, higher FP)
static SSTI_REGEX_PL4: Lazy<Vec<(Regex, &'static str, &'static str, u32)>> = Lazy::new(|| {
    vec![
        (Regex::new(r"\{\{.{1,100}\}\}").unwrap(),
         "CRS-945100", "Jinja2/Twig/Handlebars template expression", 20),
        (Regex::new(r"\{%.{1,100}%\}").unwrap(),
         "CRS-945100", "Django/Jinja2 template tag", 20),
        (Regex::new(r"(?i)<\#.{1,100}>").unwrap(),
         "CRS-945110", "FreeMarker template expression", 20),
        (Regex::new(r"(?i)\$\{.{1,100}\}").unwrap(),
         "CRS-945120", "Generic EL/Thymeleaf/Spring expression", 15),
        (Regex::new(r"(?i)<%=.{1,100}%>").unwrap(),
         "CRS-945130", "JSP/ERB expression tag", 15),
        (Regex::new(r"(?i)\{\{.{0,20}__class__").unwrap(),
         "CRS-945140", "Python SSTI class escape", 30),
        (Regex::new(r"(?i)\{\{.{0,20}config\.").unwrap(),
         "CRS-945150", "Flask/Jinja2 config object access", 30),
    ]
});

// ── Public entry point ────────────────────────────────────────────────────────

/// Run all CRS-equivalent rules at or below `paranoia_level` (1-4).
/// Returns a deduplicated list of hits.
pub fn check(input: &str, paranoia_level: u8) -> Vec<Hit> {
    let mut hits = Vec::new();
    let lower = input.to_lowercase();
    let bytes = lower.as_bytes();

    // ── PL1: AC-based checks (always run) ─────────────────────────────────
    run_ac(&SQLI_AC_PL1, bytes, &mut hits, "sqli");
    run_ac(&XSS_AC_PL1, bytes, &mut hits, "xss");
    run_ac(&RCE_AC_PL1, bytes, &mut hits, "rce");
    run_ac(&PHP_AC_PL1, bytes, &mut hits, "rce");
    run_ac(&JAVA_AC_PL1, bytes, &mut hits, "rce");

    // ── PL2: structural regex ──────────────────────────────────────────────
    if paranoia_level >= 2 {
        run_regex(&SQLI_REGEX_PL2, &lower, &mut hits, "sqli");
        run_regex(&XSS_REGEX_PL2, &lower, &mut hits, "xss");
    }

    // ── PL3: protocol anomalies ────────────────────────────────────────────
    if paranoia_level >= 3 {
        run_regex(&PROTO_REGEX_PL3, input, &mut hits, "protocol");
    }

    // ── PL4: SSTI ─────────────────────────────────────────────────────────
    if paranoia_level >= 4 {
        run_regex(&SSTI_REGEX_PL4, input, &mut hits, "rce");
    }

    hits
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn run_ac(
    lazy: &Lazy<(AhoCorasick, Vec<(&'static str, &'static str, u32)>)>,
    bytes: &[u8],
    hits: &mut Vec<Hit>,
    category: &'static str,
) {
    let (ac, patterns) = &**lazy;
    // Collect unique pattern indices that matched
    let mut matched = std::collections::HashSet::new();
    for mat in ac.find_iter(bytes) {
        matched.insert(mat.pattern().as_usize());
    }
    for idx in matched {
        let (desc, rule_id, score) = patterns[idx];
        hits.push(Hit {
            rule_id,
            description: desc,
            category,
            score,
        });
    }
}

fn run_regex(
    rules: &Lazy<Vec<(Regex, &'static str, &'static str, u32)>>,
    input: &str,
    hits: &mut Vec<Hit>,
    _category: &'static str,
) {
    for (re, rule_id, desc, score) in &**rules {
        if re.is_match(input) {
            hits.push(Hit {
                rule_id,
                description: desc,
                category: _category,
                score: *score,
            });
        }
    }
}

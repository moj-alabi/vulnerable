/// Scanner / automated tool detection.
use once_cell::sync::Lazy;
use regex::Regex;
use super::Hit;

const SCORE_UA:   u32 = 15;
const SCORE_PATH: u32 = 10;

// Known scanner User-Agent substrings (lowercase)
static SCANNER_UAS: &[&str] = &[
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "dirb", "gobuster",
    "wfuzz", "ffuf", "burpsuite", "burp ", "owasp zap", "zaproxy",
    "acunetix", "nessus", "openvas", "metasploit", "msfconsole",
    "havij", "pangolin", "w3af", "skipfish", "arachni",
    "python-requests", "go-http-client", "libwww-perl", "lwp-trivial",
    "nuclei", "dalfox", "commix", "hydra", "medusa",
    "zgrab", "xsser", "wpscan", "joomscan",
];

static SCAN_PATHS: Lazy<Vec<Regex>> = Lazy::new(|| {
    [
        r"(?i)/\.git/",
        r"(?i)/\.env$",
        r"(?i)/wp-login\.php",
        r"(?i)/xmlrpc\.php",
        r"(?i)/phpmyadmin",
        r"(?i)/(etc|proc)/",
        r"(?i)/shell\.(php|asp|aspx|jsp)",
        r"(?i)/(c99|r57|b374k|webshell)",
        r"(?i)/eval-stdin",
        r"(?i)/actuator/(env|heapdump|mappings|beans|dump)",
        r"(?i)/__debugbar",
        r"(?i)/\.htaccess",
        r"(?i)/\.svn/",
        r"(?i)/backup\.(zip|tar|gz|sql)",
        r"(?i)/config\.(php|yml|yaml|json|bak)",
        r"(?i)/wp-content/debug\.log",
        r"(?i)/server-status",
        r"(?i)/manager/html",   // Tomcat
        r"(?i)/solr/admin",
        r"(?i)/jmx-console",
        r"(?i)/console/login",  // JBoss
    ].iter().map(|p| Regex::new(p).unwrap()).collect()
});

pub fn check_ua(ua: &str) -> Vec<Hit> {
    let lower = ua.to_lowercase();
    for sig in SCANNER_UAS {
        if lower.contains(sig) {
            return vec![Hit {
                rule_id:     "SCAN-001",
                description: "Known scanner/exploit-tool User-Agent",
                category:    "scanner",
                score:       SCORE_UA,
            }];
        }
    }
    vec![]
}

pub fn check_path(path: &str) -> Vec<Hit> {
    for pat in SCAN_PATHS.iter() {
        if pat.is_match(path) {
            return vec![Hit {
                rule_id:     "SCAN-002",
                description: "Scanner probe path detected",
                category:    "scanner",
                score:       SCORE_PATH,
            }];
        }
    }
    vec![]
}

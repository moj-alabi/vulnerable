"""Scanner / automated tool detection rules."""
import re

# Known scanner / exploit-tool User-Agent substrings (lowercase)
SCANNER_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster", "dirb", "gobuster",
    "wfuzz", "ffuf", "burpsuite", "burp ", "owasp zap", "zaproxy",
    "acunetix", "nessus", "openvas", "metasploit", "msfconsole",
    "havij", "pangolin", "w3af", "skipfish", "arachni",
    "python-requests", "go-http-client", "libwww-perl", "lwp-trivial",
    "curl/", "wget/", "httpie", "nuclei", "dalfox", "commix",
]

# Paths that scanners probe (case-insensitive)
SCAN_PATHS = [
    r"(?i)/\.git/",
    r"(?i)/\.env",
    r"(?i)/wp-login\.php",
    r"(?i)/xmlrpc\.php",
    r"(?i)/admin/config",
    r"(?i)/phpmyadmin",
    r"(?i)/(etc|proc)/",
    r"(?i)/shell\.(php|asp|aspx|jsp)",
    r"(?i)/c99|r57|b374k",           # known webshell names
    r"(?i)/eval-stdin",
    r"(?i)/actuator/(env|heapdump|mappings|beans)",   # Spring Boot
    r"(?i)/__debugbar",
    r"(?i)/\.htaccess",
]

COMPILED_PATHS = [re.compile(p) for p in SCAN_PATHS]


def check_ua(ua: str) -> list[dict]:
    """Check User-Agent for scanner signatures."""
    hits = []
    ua_lower = ua.lower()
    for sig in SCANNER_UA:
        if sig in ua_lower:
            hits.append({
                "rule_id": "SCAN-001",
                "description": f"Known scanner User-Agent: {sig}",
                "category": "scanner",
            })
            break
    return hits


def check_path(path: str) -> list[dict]:
    """Check URL path for known probe/scanner patterns."""
    hits = []
    for pattern in COMPILED_PATHS:
        if pattern.search(path):
            hits.append({
                "rule_id": "SCAN-002",
                "description": f"Scanner probe path: {path}",
                "category": "scanner",
            })
            break
    return hits

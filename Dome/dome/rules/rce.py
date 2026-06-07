"""Remote Code / Command Execution detection rules."""
import re

PATTERNS = [
    # Shell metacharacters in param values
    (r"[;&|`$]\s*(ls|cat|pwd|id|whoami|uname|curl|wget|bash|sh|python|perl|ruby|nc|ncat)\b",
                                                                     "RCE-001", "Shell command in parameter"),
    # Backtick / $() command substitution
    (r"`[^`]+`|\$\([^)]+\)",                                         "RCE-002", "Command substitution"),
    # Pipe to shell
    (r"\|\s*(bash|sh|zsh|ksh|csh)\b",                                "RCE-003", "Pipe to shell"),
    # eval with encoded content
    (r"(?i)\beval\s*\(",                                             "RCE-004", "eval() call"),
    # OS command functions (PHP/Python/etc)
    (r"(?i)\b(system|passthru|popen|proc_open|shell_exec|exec|subprocess)\s*\(", "RCE-005", "OS command function"),
    # Base64-encoded payloads piped to bash
    (r"(?i)base64\s*(-d|--decode).*?\|\s*(bash|sh)",                 "RCE-006", "Base64-decoded shell execution"),
    # curl/wget piped to shell (dropper pattern)
    (r"(?i)(curl|wget)[^|]+\|\s*(bash|sh|python)",                   "RCE-007", "Download and execute dropper"),
    # /dev/tcp reverse shell
    (r"/dev/tcp/",                                                   "RCE-008", "Bash /dev/tcp reverse shell"),
    # OGNL injection (Struts/Java)
    (r"(?i)%\{[^}]*\}|#\{[^}]*\}",                                  "RCE-009", "OGNL/EL expression injection"),
    # Log4Shell / JNDI
    (r"(?i)\$\{jndi:",                                               "RCE-010", "Log4Shell JNDI injection"),
]

COMPILED = [(re.compile(p), rid, desc) for p, rid, desc in PATTERNS]


def check(value: str) -> list[dict]:
    hits = []
    for pattern, rule_id, description in COMPILED:
        if pattern.search(value):
            hits.append({"rule_id": rule_id, "description": description, "category": "rce"})
    return hits

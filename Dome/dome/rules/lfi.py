"""Local/Remote File Inclusion detection rules."""
import re

PATTERNS = [
    # Directory traversal sequences
    (r"(\.\./|\.\.\\){2,}",                                         "LFI-001", "Directory traversal (../)"),
    # URL-encoded traversal
    (r"(%2e%2e%2f|%2e%2e/|\.\.%2f){1,}",                           "LFI-002", "URL-encoded path traversal"),
    # Double URL-encoded
    (r"(%252e%252e|%252f)",                                          "LFI-003", "Double URL-encoded traversal"),
    # Null byte injection
    (r"%00|\\x00|\x00",                                              "LFI-004", "Null byte injection"),
    # Sensitive file access
    (r"(?i)(etc/passwd|etc/shadow|etc/hosts|proc/self|win\.ini|boot\.ini|system32)", "LFI-005", "Sensitive file path"),
    # PHP wrappers
    (r"(?i)(php://|phar://|zip://|data://|expect://|file://)",       "LFI-006", "PHP stream wrapper"),
    # Remote file inclusion (http/https/ftp in a param)
    (r"(?i)=\s*https?://",                                           "RFI-001", "Remote file inclusion via HTTP"),
    (r"(?i)=\s*ftp://",                                              "RFI-002", "Remote file inclusion via FTP"),
]

COMPILED = [(re.compile(p), rid, desc) for p, rid, desc in PATTERNS]


def check(value: str) -> list[dict]:
    hits = []
    for pattern, rule_id, description in COMPILED:
        if pattern.search(value):
            hits.append({"rule_id": rule_id, "description": description, "category": "lfi"})
    return hits

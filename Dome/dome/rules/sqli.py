"""SQL Injection detection rules."""
import re

# Patterns ordered from high-confidence to heuristic
PATTERNS = [
    # Classic UNION-based
    (r"(?i)\bunion\b.{0,20}\bselect\b",                          "SQLI-001", "UNION SELECT injection"),
    # Boolean-based blind
    (r"(?i)\b(and|or)\b\s+[\w'\"]+\s*[=<>!]+\s*[\w'\"]+",       "SQLI-002", "Boolean-based blind SQLi"),
    # Stacked queries / comment sequences
    (r"(--|#|/\*.*?\*/)\s*$",                                     "SQLI-003", "SQL comment terminator"),
    # Sleep / time-based blind
    (r"(?i)\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(",   "SQLI-004", "Time-based blind SQLi"),
    # INFORMATION_SCHEMA probing
    (r"(?i)\binformation_schema\b",                               "SQLI-005", "Schema enumeration"),
    # Common SQLi payloads
    (r"(?i)'?\s*(OR|AND)\s+'?1'?\s*=\s*'?1",                     "SQLI-006", "Tautology (1=1)"),
    # Quote + keyword
    (r"(?i)['\"];\s*(DROP|ALTER|INSERT|UPDATE|DELETE|EXEC)\b",   "SQLI-007", "Destructive statement after quote"),
    # xp_cmdshell / sp_executesql
    (r"(?i)\b(xp_cmdshell|sp_executesql|exec\s*\()",             "SQLI-008", "MSSQL stored procedure abuse"),
    # Load/outfile
    (r"(?i)\b(load_file|into\s+outfile|into\s+dumpfile)\b",      "SQLI-009", "File read/write via SQL"),
    # Hex encoding bypass
    (r"(?i)0x[0-9a-f]{4,}",                                      "SQLI-010", "Hex-encoded payload"),
]

COMPILED = [(re.compile(p), rid, desc) for p, rid, desc in PATTERNS]


def check(value: str) -> list[dict]:
    hits = []
    for pattern, rule_id, description in COMPILED:
        if pattern.search(value):
            hits.append({"rule_id": rule_id, "description": description, "category": "sqli"})
    return hits

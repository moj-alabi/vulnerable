"""Cross-Site Scripting (XSS) detection rules."""
import re

PATTERNS = [
    # Basic script tag
    (r"(?i)<\s*script[^>]*>",                                        "XSS-001", "Script tag injection"),
    # Event handlers
    (r"(?i)\bon\w+\s*=\s*['\"]?.*?['\"]?",                           "XSS-002", "Inline event handler"),
    # javascript: URI
    (r"(?i)javascript\s*:",                                          "XSS-003", "javascript: URI scheme"),
    # vbscript: URI
    (r"(?i)vbscript\s*:",                                            "XSS-004", "vbscript: URI scheme"),
    # data: URI with script
    (r"(?i)data\s*:.*?(base64|text/html)",                           "XSS-005", "data: URI potential XSS"),
    # expression() (IE CSS)
    (r"(?i)expression\s*\(",                                         "XSS-006", "CSS expression()"),
    # document.cookie / document.write
    (r"(?i)document\.(cookie|write|location|domain)",                "XSS-007", "DOM manipulation"),
    # alert/confirm/prompt
    (r"(?i)\b(alert|confirm|prompt)\s*\(",                           "XSS-008", "JS dialog function"),
    # SVG with script/event
    (r"(?i)<\s*(svg|img|body|iframe|embed|object)[^>]*(on\w+|src\s*=\s*['\"]?javascript)", "XSS-009", "Tag+event/JS attribute"),
    # HTML entity obfuscation of <script
    (r"(?i)(&lt;|&#x3c;|&#60;)\s*script",                           "XSS-010", "Entity-encoded script tag"),
]

COMPILED = [(re.compile(p), rid, desc) for p, rid, desc in PATTERNS]


def check(value: str) -> list[dict]:
    hits = []
    for pattern, rule_id, description in COMPILED:
        if pattern.search(value):
            hits.append({"rule_id": rule_id, "description": description, "category": "xss"})
    return hits

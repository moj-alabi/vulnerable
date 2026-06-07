"""
JA3 / JA4 TLS fingerprint inspection.

How Dome gets TLS fingerprints
──────────────────────────────
Dome is an HTTP-layer proxy and cannot parse raw TLS ClientHello packets
itself.  There are two supported modes:

  1. Header injection (recommended)
     A TLS-terminating proxy upstream (nginx with ngx_http_ssl_module +
     ja3 patch, HAProxy, Caddy, Envoy, etc.) adds the fingerprint as an
     HTTP header before forwarding to Dome.

     nginx example:
       ssl_preread on;
       add_header X-JA3-Fingerprint  $ssl_ja3_hash;
       add_header X-JA4-Fingerprint  $ssl_ja4;

     Supported header names (first match wins):
       X-JA3-Fingerprint, X-JA3, CF-JA3 (Cloudflare), Fastly-JA3

  2. Known-bad hash blocklist
     Dome ships with a small built-in list of JA3 hashes associated with
     known malware / exploit frameworks.  Add your own in config.yml.

JA3 format:   32-char hex MD5  e.g. "a0e9f5d64349fb13191bc781f81f42e1"
JA4 format:   "t13d1516h2_..."  (FoxIO spec, variable length)
"""
from __future__ import annotations
import re

# ── Built-in blocklist ────────────────────────────────────────────────────────
# Sources: Salesforce JA3 dataset, GreyNoise, public threat intel.
# These are hashes observed in pen-test / malware tooling – NOT guaranteed
# to be exhaustive.  Add your own via config.yml  waf.blocked_ja3.

KNOWN_BAD_JA3: dict[str, str] = {
    # Metasploit / Meterpreter
    "6734f37431670b3ab4292b8f60f29984": "Metasploit Framework",
    "bc6c386f480f96b3b6c57ba0b4eb037c": "Metasploit (Ruby SSL)",
    "de350869b8c85de67a350c8d186f11e6": "Metasploit (Python)",
    # Cobalt Strike
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike default",
    "1d0e413e15f9a5f773b97fce6b3a00ed": "Cobalt Strike (Java)",
    # SQLMap / exploit tools
    "a0e9f5d64349fb13191bc781f81f42e1": "SQLMap",
    # Nmap NSE
    "3b5074b1b5d032e5620f69f9f700ff0e": "Nmap NSE TLS scan",
    # Python requests (common in automation/scripts – flag but don't block by default)
    "6597d2e0a4d43ff60dc0c4f5d5dc5d35": "Python-requests",
    # curl (informational)
    "4e4f44af4f44db17b1a4a2ca7ababf25": "curl",
}

# JA4 prefix blocklist (match on the first N chars of the JA4 string)
KNOWN_BAD_JA4_PREFIXES: list[tuple[str, str]] = [
    # Cobalt Strike beacon
    ("t13d190900_", "Cobalt Strike beacon (JA4 prefix)"),
]

_JA3_HEADERS = ["X-JA3-Fingerprint", "X-JA3", "CF-JA3", "Fastly-JA3"]
_JA4_HEADERS = ["X-JA4-Fingerprint", "X-JA4", "CF-JA4"]
_JA3_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


def _extract_ja3(headers: dict[str, str]) -> str | None:
    for h in _JA3_HEADERS:
        val = headers.get(h, "").strip().lower()
        if val and _JA3_RE.match(val):
            return val
    return None


def _extract_ja4(headers: dict[str, str]) -> str | None:
    for h in _JA4_HEADERS:
        val = headers.get(h, "").strip()
        if val:
            return val
    return None


def check(
    headers: dict[str, str],
    extra_blocked_ja3: list[str] | None = None,
    extra_blocked_ja4_prefixes: list[str] | None = None,
) -> list[dict]:
    """
    Inspect JA3/JA4 fingerprints from request headers.
    Returns a list of hit dicts (empty = clean).
    """
    hits: list[dict] = []
    blocked_ja3 = {**KNOWN_BAD_JA3}
    if extra_blocked_ja3:
        for h in extra_blocked_ja3:
            blocked_ja3[h.lower()] = "Custom blocklist"

    blocked_ja4 = list(KNOWN_BAD_JA4_PREFIXES)
    if extra_blocked_ja4_prefixes:
        for p in extra_blocked_ja4_prefixes:
            blocked_ja4.append((p, "Custom JA4 blocklist"))

    ja3 = _extract_ja3(headers)
    if ja3:
        label = blocked_ja3.get(ja3)
        if label:
            hits.append({
                "rule_id": "JA3-001",
                "description": f"Blocked JA3 hash {ja3} ({label})",
                "category": "fingerprint",
                "ja3": ja3,
            })

    ja4 = _extract_ja4(headers)
    if ja4:
        for prefix, label in blocked_ja4:
            if ja4.startswith(prefix):
                hits.append({
                    "rule_id": "JA4-001",
                    "description": f"Blocked JA4 prefix {prefix!r} ({label})",
                    "category": "fingerprint",
                    "ja4": ja4,
                })
                break

    return hits

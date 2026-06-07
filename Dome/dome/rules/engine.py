"""
Rule engine – runs all detection modules against an incoming request.
Returns a list of hits and a decision: ALLOW | BLOCK | LOG.
"""
from __future__ import annotations
import urllib.parse
from dataclasses import dataclass, field

from . import sqli, xss, lfi, rce, scanner
from .ratelimit import RateLimiter


@dataclass
class RequestContext:
    method: str
    path: str
    query_string: str
    headers: dict[str, str]
    body: str
    client_ip: str


@dataclass
class InspectionResult:
    action: str                    # "ALLOW" | "BLOCK" | "LOG"
    hits: list[dict] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.action == "BLOCK"


class RuleEngine:
    def __init__(self, config: dict):
        self.mode = config.get("mode", "block").lower()      # block | detect
        self.blocked_ips: set[str] = set(config.get("blocked_ips", []))
        self.allowed_ips: set[str] = set(config.get("allowed_ips", []))
        self.blocked_paths: list[str] = config.get("blocked_paths", [])

        rl_cfg = config.get("rate_limit", {})
        self.rate_limiter = RateLimiter(
            window_seconds=rl_cfg.get("window_seconds", 60),
            max_requests=rl_cfg.get("max_requests", 200),
            sensitive_max=rl_cfg.get("sensitive_max", 20),
            ban_duration=rl_cfg.get("ban_duration", 300),
        )

    def _collect_values(self, ctx: RequestContext) -> list[str]:
        """Gather all user-supplied strings to inspect."""
        values: list[str] = []

        # URL path + decoded path
        values.append(ctx.path)
        values.append(urllib.parse.unquote(ctx.path))

        # Query string parameters
        for _, v in urllib.parse.parse_qsl(ctx.query_string, keep_blank_values=True):
            values.append(v)
            values.append(urllib.parse.unquote_plus(v))

        # Request body (form data or raw)
        if ctx.body:
            values.append(ctx.body)
            try:
                for _, v in urllib.parse.parse_qsl(ctx.body, keep_blank_values=True):
                    values.append(v)
            except Exception:
                pass

        # Selected headers
        for hdr in ("Referer", "X-Forwarded-For", "X-Original-URL",
                    "X-Rewrite-URL", "User-Agent"):
            val = ctx.headers.get(hdr, "")
            if val:
                values.append(val)

        return values

    def inspect(self, ctx: RequestContext) -> InspectionResult:
        hits: list[dict] = []

        # 1. IP allowlist – fast pass
        if ctx.client_ip in self.allowed_ips:
            return InspectionResult(action="ALLOW")

        # 2. IP blocklist
        if ctx.client_ip in self.blocked_ips:
            hits.append({
                "rule_id": "IP-001",
                "description": f"Blocked IP: {ctx.client_ip}",
                "category": "ip_block",
            })
            return InspectionResult(action="BLOCK", hits=hits)

        # 3. Blocked paths (exact prefix)
        for bp in self.blocked_paths:
            if ctx.path.startswith(bp):
                hits.append({
                    "rule_id": "PATH-001",
                    "description": f"Blocked path: {ctx.path}",
                    "category": "path_block",
                })
                return InspectionResult(action="BLOCK", hits=hits)

        # 4. Rate limiting
        rl_hit = self.rate_limiter.check(ctx.client_ip, ctx.path)
        if rl_hit:
            return InspectionResult(action="BLOCK", hits=[rl_hit])

        # 5. Scanner detection (UA + path)
        ua = ctx.headers.get("User-Agent", "")
        hits.extend(scanner.check_ua(ua))
        hits.extend(scanner.check_path(ctx.path))

        # 6. Payload inspection
        for value in self._collect_values(ctx):
            if not value:
                continue
            hits.extend(sqli.check(value))
            hits.extend(xss.check(value))
            hits.extend(lfi.check(value))
            hits.extend(rce.check(value))

        if not hits:
            return InspectionResult(action="ALLOW")

        # In detect (log-only) mode, never actually block
        action = "BLOCK" if self.mode == "block" else "LOG"
        return InspectionResult(action=action, hits=hits)

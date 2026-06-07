"""Rate limiting / brute-force detection."""
import time
import threading
from collections import defaultdict


class RateLimiter:
    """
    Sliding-window rate limiter per source IP.

    Tracks request counts per IP over a rolling window.
    Separate stricter limits for sensitive paths (login, admin).
    """

    def __init__(
        self,
        window_seconds: int = 60,
        max_requests: int = 200,
        sensitive_max: int = 20,
        ban_duration: int = 300,
    ):
        self.window = window_seconds
        self.max_requests = max_requests
        self.sensitive_max = sensitive_max
        self.ban_duration = ban_duration

        # ip → deque of timestamps
        self._timestamps: dict[str, list[float]] = defaultdict(list)
        # ip → ban-expiry timestamp
        self._bans: dict[str, float] = {}
        self._lock = threading.Lock()

    # Paths that get the tighter limit
    SENSITIVE_PATHS = (
        "/login", "/admin", "/wp-login", "/signin",
        "/auth", "/password", "/register",
    )

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            expiry = self._bans.get(ip)
            if expiry and time.time() < expiry:
                return True
            if expiry:
                del self._bans[ip]
            return False

    def check(self, ip: str, path: str) -> dict | None:
        """
        Returns a hit dict if the request should be blocked, else None.
        """
        if self.is_banned(ip):
            return {
                "rule_id": "RATE-002",
                "description": f"IP {ip} is temporarily banned",
                "category": "ratelimit",
            }

        now = time.time()
        sensitive = any(path.lower().startswith(p) for p in self.SENSITIVE_PATHS)
        limit = self.sensitive_max if sensitive else self.max_requests

        with self._lock:
            timestamps = self._timestamps[ip]
            # Prune old entries
            cutoff = now - self.window
            self._timestamps[ip] = [t for t in timestamps if t > cutoff]
            self._timestamps[ip].append(now)
            count = len(self._timestamps[ip])

        if count > limit:
            with self._lock:
                self._bans[ip] = now + self.ban_duration
            return {
                "rule_id": "RATE-001",
                "description": (
                    f"Rate limit exceeded: {count} requests in {self.window}s "
                    f"(limit {limit}) – IP banned for {self.ban_duration}s"
                ),
                "category": "ratelimit",
            }
        return None

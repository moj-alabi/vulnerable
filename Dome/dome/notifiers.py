"""
Dome WAF – Alert notifiers.

Sends block/detection events to:
  - Discord webhook  (rich embed)
  - Remote syslog    (UDP/TCP, RFC 5424)
  - Generic webhook  (POST JSON to any URL)

All notifiers are fire-and-forget (asyncio background tasks).
A failure in any notifier never blocks the proxy response.
"""
from __future__ import annotations
import asyncio
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any

import aiohttp

logger = logging.getLogger("dome.notifiers")

# ── Severity colours for Discord embeds ───────────────────────────────────────
_COLOURS = {
    "BLOCK":  0xE74C3C,   # red
    "LOG":    0xF39C12,   # orange
    "ALLOW":  0x2ECC71,   # green
}

_SYSLOG_SEVERITY = {
    "BLOCK": 2,   # CRIT
    "LOG":   4,   # WARNING
    "ALLOW": 6,   # INFO
    "ERROR": 3,   # ERR
}


# ─────────────────────────────────────────────────────────────────────────────
#  Discord Webhook
# ─────────────────────────────────────────────────────────────────────────────
async def send_discord(
    session: aiohttp.ClientSession,
    webhook_url: str,
    event: dict[str, Any],
    *,
    min_action: str = "BLOCK",
) -> None:
    """
    Post a rich embed to a Discord webhook.
    min_action: only send if action >= this severity (BLOCK | LOG | ALLOW).
    """
    order = {"ALLOW": 0, "LOG": 1, "BLOCK": 2}
    if order.get(event.get("action", ""), 0) < order.get(min_action, 2):
        return

    action   = event.get("action", "?")
    ip       = event.get("client_ip", "?")
    method   = event.get("method", "?")
    path     = event.get("path", "?")
    hits     = event.get("hits", [])
    hit_text = "\n".join(f"• `{h['rule_id']}` – {h['description']}" for h in hits[:10])
    if not hit_text:
        hit_text = "_no rule hits_"

    embed = {
        "title": f"🛡️ Dome WAF — {action}",
        "color": _COLOURS.get(action, 0x95A5A6),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fields": [
            {"name": "Action",     "value": f"`{action}`",          "inline": True},
            {"name": "Client IP",  "value": f"`{ip}`",              "inline": True},
            {"name": "Request",    "value": f"`{method} {path}`",   "inline": False},
            {"name": "Rules Hit",  "value": hit_text,               "inline": False},
            {"name": "Categories", "value": "`" + "`, `".join(event.get("categories", [])) + "`" if event.get("categories") else "_none_", "inline": True},
            {"name": "Duration",   "value": f"{event.get('duration_ms', 0):.1f} ms", "inline": True},
        ],
        "footer": {"text": "Dome WAF"},
    }

    payload = {"embeds": [embed], "username": "Dome WAF"}

    try:
        async with session.post(
            webhook_url,
            json=payload,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            if resp.status not in (200, 204):
                body = await resp.text()
                logger.warning("Discord webhook returned %s: %s", resp.status, body[:200])
    except Exception as exc:
        logger.warning("Discord webhook error: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
#  Generic HTTP Webhook (POST JSON)
# ─────────────────────────────────────────────────────────────────────────────
async def send_webhook(
    session: aiohttp.ClientSession,
    url: str,
    event: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    min_action: str = "BLOCK",
) -> None:
    """POST the raw event JSON to any HTTP endpoint."""
    order = {"ALLOW": 0, "LOG": 1, "BLOCK": 2}
    if order.get(event.get("action", ""), 0) < order.get(min_action, 2):
        return

    req_headers = {"Content-Type": "application/json"}
    if headers:
        req_headers.update(headers)

    try:
        async with session.post(
            url,
            data=json.dumps(event),
            headers=req_headers,
            timeout=aiohttp.ClientTimeout(total=5),
        ) as resp:
            if resp.status >= 400:
                logger.warning("Webhook %s returned %s", url, resp.status)
    except Exception as exc:
        logger.warning("Webhook error (%s): %s", url, exc)


# ─────────────────────────────────────────────────────────────────────────────
#  Syslog (UDP or TCP, RFC 5424 format)
# ─────────────────────────────────────────────────────────────────────────────
class SyslogNotifier:
    """
    Sends RFC-5424 syslog messages to a remote log server.
    Falls back to UDP if TCP is unavailable.
    """

    FACILITY_LOCAL0 = 16

    def __init__(self, host: str, port: int = 514, proto: str = "udp"):
        self.host  = host
        self.port  = port
        self.proto = proto.lower()
        self._sock: socket.socket | None = None

    def _connect(self) -> None:
        if self._sock:
            return
        if self.proto == "tcp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(3)
            self._sock.connect((self.host, self.port))
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _format(self, event: dict[str, Any]) -> bytes:
        severity  = _SYSLOG_SEVERITY.get(event.get("action", ""), 6)
        priority  = self.FACILITY_LOCAL0 * 8 + severity
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        hostname  = socket.gethostname()
        app_name  = "dome-waf"
        msg_id    = event.get("action", "-")
        rules_hit = ",".join(h["rule_id"] for h in event.get("hits", []))
        message   = (
            f"action={event.get('action','-')} "
            f"ip={event.get('client_ip','-')} "
            f"method={event.get('method','-')} "
            f"path={event.get('path','-')} "
            f"rules={rules_hit or '-'} "
            f"status={event.get('status_code','-')}"
        )
        # RFC 5424:  <PRIORITY>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID MSG
        line = f"<{priority}>1 {timestamp} {hostname} {app_name} - {msg_id} - {message}"
        return line.encode("utf-8")

    def send(self, event: dict[str, Any], *, min_action: str = "BLOCK") -> None:
        order = {"ALLOW": 0, "LOG": 1, "BLOCK": 2}
        if order.get(event.get("action", ""), 0) < order.get(min_action, 2):
            return
        try:
            self._connect()
            data = self._format(event)
            if self.proto == "tcp":
                self._sock.sendall(data + b"\n")
            else:
                self._sock.sendto(data, (self.host, self.port))
        except Exception as exc:
            logger.warning("Syslog send error (%s:%s): %s", self.host, self.port, exc)
            self._sock = None   # force reconnect next time

    # Convenience async wrapper so callers can await it
    async def send_async(self, event: dict[str, Any], *, min_action: str = "BLOCK") -> None:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, lambda: self.send(event, min_action=min_action))


# ─────────────────────────────────────────────────────────────────────────────
#  Notifier Manager  (wires everything together)
# ─────────────────────────────────────────────────────────────────────────────
class NotifierManager:
    """
    Holds all configured notifiers.
    Call  manager.dispatch(session, event)  from the proxy – fire and forget.
    """

    def __init__(self, config: dict):
        nc = config.get("notifications", {})

        self.discord_url    = nc.get("discord_webhook")
        self.discord_min    = nc.get("discord_min_action", "BLOCK")

        self.webhook_url    = nc.get("webhook_url")
        self.webhook_headers = nc.get("webhook_headers", {})
        self.webhook_min    = nc.get("webhook_min_action", "BLOCK")

        syslog_cfg = nc.get("syslog", {})
        if syslog_cfg.get("enabled"):
            self.syslog = SyslogNotifier(
                host=syslog_cfg["host"],
                port=int(syslog_cfg.get("port", 514)),
                proto=syslog_cfg.get("proto", "udp"),
            )
            self.syslog_min = syslog_cfg.get("min_action", "BLOCK")
        else:
            self.syslog     = None
            self.syslog_min = "BLOCK"

    def has_any(self) -> bool:
        return bool(self.discord_url or self.webhook_url or self.syslog)

    def dispatch(
        self,
        session: aiohttp.ClientSession,
        event: dict[str, Any],
    ) -> None:
        """Schedule all notifications as background tasks (non-blocking)."""
        if self.discord_url:
            asyncio.ensure_future(
                send_discord(session, self.discord_url, event, min_action=self.discord_min)
            )
        if self.webhook_url:
            asyncio.ensure_future(
                send_webhook(
                    session, self.webhook_url, event,
                    headers=self.webhook_headers,
                    min_action=self.webhook_min,
                )
            )
        if self.syslog:
            asyncio.ensure_future(
                self.syslog.send_async(event, min_action=self.syslog_min)
            )

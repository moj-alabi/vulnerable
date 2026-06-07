"""
Dome WAF – Async reverse proxy core.
Uses aiohttp for both the listening server and upstream HTTP client.
"""
from __future__ import annotations
import asyncio
import time
from typing import Any

import aiohttp
from aiohttp import web

from .rules.engine import RuleEngine, RequestContext
from .logger import WafLogger
from .notifiers import NotifierManager


BLOCK_RESPONSE_BODY = b"""<!DOCTYPE html>
<html>
<head><title>403 Blocked by Dome WAF</title></head>
<body style="font-family:sans-serif;text-align:center;padding:60px">
  <h1>&#128737; Request Blocked</h1>
  <p>This request was blocked by <strong>Dome WAF</strong>.</p>
  <p>If you believe this is an error, please contact the administrator.</p>
</body>
</html>"""


class DomeProxy:
    def __init__(self, config: dict, engine: RuleEngine, logger: WafLogger, notifiers: NotifierManager | None = None):
        self.upstream = config["upstream"].rstrip("/")
        self.listen_host = config.get("listen_host", "0.0.0.0")
        self.listen_port = int(config.get("listen_port", 8888))
        self.timeout = aiohttp.ClientTimeout(total=config.get("upstream_timeout", 30))
        self.engine = engine
        self.logger = logger
        self.notifiers = notifiers
        self._session: aiohttp.ClientSession | None = None

    # ── aiohttp app lifecycle ─────────────────────────────────────────────────
    async def _startup(self, app: web.Application) -> None:
        connector = aiohttp.TCPConnector(limit=256, ssl=False)
        self._session = aiohttp.ClientSession(connector=connector, timeout=self.timeout)

    async def _shutdown(self, app: web.Application) -> None:
        if self._session:
            await self._session.close()

    # ── Request handler ───────────────────────────────────────────────────────
    async def handle(self, request: web.Request) -> web.Response:
        start = time.monotonic()

        # Determine real client IP (trust X-Forwarded-For if behind another proxy)
        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.remote
            or "unknown"
        )

        # Read body (limit to 1 MB to avoid memory exhaustion)
        try:
            body_bytes = await request.read()
            if len(body_bytes) > 1_048_576:
                body_bytes = body_bytes[:1_048_576]
            body = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body = ""

        ctx = RequestContext(
            method=request.method,
            path=request.path,
            query_string=request.query_string,
            headers=dict(request.headers),
            body=body,
            client_ip=client_ip,
        )

        result = self.engine.inspect(ctx)

        if result.blocked:
            elapsed = (time.monotonic() - start) * 1000
            event = self.logger.log_request(
                action="BLOCK",
                client_ip=client_ip,
                method=request.method,
                path=request.path,
                status_code=403,
                hits=result.hits,
                duration_ms=elapsed,
            )
            if self.notifiers and event:
                self.notifiers.dispatch(self._session, event)
            return web.Response(
                status=403,
                content_type="text/html",
                body=BLOCK_RESPONSE_BODY,
                headers={
                    "X-Dome-Action": "BLOCK",
                    "X-Dome-Rules": ",".join(h["rule_id"] for h in result.hits),
                },
            )

        # ── Forward request to upstream ───────────────────────────────────────
        upstream_url = f"{self.upstream}{request.path}"
        if request.query_string:
            upstream_url += f"?{request.query_string}"

        # Strip hop-by-hop headers
        forward_headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in (
                "host", "connection", "keep-alive", "transfer-encoding",
                "te", "trailer", "upgrade",
            )
        }
        forward_headers["X-Forwarded-For"] = client_ip
        forward_headers["X-Forwarded-Proto"] = "http"

        try:
            async with self._session.request(
                method=request.method,
                url=upstream_url,
                headers=forward_headers,
                data=body_bytes,
                allow_redirects=False,
                ssl=False,
            ) as upstream_resp:
                resp_body = await upstream_resp.read()
                resp_headers = {
                    k: v for k, v in upstream_resp.headers.items()
                    if k.lower() not in (
                        "transfer-encoding", "connection", "keep-alive",
                    )
                }
                resp_headers["X-Dome-Action"] = result.action  # ALLOW or LOG

                elapsed = (time.monotonic() - start) * 1000
                event = self.logger.log_request(
                    action=result.action,
                    client_ip=client_ip,
                    method=request.method,
                    path=request.path,
                    status_code=upstream_resp.status,
                    hits=result.hits,
                    duration_ms=elapsed,
                )
                if self.notifiers and event and result.hits:
                    self.notifiers.dispatch(self._session, event)

                return web.Response(
                    status=upstream_resp.status,
                    headers=resp_headers,
                    body=resp_body,
                )

        except aiohttp.ClientConnectorError as exc:
            elapsed = (time.monotonic() - start) * 1000
            self.logger.log_request(
                action="ERROR",
                client_ip=client_ip,
                method=request.method,
                path=request.path,
                status_code=502,
                hits=[{"rule_id": "SYS-001", "description": str(exc), "category": "error"}],
                duration_ms=elapsed,
            )
            return web.Response(status=502, text=f"Dome WAF: upstream unavailable – {exc}")

        except Exception as exc:  # noqa: BLE001
            return web.Response(status=500, text=f"Dome WAF internal error: {exc}")

    # ── Build and run ─────────────────────────────────────────────────────────
    def build_app(self) -> web.Application:
        app = web.Application()
        app.on_startup.append(self._startup)
        app.on_cleanup.append(self._shutdown)
        app.router.add_route("*", "/{path_info:.*}", self.handle)
        return app

    def run(self) -> None:
        app = self.build_app()
        print(f"[Dome WAF] Listening on {self.listen_host}:{self.listen_port} → {self.upstream}")
        web.run_app(app, host=self.listen_host, port=self.listen_port, access_log=None)

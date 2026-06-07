#!/usr/bin/env python3
"""
Dome WAF – entry point.

Usage:
    python waf.py                        # uses config.yml in same directory
    python waf.py --config /path/to.yml  # custom config path
    python waf.py --mode detect          # override mode (block|detect)
    python waf.py --upstream http://127.0.0.1:80   # override upstream
    python waf.py --port 8888            # override listen port
"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

import yaml

from dome.rules.engine import RuleEngine
from dome.logger import WafLogger
from dome.proxy import DomeProxy
from dome.notifiers import NotifierManager


def load_config(path: str) -> dict:
    cfg_path = Path(path)
    if not cfg_path.exists():
        print(f"[Dome] Config file not found: {path}", file=sys.stderr)
        sys.exit(1)
    with open(cfg_path) as f:
        return yaml.safe_load(f) or {}


def main() -> None:
    parser = argparse.ArgumentParser(description="Dome WAF – standalone reverse proxy WAF")
    parser.add_argument("--config",   default="config.yml",        help="Path to config.yml")
    parser.add_argument("--mode",     choices=["block", "detect"],  help="Override WAF mode")
    parser.add_argument("--upstream", help="Override upstream URL (e.g. http://127.0.0.1:80)")
    parser.add_argument("--port",     type=int,                     help="Override listen port")
    args = parser.parse_args()

    config = load_config(args.config)

    # CLI overrides
    if args.mode:
        config.setdefault("waf", {})["mode"] = args.mode
    if args.upstream:
        config["proxy"]["upstream"] = args.upstream
    if args.port:
        config["proxy"]["listen_port"] = args.port

    proxy_cfg = config.get("proxy", {})
    waf_cfg   = config.get("waf", {})
    log_cfg   = config.get("logging", {})

    # Merge waf config into engine config
    engine_cfg = {**waf_cfg}

    logger    = WafLogger(
        log_path=log_cfg.get("path", "/var/log/dome/waf.log"),
        max_bytes=log_cfg.get("max_bytes", 10_485_760),
        backup_count=log_cfg.get("backup_count", 5),
    )
    engine    = RuleEngine(engine_cfg)
    notifiers = NotifierManager(config)
    proxy     = DomeProxy(proxy_cfg, engine, logger, notifiers)

    if notifiers.has_any():
        active = []
        if notifiers.discord_url:  active.append("Discord")
        if notifiers.webhook_url:  active.append("Webhook")
        if notifiers.syslog:       active.append(f"Syslog({notifiers.syslog.host}:{notifiers.syslog.port})")
        print(f"[Dome WAF v0.1.0] Notifiers: {', '.join(active)}")
    else:
        print("[Dome WAF v0.1.0] Notifiers: none configured")

    print(f"[Dome WAF v0.1.0] Mode: {engine.mode.upper()}")
    proxy.run()


if __name__ == "__main__":
    main()

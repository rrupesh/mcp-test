"""CLI entrypoint."""
from __future__ import annotations

import argparse
import logging

import uvicorn

from .api import create_app
from .config import Config


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="gke-cred-audit")
    p.add_argument("--bind", default=None)
    p.add_argument("--port", type=int, default=None)
    p.add_argument("--enable-secret-listing", action="store_true",
                   help="Enable namespace secret metadata enumeration (values are still never returned).")
    p.add_argument("--log-level", default="info")
    return p.parse_args()


def main() -> None:
    args = _parse_args()
    cfg = Config.from_env()
    overrides: dict = {}
    if args.bind:
        overrides["bind"] = args.bind
    if args.port:
        overrides["port"] = args.port
    if args.enable_secret_listing:
        overrides["enable_secret_listing"] = True
    if overrides:
        cfg = Config(**{**cfg.__dict__, **overrides})

    logging.basicConfig(
        level=args.log_level.upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    logging.getLogger("audit").info(
        "starting gke-cred-audit bind=%s:%d auth=none(gateway-managed) secret_listing=%s raw_reveal=%s",
        cfg.bind, cfg.port, cfg.enable_secret_listing, cfg.raw_reveal,
    )
    app = create_app(cfg)
    uvicorn.run(
        app,
        host=cfg.bind,
        port=cfg.port,
        log_level=args.log_level,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
mhr-ggate | VPS Relay Server
Receives base64-wrapped requests forwarded from Google Apps Script and
proxies them to the local xray instance, then base64-wraps the response
back so it survives the GAS round trip cleanly.

Pipeline (return path):

    127.0.0.1:10000 (xray) -> this server -> nginx :443 -> GAS -> client_relay -> xray client

Run (behind nginx + TLS):
    pip install -r requirements.txt
    export MHR_SECRET="your_shared_secret"
    python3 server.py
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import logging
import os
import secrets
import signal
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

try:
    import httpx
    import uvicorn
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.responses import JSONResponse, PlainTextResponse, Response
except ImportError as e:  # pragma: no cover
    sys.stderr.write(
        "[!] missing dependency: %s\n"
        "    install with: pip install -r requirements.txt\n" % e.name
    )
    sys.exit(1)


# ──────────────────────────────────────────────────────────
# config
# ──────────────────────────────────────────────────────────
@dataclass
class Config:
    secret: str = ""
    xray_host: str = "127.0.0.1"
    xray_port: int = 10000
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    upstream_timeout: float = 60.0
    log_level: str = "INFO"
    enable_health: bool = True
    max_body_bytes: int = 8 * 1024 * 1024  # 8 MiB hard cap per request
    trusted_proxy_header: str = "x-forwarded-for"


@dataclass
class Stats:
    started_at: float = field(default_factory=time.time)
    requests_total: int = 0
    requests_forbidden: int = 0
    requests_failed: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    last_error: str = ""

    def snapshot(self) -> dict:
        return {
            "uptime_sec": round(time.time() - self.started_at, 1),
            "requests_total": self.requests_total,
            "requests_forbidden": self.requests_forbidden,
            "requests_failed": self.requests_failed,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "last_error": self.last_error,
        }


def load_config(args: argparse.Namespace) -> Config:
    cfg = Config()
    cfg.secret      = os.environ.get("MHR_SECRET",      cfg.secret)
    cfg.xray_host   = os.environ.get("XRAY_HOST",       cfg.xray_host)
    cfg.xray_port   = int(os.environ.get("XRAY_PORT",   cfg.xray_port))
    cfg.listen_host = os.environ.get("LISTEN_HOST",     cfg.listen_host)
    cfg.listen_port = int(os.environ.get("LISTEN_PORT", cfg.listen_port))
    cfg.log_level   = os.environ.get("LOG_LEVEL",       cfg.log_level)
    if args.secret:    cfg.secret      = args.secret
    if args.xray:
        host, port = args.xray.rsplit(":", 1)
        cfg.xray_host, cfg.xray_port = host, int(port)
    if args.listen:
        host, port = args.listen.rsplit(":", 1)
        cfg.listen_host, cfg.listen_port = host, int(port)
    if args.log_level: cfg.log_level   = args.log_level
    return cfg


def validate_config(cfg: Config) -> Optional[str]:
    if not cfg.secret or cfg.secret == "CHANGE_THIS_SECRET_KEY":
        return "MHR_SECRET is not set or still the default"
    if len(cfg.secret) < 12:
        return "MHR_SECRET is too short (use at least 12 chars / 96 bits)"
    if not (1 <= cfg.xray_port <= 65535):
        return f"XRAY_PORT out of range: {cfg.xray_port}"
    if not (1 <= cfg.listen_port <= 65535):
        return f"LISTEN_PORT out of range: {cfg.listen_port}"
    return None


# ──────────────────────────────────────────────────────────
# app
# ──────────────────────────────────────────────────────────
def make_app(
    cfg: Config,
    http_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
) -> FastAPI:
    """Build the VPS relay app.

    `http_factory` is the same DI hook as on the client side: tests can
    inject a MockTransport to drive the xray upstream without a real
    socket.
    """
    log = logging.getLogger("mhr.server")
    stats = Stats()

    timeout = httpx.Timeout(cfg.upstream_timeout, connect=5.0)
    limits  = httpx.Limits(max_keepalive_connections=64, max_connections=256)
    xray_base = f"http://{cfg.xray_host}:{cfg.xray_port}"

    def _default_http() -> httpx.AsyncClient:
        return httpx.AsyncClient(timeout=timeout, limits=limits, http2=False)

    factory = http_factory or _default_http

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI):
        client = factory()
        app.state.http  = client
        app.state.cfg   = cfg
        app.state.stats = stats
        log.info("listening on %s:%s", cfg.listen_host, cfg.listen_port)
        log.info("xray upstream: %s", xray_base)
        try:
            yield
        finally:
            await client.aclose()

    app = FastAPI(docs_url=None, redoc_url=None, lifespan=lifespan)

    def _check_secret(request: Request) -> None:
        provided = request.headers.get("x-mhr-secret", "")
        # constant-time compare to dodge timing attacks
        if not secrets.compare_digest(provided, cfg.secret):
            stats.requests_forbidden += 1
            raise HTTPException(status_code=403, detail="forbidden")

    def _peer(request: Request) -> str:
        xff = request.headers.get(cfg.trusted_proxy_header, "")
        if xff:
            return xff.split(",")[0].strip()
        return request.client.host if request.client else "?"

    def _strip_hop_headers(headers) -> dict:
        drop = {
            "host", "content-length", "transfer-encoding",
            "connection", "keep-alive", "te", "trailer", "upgrade",
            "x-mhr-secret", "x-mhr-method", "x-forwarded-for",
            "x-forwarded-proto", "x-forwarded-host",
        }
        return {k: v for k, v in headers.items() if k.lower() not in drop}

    @app.get("/")
    async def root():
        if not cfg.enable_health:
            raise HTTPException(404)
        return PlainTextResponse("ok")

    @app.get("/_mhr/health")
    async def health():
        return {"ok": True}

    @app.get("/_mhr/stats")
    async def stats_endpoint(request: Request):
        # only allow stats with the same shared secret
        _check_secret(request)
        return JSONResponse(stats.snapshot())

    async def _forward(method: str, path: str, request: Request) -> Response:
        _check_secret(request)
        peer = _peer(request)

        if method == "POST":
            raw_body = await request.body()
            if len(raw_body) > cfg.max_body_bytes * 4 // 3 + 16:
                raise HTTPException(413, "payload too large")
            try:
                # client_relay always sends ASCII base64 text; decode to raw bytes.
                payload = base64.b64decode(raw_body, validate=False) if raw_body else b""
            except Exception as exc:
                stats.requests_failed += 1
                stats.last_error = f"b64 decode: {exc!r}"
                log.warning("b64 decode error from %s: %s", peer, exc)
                raise HTTPException(400, "invalid base64 body")
        else:
            payload = b""

        forward_path = path if path.startswith("/") else f"/{path}"
        url = f"{xray_base}{forward_path}"
        headers = _strip_hop_headers(request.headers)

        try:
            if method == "POST":
                resp = await app.state.http.post(url, content=payload, headers=headers)
            else:
                resp = await app.state.http.get(url, headers=headers)
        except httpx.RequestError as exc:
            stats.requests_failed += 1
            stats.last_error = repr(exc)
            log.warning("xray upstream error from %s on %s: %s", peer, forward_path, exc)
            return PlainTextResponse("", status_code=502)

        encoded = base64.b64encode(resp.content).decode("ascii")
        stats.requests_total += 1
        stats.bytes_in  += len(payload)
        stats.bytes_out += len(resp.content)
        # mirror status. xray client cares about 2xx vs not.
        return PlainTextResponse(
            encoded,
            status_code=resp.status_code,
            media_type="text/plain; charset=ascii",
        )

    @app.post("/{path:path}")
    async def relay_post(path: str, request: Request):
        return await _forward("POST", path, request)

    @app.api_route("/{path:path}", methods=["GET"])
    async def relay_get(path: str, request: Request):
        if path == "" or path == "_mhr/health":
            # already handled above; fastapi will dispatch the other route
            raise HTTPException(404)
        return await _forward("GET", path, request)

    return app


# ──────────────────────────────────────────────────────────
# entrypoint
# ──────────────────────────────────────────────────────────
def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def main() -> int:
    p = argparse.ArgumentParser(description="mhr-ggate VPS relay server")
    p.add_argument("--secret",    help="shared secret (or set MHR_SECRET)")
    p.add_argument("--xray",      help="xray upstream host:port (default 127.0.0.1:10000)")
    p.add_argument("--listen",    help="bind host:port (default 0.0.0.0:8080)")
    p.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args()

    cfg = load_config(args)
    setup_logging(cfg.log_level)
    err = validate_config(cfg)
    if err:
        print(f"[!] config error: {err}", file=sys.stderr)
        return 2

    app = make_app(cfg)
    config = uvicorn.Config(
        app,
        host=cfg.listen_host,
        port=cfg.listen_port,
        log_level=cfg.log_level.lower(),
        access_log=False,
        proxy_headers=True,
        forwarded_allow_ips="127.0.0.1",
    )
    server = uvicorn.Server(config)

    def _stop(*_):
        server.should_exit = True

    if sys.platform == "win32":
        signal.signal(signal.SIGINT,  _stop)
        signal.signal(signal.SIGTERM, _stop)

    server.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())

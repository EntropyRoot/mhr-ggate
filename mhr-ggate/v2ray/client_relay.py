#!/usr/bin/env python3
"""
mhr-ggate | Client-side Relay
Sits between your local xray client and the Google Apps Script web app.

Why this exists:
    GAS cannot speak the VMess protocol natively, and binary data does not
    survive a round-trip through GAS untouched (e.postData.contents is a
    string). This relay base64-wraps every request body on the way out and
    base64-decodes the response on the way back, so the bytes that xray
    sends are exactly the bytes the VPS-side xray receives.

Pipeline:

    xray client (xhttp / splithttp, no TLS)
      -> 127.0.0.1:LOCAL_PORT  (this script)
        -> https://script.google.com/macros/s/.../exec  (GAS Code.gs)
          -> https://your-vps/...                       (server.py + nginx)
            -> 127.0.0.1:10000                          (xray server)

Run:
    python3 client_relay.py --gas-url <GAS_URL> --secret <SECRET>
    # or with config file:
    python3 client_relay.py --config relay.toml
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import logging
import os
import signal
import sys
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Callable, Optional
from urllib.parse import urlparse

try:
    import httpx
    from fastapi import FastAPI, HTTPException, Request, Response
    from fastapi.responses import JSONResponse, PlainTextResponse
    import uvicorn
except ImportError as e:  # pragma: no cover - import error guard
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
    gas_url: str = ""
    secret: str = ""
    listen_host: str = "127.0.0.1"
    listen_port: int = 8000
    upstream_timeout: float = 60.0
    max_retries: int = 2
    retry_backoff: float = 0.4
    log_level: str = "INFO"
    user_agent: str = "mhr-ggate-relay/2.0"
    metrics_enabled: bool = True


@dataclass
class Stats:
    started_at: float = field(default_factory=time.time)
    requests_total: int = 0
    requests_failed: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    last_error: str = ""

    def as_dict(self) -> dict:
        return {
            "uptime_sec": round(time.time() - self.started_at, 1),
            "requests_total": self.requests_total,
            "requests_failed": self.requests_failed,
            "bytes_up": self.bytes_up,
            "bytes_down": self.bytes_down,
            "last_error": self.last_error,
        }


def load_config(args: argparse.Namespace) -> Config:
    cfg = Config()
    # config file
    if args.config:
        path = args.config
        with open(path, "r", encoding="utf-8") as f:
            data = _load_toml_or_json(path, f.read())
        for key, value in data.items():
            if hasattr(cfg, key):
                setattr(cfg, key, value)
    # env
    cfg.gas_url     = os.environ.get("MHR_GAS_URL",     cfg.gas_url)
    cfg.secret      = os.environ.get("MHR_SECRET",      cfg.secret)
    cfg.listen_host = os.environ.get("MHR_LISTEN_HOST", cfg.listen_host)
    cfg.listen_port = int(os.environ.get("MHR_LISTEN_PORT", cfg.listen_port))
    # cli overrides
    if args.gas_url:    cfg.gas_url     = args.gas_url
    if args.secret:     cfg.secret      = args.secret
    if args.listen:     cfg.listen_host, cfg.listen_port = _parse_listen(args.listen)
    if args.log_level:  cfg.log_level   = args.log_level
    return cfg


def _load_toml_or_json(path: str, raw: str) -> dict:
    if path.lower().endswith(".json"):
        return json.loads(raw)
    try:
        import tomllib  # py311+
    except ImportError:  # pragma: no cover
        import tomli as tomllib  # type: ignore
    return tomllib.loads(raw)


def _parse_listen(spec: str) -> tuple[str, int]:
    if ":" in spec:
        host, port = spec.rsplit(":", 1)
    else:
        host, port = "127.0.0.1", spec
    return host, int(port)


def validate_config(cfg: Config) -> Optional[str]:
    if not cfg.gas_url or "YOUR_SCRIPT_ID" in cfg.gas_url:
        return "MHR_GAS_URL is not set (use --gas-url or env MHR_GAS_URL)"
    parsed = urlparse(cfg.gas_url)
    if parsed.scheme not in ("http", "https"):
        return f"gas_url must be http/https, got {parsed.scheme!r}"
    if not parsed.netloc:
        return f"gas_url is missing host: {cfg.gas_url!r}"
    if not cfg.secret or cfg.secret == "CHANGE_THIS_SECRET_KEY":
        return "MHR_SECRET is not set (use --secret or env MHR_SECRET)"
    if not (1 <= cfg.listen_port <= 65535):
        return f"listen_port out of range: {cfg.listen_port}"
    return None


# ──────────────────────────────────────────────────────────
# core relay
# ──────────────────────────────────────────────────────────
def make_app(
    cfg: Config,
    http_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
) -> FastAPI:
    """Build the relay app.

    `http_factory`, when provided, is called to construct the outbound
    httpx.AsyncClient — useful for tests that want to inject a
    MockTransport. When omitted, a standard pooled client is created.
    """
    log = logging.getLogger("mhr.client")
    stats = Stats()

    def _default_http() -> httpx.AsyncClient:
        timeout = httpx.Timeout(cfg.upstream_timeout, connect=10.0)
        limits  = httpx.Limits(max_keepalive_connections=32, max_connections=128)
        return httpx.AsyncClient(
            timeout=timeout,
            limits=limits,
            http2=False,
            follow_redirects=True,
            headers={"User-Agent": cfg.user_agent},
        )

    factory = http_factory or _default_http

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        client = factory()
        app.state.http   = client
        app.state.cfg    = cfg
        app.state.stats  = stats
        log.info("relay listening on http://%s:%s", cfg.listen_host, cfg.listen_port)
        log.info("forwarding to GAS: %s", cfg.gas_url)
        try:
            yield
        finally:
            await client.aclose()

    app = FastAPI(
        title="mhr-ggate client relay",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )

    @app.get("/_mhr/health")
    async def health():
        return {"ok": True}

    @app.get("/_mhr/stats")
    async def metrics():
        if not cfg.metrics_enabled:
            raise HTTPException(404, "metrics disabled")
        return JSONResponse(stats.as_dict())

    async def forward(request: Request, path: str) -> Response:
        method = request.method.upper()
        if method not in ("GET", "POST"):
            raise HTTPException(405, "only GET/POST supported")

        body = await request.body() if method == "POST" else b""
        encoded_body = base64.b64encode(body).decode("ascii") if body else ""

        # GAS expects the original sub-path inside ?path=
        forward_path = "/" + path if not path.startswith("/") else path
        params = {"path": forward_path}
        headers = {
            "X-MHR-Secret": cfg.secret,
            "X-MHR-Method": method,
            "Content-Type": "text/plain; charset=ascii",
        }

        last_exc: Optional[BaseException] = None
        for attempt in range(cfg.max_retries + 1):
            try:
                if method == "POST":
                    resp = await app.state.http.post(
                        cfg.gas_url, params=params, headers=headers, content=encoded_body
                    )
                else:
                    resp = await app.state.http.get(
                        cfg.gas_url, params=params, headers=headers
                    )
                # gas returns 200 + base64-text body on success.
                # network/google-side errors are surfaced as 5xx.
                if resp.status_code >= 500:
                    raise httpx.HTTPStatusError(
                        f"upstream {resp.status_code}", request=resp.request, response=resp
                    )
                stats.requests_total += 1
                stats.bytes_up   += len(body)
                raw = _decode_b64_lenient(resp.text)
                stats.bytes_down += len(raw)
                # mirror upstream status code so xray can tell when something is off.
                return Response(
                    content=raw,
                    status_code=resp.status_code,
                    media_type="application/octet-stream",
                )
            except (httpx.RequestError, httpx.HTTPStatusError) as exc:
                last_exc = exc
                if attempt >= cfg.max_retries:
                    break
                await asyncio.sleep(cfg.retry_backoff * (2 ** attempt))

        stats.requests_failed += 1
        stats.last_error = repr(last_exc)
        log.warning("forward failed (%s %s): %s", method, path, last_exc)
        # 502 tells xray the tunnel hop is unhealthy without killing the session.
        return Response(status_code=502, content=b"", media_type="application/octet-stream")

    @app.api_route("/{full_path:path}", methods=["GET", "POST"])
    async def catchall(full_path: str, request: Request):
        return await forward(request, full_path)

    return app


def _decode_b64_lenient(text: str) -> bytes:
    """GAS strips trailing newlines or pads inconsistently. Be liberal."""
    if not text:
        return b""
    s = text.strip()
    # add missing padding if any
    pad = (-len(s)) % 4
    if pad:
        s += "=" * pad
    try:
        return base64.b64decode(s, validate=False)
    except Exception:
        return b""


# ──────────────────────────────────────────────────────────
# entrypoint
# ──────────────────────────────────────────────────────────
def setup_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def install_signal_handlers(loop: asyncio.AbstractEventLoop, server: uvicorn.Server) -> None:
    def _stop(*_):
        server.should_exit = True

    if sys.platform == "win32":
        signal.signal(signal.SIGINT,  _stop)
        signal.signal(signal.SIGTERM, _stop)
    else:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _stop)


def main() -> int:
    p = argparse.ArgumentParser(description="mhr-ggate client-side relay")
    p.add_argument("--gas-url",  help="Google Apps Script web app URL")
    p.add_argument("--secret",   help="shared secret with the GAS/VPS side")
    p.add_argument("--listen",   default=None, help="host:port to listen on (default 127.0.0.1:8000)")
    p.add_argument("--config",   help="optional toml/json config file")
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
        loop="asyncio",
    )
    server = uvicorn.Server(config)
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    install_signal_handlers(loop, server)
    loop.run_until_complete(server.serve())
    return 0


if __name__ == "__main__":
    sys.exit(main())

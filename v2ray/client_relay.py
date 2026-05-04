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
import binascii
import json
import logging
import os
import re
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

from fronted_gas_transport import (
    DirectHttpxTransport,
    FrontedGASConfig,
    FrontedGASTransport,
    Transport,
)


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
    # ── transport selection (research) ─────────────────────────────
    # "direct"  : plain httpx → script.google.com  (today's behavior)
    # "fronted" : raw TLS to a Google edge IP, SNI rotated, HTTP Host
    #             pinned to script.google.com — see
    #             v2ray/fronted_gas_transport.py and
    #             docs/research-fronted-transport.md
    transport_mode: str = "direct"
    # Optional fronting knobs (only meaningful when transport_mode == "fronted")
    front_connect_host: str = ""              # Google edge IP, "" → DNS
    front_sni_hosts: list[str] = field(default_factory=list)
    front_http_host: str = "script.google.com"
    front_verify_ssl: bool = True
    # Multi-deployment + H2 + keepalive + fan-out (see
    # v2ray/fronted_gas_transport.py docstring and
    # docs/research-fronted-transport.md for the architecture).
    front_script_ids: list[str] = field(default_factory=list)
    front_enable_h2: bool = True
    front_enable_keepalive: bool = True
    front_enable_dev_probe: bool = True
    front_enable_pool_maintenance: bool = True
    front_parallel_relay: int = 1
    front_pool_max: int = 16
    front_pool_min_idle: int = 4


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
    # ── transport overrides (CLI > env > config file) ───────────────
    env_mode = os.environ.get("MHR_TRANSPORT")
    if env_mode:
        cfg.transport_mode = env_mode
    if getattr(args, "transport", None):
        cfg.transport_mode = args.transport
    env_connect = os.environ.get("MHR_FRONT_CONNECT_HOST")
    if env_connect:
        cfg.front_connect_host = env_connect
    if getattr(args, "front_connect_host", None):
        cfg.front_connect_host = args.front_connect_host
    if getattr(args, "front_sni", None):
        cfg.front_sni_hosts = list(args.front_sni)
    if getattr(args, "front_script_id", None):
        cfg.front_script_ids = list(args.front_script_id)
    if getattr(args, "front_http_host", None):
        cfg.front_http_host = args.front_http_host
    if getattr(args, "no_h2", False):
        cfg.front_enable_h2 = False
    if getattr(args, "no_keepalive", False):
        cfg.front_enable_keepalive = False
    if getattr(args, "no_dev_probe", False):
        cfg.front_enable_dev_probe = False
    if getattr(args, "no_pool_maintenance", False):
        cfg.front_enable_pool_maintenance = False
    if getattr(args, "front_parallel", None) is not None:
        cfg.front_parallel_relay = max(1, int(args.front_parallel))
    if getattr(args, "front_pool_max", None) is not None:
        cfg.front_pool_max = max(1, int(args.front_pool_max))
    if getattr(args, "front_pool_min_idle", None) is not None:
        cfg.front_pool_min_idle = max(0, int(args.front_pool_min_idle))
    if getattr(args, "front_insecure", False):
        cfg.front_verify_ssl = False
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


_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*(?<!-)$"
)


def _is_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        if not p.isdigit() or not (0 <= int(p) <= 255):
            return False
        # reject leading-zero forms like "01.2.3.4"
        if len(p) > 1 and p[0] == "0":
            return False
    return True


def _is_hostname(s: str) -> bool:
    return bool(_HOSTNAME_RE.match(s))


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

    # ── fronted-mode validation ──────────────────────────────────
    mode = (cfg.transport_mode or "direct").lower()
    if mode not in ("direct", "fronted"):
        return f"transport_mode must be 'direct' or 'fronted', got {cfg.transport_mode!r}"
    if mode == "fronted":
        # fronting only makes sense with HTTPS — we encrypt under the SNI
        # cover, then disclose the real Host inside the TLS tunnel.
        if parsed.scheme != "https":
            return "transport_mode='fronted' requires an https gas_url"
        if cfg.front_connect_host:
            ch = cfg.front_connect_host.strip()
            # If the string is shaped like an IPv4 literal (four dot-
            # separated all-digit groups), it must pass the strict IPv4
            # check — otherwise a typo like "999.999.999.999" would slip
            # past as a hostname.
            looks_like_ip = ch.count(".") == 3 and all(
                p.isdigit() for p in ch.split(".") if p
            )
            if looks_like_ip:
                if not _is_ipv4(ch):
                    return (f"front_connect_host looks like an IPv4 literal but "
                            f"is invalid: {cfg.front_connect_host!r}")
            elif not _is_hostname(ch):
                return (f"front_connect_host is neither a valid IPv4 nor a "
                        f"hostname: {cfg.front_connect_host!r}")
        for sni in cfg.front_sni_hosts or ():
            s = str(sni).strip().rstrip(".")
            if not s:
                return "front_sni_hosts contains an empty entry"
            if not _is_hostname(s):
                return f"front_sni_hosts contains an invalid hostname: {sni!r}"
        if not cfg.front_http_host or not _is_hostname(cfg.front_http_host):
            return f"front_http_host is invalid: {cfg.front_http_host!r}"
        if not isinstance(cfg.front_verify_ssl, bool):
            return "front_verify_ssl must be a boolean"

        # ── multi-deployment / fan-out / pool tuning ─────────────
        for sid in cfg.front_script_ids or ():
            if not isinstance(sid, str) or not sid.strip():
                return "front_script_ids contains an empty entry"
            # Apps Script deployment IDs are URL-safe base64 strings
            # (~50-100 chars). Reject anything that obviously isn't.
            if not re.match(r"^[A-Za-z0-9_-]{16,}$", sid.strip()):
                return f"front_script_ids contains a malformed SID: {sid!r}"
        for flag_name in (
            "front_enable_h2", "front_enable_keepalive",
            "front_enable_dev_probe", "front_enable_pool_maintenance",
        ):
            if not isinstance(getattr(cfg, flag_name), bool):
                return f"{flag_name} must be a boolean"
        if not (1 <= int(cfg.front_parallel_relay) <= 32):
            return (f"front_parallel_relay must be in [1, 32], got "
                    f"{cfg.front_parallel_relay}")
        if int(cfg.front_parallel_relay) > 1 and len(cfg.front_script_ids or ()) < 2:
            return ("front_parallel_relay > 1 requires at least 2 "
                    "front_script_ids — fan-out has nothing to race")
        if not (1 <= int(cfg.front_pool_max) <= 1024):
            return f"front_pool_max out of range [1, 1024]: {cfg.front_pool_max}"
        if int(cfg.front_pool_min_idle) < 0:
            return f"front_pool_min_idle must be >= 0: {cfg.front_pool_min_idle}"
        if int(cfg.front_pool_min_idle) > int(cfg.front_pool_max):
            return ("front_pool_min_idle cannot exceed front_pool_max "
                    f"({cfg.front_pool_min_idle} > {cfg.front_pool_max})")
    return None


# ──────────────────────────────────────────────────────────
# core relay
# ──────────────────────────────────────────────────────────
def make_app(
    cfg: Config,
    http_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
    transport_factory: Optional[Callable[[], Transport]] = None,
) -> FastAPI:
    """Build the relay app.

    Two factories are accepted (for tests):
      * `http_factory`      — builds the inner httpx.AsyncClient that the
        Direct transport wraps. Lets tests inject a MockTransport while
        leaving the rest of the relay logic intact.
      * `transport_factory` — builds the outbound Transport directly,
        bypassing httpx entirely. Useful for asserting against the
        Fronted path with a stub.

    If neither is provided, a transport is built from `cfg.transport_mode`.
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

    def _default_transport() -> Transport:
        if cfg.transport_mode == "fronted":
            # Build kwargs explicitly so every Config field that has a
            # FrontedGASConfig counterpart is wired through. Empty
            # sni_hosts → omit the kwarg so the FrontedGASConfig default
            # (the Google SNI rotation pool) takes over.
            kwargs: dict = {
                "connect_host": cfg.front_connect_host or "",
                "http_host": cfg.front_http_host or "script.google.com",
                "verify_ssl": cfg.front_verify_ssl,
                "script_ids": tuple(cfg.front_script_ids or ()),
                "enable_h2": cfg.front_enable_h2,
                "enable_keepalive": cfg.front_enable_keepalive,
                "enable_dev_probe": cfg.front_enable_dev_probe,
                "enable_pool_maintenance": cfg.front_enable_pool_maintenance,
                "parallel_relay": max(1, int(cfg.front_parallel_relay)),
                "pool_max": max(1, int(cfg.front_pool_max)),
                "pool_min_idle": max(0, int(cfg.front_pool_min_idle)),
                "relay_timeout": cfg.upstream_timeout,
                "user_agent": cfg.user_agent,
            }
            if cfg.front_sni_hosts:
                kwargs["sni_hosts"] = tuple(cfg.front_sni_hosts)
            fcfg = FrontedGASConfig(**kwargs)
            # Detect H2 lib at runtime so the log line is honest about
            # whether multiplexing will actually fire.
            try:
                from h2_transport import H2_AVAILABLE  # type: ignore
            except ImportError:  # pragma: no cover
                H2_AVAILABLE = False
            log.info(
                "transport: FRONTED (connect=%s http_host=%s sni_pool=%s "
                "script_ids=%d h2=%s keepalive=%s dev_probe=%s "
                "pool=%d/%d parallel=%d)",
                fcfg.connect_host or "<DNS>",
                fcfg.http_host,
                list(fcfg.sni_hosts),
                len(fcfg.script_ids),
                "on" if (fcfg.enable_h2 and H2_AVAILABLE) else (
                    "off-by-config" if not fcfg.enable_h2
                    else "off-no-h2-lib"),
                "on" if fcfg.enable_keepalive else "off",
                "on" if fcfg.enable_dev_probe else "off",
                fcfg.pool_min_idle, fcfg.pool_max,
                fcfg.parallel_relay,
            )
            if fcfg.enable_h2 and not H2_AVAILABLE:
                log.warning(
                    "front_enable_h2=true but the `h2` library is not "
                    "installed; falling back to HTTP/1.1 only. "
                    "Run: pip install h2"
                )
            return FrontedGASTransport(fcfg)

        client = (http_factory or _default_http)()
        log.info("transport: DIRECT (httpx)")
        return DirectHttpxTransport(client)

    tx_factory = transport_factory or _default_transport

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        transport = tx_factory()
        app.state.transport = transport
        app.state.cfg       = cfg
        app.state.stats     = stats
        log.info("relay listening on http://%s:%s", cfg.listen_host, cfg.listen_port)
        log.info("forwarding to GAS: %s", cfg.gas_url)
        try:
            yield
        finally:
            await transport.aclose()

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
                transport: Transport = app.state.transport
                if method == "POST":
                    resp = await transport.post(
                        cfg.gas_url, params=params, headers=headers, content=encoded_body
                    )
                else:
                    resp = await transport.get(
                        cfg.gas_url, params=params, headers=headers
                    )
                # gas returns 200 + base64-text body on success.
                # network/google-side errors are surfaced as 5xx.
                if resp.status_code >= 500:
                    raise RuntimeError(f"upstream {resp.status_code}")
                # Decode policy:
                #   * 2xx  → strict base64 decode; corrupt body or a GAS
                #            error envelope raises UpstreamDecodeError so
                #            the forward loop retries / surfaces a 502.
                #            Silently-empty bytes would desync VMess.
                #   * else → pass through with empty body. xray uses the
                #            status code (e.g. 403, 404) for diagnostics
                #            and ignores the body when status != 200.
                if 200 <= resp.status_code < 300:
                    raw = _decode_b64_strict(resp.text)
                else:
                    raw = b""
                stats.requests_total += 1
                stats.bytes_up   += len(body)
                stats.bytes_down += len(raw)
                # mirror upstream status code so xray can tell when something is off.
                return Response(
                    content=raw,
                    status_code=resp.status_code,
                    media_type="application/octet-stream",
                )
            except (httpx.RequestError, httpx.HTTPStatusError, UpstreamDecodeError,
                    RuntimeError, OSError, asyncio.TimeoutError) as exc:
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


class UpstreamDecodeError(RuntimeError):
    """The GAS body did not decode as valid base64 ASCII.

    Raised by `_decode_b64_strict` so the forward loop can retry / surface
    a 502 instead of silently handing xray a corrupted byte stream that
    will desync the VMess inner protocol.
    """


# Recognises the JSON envelope that gas/Code.gs produces on error
# (`{"error": "...", "code": ..., "version": "..."}`). Cheap test —
# we don't fully parse JSON here, just sniff the prefix.
_GAS_ERROR_PREFIX_RE = re.compile(rb'^\s*\{\s*"error"\s*:', re.ASCII)


def _decode_b64_strict(text: str) -> bytes:
    """Decode the base64-ASCII body returned by gas/Code.gs.

    Behaviour:
      * empty / whitespace-only → b""  (legitimate: server had nothing
        to forward back, e.g. a flush/keepalive POST).
      * GAS error envelope JSON → raise UpstreamDecodeError with the
        upstream message. Otherwise xray would receive the JSON bytes
        as if they were tunnel data and break framing.
      * any other non-base64 input → raise UpstreamDecodeError.
        Fail loud, never silent — corrupt bytes desync VMess.
    """
    if text is None:
        raise UpstreamDecodeError("upstream returned no body")
    s = text.strip()
    if not s:
        return b""

    raw_bytes = s.encode("ascii", errors="replace") if isinstance(s, str) else s
    if _GAS_ERROR_PREFIX_RE.match(raw_bytes):
        # Surface the upstream message, but keep it bounded so a chatty
        # error envelope can't blow up the log line.
        msg = s[:300].replace("\n", " ").replace("\r", " ")
        raise UpstreamDecodeError(f"GAS error envelope: {msg}")

    pad = (-len(s)) % 4
    if pad:
        s = s + ("=" * pad)
    try:
        # validate=True so non-base64 chars are rejected. The strip()
        # above already removed legitimate trailing whitespace.
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError) as exc:
        preview = text[:80].replace("\n", "\\n")
        raise UpstreamDecodeError(
            f"upstream body is not valid base64: {exc} (first 80 chars: {preview!r})"
        ) from exc


# Backwards-compat shim: existing tests import `_decode_b64_lenient`. It
# now delegates to the strict decoder but swallows UpstreamDecodeError
# back to b"" so callers that opted into "lenient" semantics still see
# the old behaviour. New code in this module uses _decode_b64_strict.
def _decode_b64_lenient(text: str) -> bytes:
    try:
        return _decode_b64_strict(text)
    except UpstreamDecodeError:
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
    p = argparse.ArgumentParser(
        description="mhr-ggate client-side relay",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--gas-url",  help="Google Apps Script web app URL")
    p.add_argument("--secret",   help="shared secret with the GAS/VPS side")
    p.add_argument("--listen",   default=None,
                   help="host:port to listen on (default 127.0.0.1:8000)")
    p.add_argument("--config",   help="optional toml/json config file")
    p.add_argument("--log-level", default=None,
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    # ── transport selection / fronted-mode knobs ──────────────────
    g = p.add_argument_group(
        "fronted transport",
        "Domain-fronting research mode. See "
        "docs/research-fronted-transport.md for the architecture.",
    )
    g.add_argument("--transport", choices=("direct", "fronted"), default=None,
                   help="outbound transport (overrides config file)")
    g.add_argument("--front-connect-host", default=None,
                   help="Google edge IP for the TCP destination "
                        "(empty = DNS-resolve script.google.com)")
    g.add_argument("--front-sni", action="append", default=None,
                   metavar="HOST",
                   help="add an SNI host to the rotation pool (repeatable)")
    g.add_argument("--front-script-id", action="append", default=None,
                   metavar="SID",
                   help="add an Apps Script deployment ID to the round-"
                        "robin pool (repeatable). Empty = single SID from "
                        "the gas_url path.")
    g.add_argument("--front-http-host", default=None,
                   help="HTTP Host header / H2 :authority (default "
                        "script.google.com)")
    g.add_argument("--front-parallel", type=int, default=None,
                   metavar="N",
                   help="fan-out factor: race N concurrent script IDs "
                        "(needs at least N front-script-id entries)")
    g.add_argument("--front-pool-max", type=int, default=None,
                   metavar="N",
                   help="max H1 connections in the fallback pool")
    g.add_argument("--front-pool-min-idle", type=int, default=None,
                   metavar="N",
                   help="target idle H1 connections kept warm in the pool")
    g.add_argument("--no-h2", action="store_true",
                   help="disable HTTP/2 multiplexing; force the H1 pool")
    g.add_argument("--no-keepalive", action="store_true",
                   help="disable Apps Script container keepalive ping")
    g.add_argument("--no-dev-probe", action="store_true",
                   help="disable /dev fast-path probe (sticks with /exec)")
    g.add_argument("--no-pool-maintenance", action="store_true",
                   help="disable background H1 pool refill / purge")
    g.add_argument("--front-insecure", action="store_true",
                   help="skip TLS certificate verification (debug only)")

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

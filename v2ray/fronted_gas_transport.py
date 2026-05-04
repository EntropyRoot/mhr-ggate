#!/usr/bin/env python3
"""
mhr-ggate | Fronted GAS Transport (research)

A *minimal*, raw-byte transport that sends the client_relay's already-
formed GAS request through a domain-fronted TLS connection instead of
plain `httpx`.

Why this file exists
====================
The upstream `mhr-cfw/src/domain_fronter.py` carries the same idea —
TLS-SNI fronting at a Google edge, then HTTP Host pointing at
`script.google.com` — but it does so as part of a full HTTPS web proxy
(MITM, certificate generation, browser request interception, target-site
fetch payloads). All of that is irrelevant for mhr-ggate, which is *not*
a web proxy: the only thing flowing through here is the existing
base64-wrapped Xray byte stream that `client_relay.py` already builds.

Mapping (kept intentionally narrow):

    mhr-cfw DomainFronter.relay(method, url, headers, body)
        ──> rewritten as
    FrontedGASTransport.request(method, gas_url, params, headers, body)

    mhr-cfw web payload JSON  ──> DROPPED
    mhr-cfw MITM / CA / cert  ──> DROPPED
    mhr-cfw target URL fetch  ──> DROPPED
    mhr-ggate base64 raw-body ──> KEPT verbatim

Wire shape (unchanged from `client_relay.py`):

    POST <parsed(gas_url).path>?path=<forward_path>
        Host: script.google.com           ← fronted HTTP host
        X-MHR-Secret: <secret>
        X-MHR-Method: GET|POST
        Content-Type: text/plain; charset=ascii
        Content-Length: <len(b64_body)>
        <b64_body>

    Three-way fronting split:
        connect_host = Google edge IP    (TCP destination)
        sni_host     = www.google.com    (TLS SNI extension; rotated)
        http_host    = script.google.com (HTTP Host header — the *real* dest)

The Google edge accepts TLS to any of its hosted hostnames on the same
IP and dispatches by HTTP Host, which is why the trick works at all.

Scope: research / experiment. We deliberately *omit* every
optimization that does not bear directly on the fronting handshake:
no HTTP/2, no fan-out across script IDs, no batch collector, no
request coalescing, no per-host stats, no CA, no MITM. If that
behaviour is ever wanted, port it from `domain_fronter.py` separately.
"""
from __future__ import annotations

import abc
import asyncio
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional, Sequence
from urllib.parse import urlencode, urlparse

try:
    import certifi
except ImportError:  # optional
    certifi = None

try:
    import httpx
except ImportError:  # pragma: no cover
    httpx = None  # type: ignore

log = logging.getLogger("mhr.transport")


# ──────────────────────────────────────────────────────────────────────
# Constants — copied (not imported) from mhr-cfw/src/constants.py so this
# file stands alone. If you want richer pools later, replace these.
# ──────────────────────────────────────────────────────────────────────
DEFAULT_SNI_POOL: tuple[str, ...] = (
    "www.google.com",
    "mail.google.com",
    "accounts.google.com",
)
DEFAULT_GOOGLE_EDGE_IPS: tuple[str, ...] = (
    "216.239.38.120",
    "142.250.80.142",
    "172.217.16.142",
)
TLS_CONNECT_TIMEOUT = 15.0
RELAY_TIMEOUT = 25.0
POOL_MAX = 16
POOL_TTL = 45.0
MAX_RESPONSE_BODY_BYTES = 200 * 1024 * 1024
MAX_REDIRECTS = 5


# ──────────────────────────────────────────────────────────────────────
# Generic response container — small, transport-agnostic
# ──────────────────────────────────────────────────────────────────────
@dataclass
class TransportResponse:
    status_code: int
    content: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")


class Transport(abc.ABC):
    """Tiny abstract interface, just enough to swap implementations
    inside `client_relay.py` without touching the relay's logic."""

    @abc.abstractmethod
    async def post(
        self,
        url: str,
        *,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        content: bytes | str = b"",
    ) -> TransportResponse: ...

    @abc.abstractmethod
    async def get(
        self,
        url: str,
        *,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> TransportResponse: ...

    async def aclose(self) -> None:  # pragma: no cover - default no-op
        pass


# ──────────────────────────────────────────────────────────────────────
# DirectHttpxTransport — current default; just wraps httpx so the relay
# path through `cfg.transport_mode = "direct"` is identical to today.
# ──────────────────────────────────────────────────────────────────────
class DirectHttpxTransport(Transport):
    def __init__(self, client: "httpx.AsyncClient"):
        if httpx is None:
            raise RuntimeError("httpx is required for DirectHttpxTransport")
        self._client = client

    async def post(self, url, *, params=None, headers=None, content=b""):
        r = await self._client.post(url, params=params, headers=headers, content=content)
        return TransportResponse(
            status_code=r.status_code,
            content=r.content,
            headers={k.lower(): v for k, v in r.headers.items()},
        )

    async def get(self, url, *, params=None, headers=None):
        r = await self._client.get(url, params=params, headers=headers)
        return TransportResponse(
            status_code=r.status_code,
            content=r.content,
            headers={k.lower(): v for k, v in r.headers.items()},
        )

    async def aclose(self) -> None:
        await self._client.aclose()


# ──────────────────────────────────────────────────────────────────────
# FrontedGASTransport
#   - TCP to a Google edge IP (connect_host)
#   - TLS handshake with SNI from a rotation pool       ← the "front"
#   - HTTP/1.1 with Host: script.google.com             ← the real dest
#   - small TTL connection pool, 5x redirect follow
# ──────────────────────────────────────────────────────────────────────
@dataclass
class FrontedGASConfig:
    """All knobs are optional. Sensible defaults make this drop-in usable."""
    connect_host: str = ""            # leave empty → use DNS for parsed url host
    sni_hosts: Sequence[str] = DEFAULT_SNI_POOL
    http_host: str = "script.google.com"
    verify_ssl: bool = True
    tls_connect_timeout: float = TLS_CONNECT_TIMEOUT
    relay_timeout: float = RELAY_TIMEOUT
    pool_max: int = POOL_MAX
    conn_ttl: float = POOL_TTL
    max_response_body_bytes: int = MAX_RESPONSE_BODY_BYTES
    user_agent: str = "mhr-ggate-relay/2.0 (fronted)"


class FrontedGASTransport(Transport):
    """Raw-byte fronted transport for `script.google.com`.

    Adapted from `mhr-cfw/src/domain_fronter.py` (the `_open`,
    `_acquire`, `_release`, `_next_sni`, and `_relay_single` flow). The
    request *body* here is whatever bytes `client_relay.py` hands us —
    typically the base64-ASCII envelope used by the GAS Code.gs — and we
    do not interpret it.
    """

    def __init__(self, config: FrontedGASConfig):
        self.cfg = config
        # Round-robin index for SNI rotation. Per-handshake rotation,
        # not per-request, because we keep TCP+TLS connections in a pool.
        self._sni_idx = 0
        self._sni_hosts = [
            h.strip().lower().rstrip(".")
            for h in (config.sni_hosts or DEFAULT_SNI_POOL)
            if h
        ] or list(DEFAULT_SNI_POOL)

        self._pool: list[
            tuple[asyncio.StreamReader, asyncio.StreamWriter, float]
        ] = []
        self._pool_lock = asyncio.Lock()

    # ── TLS / SNI ────────────────────────────────────────────────────
    def _ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if certifi is not None:
            try:
                ctx.load_verify_locations(cafile=certifi.where())
            except Exception:
                pass
        if not self.cfg.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _next_sni(self) -> str:
        sni = self._sni_hosts[self._sni_idx % len(self._sni_hosts)]
        self._sni_idx += 1
        return sni

    async def _open(self, fallback_host: str):
        """Open one fresh TLS connection.

        - TCP destination is `cfg.connect_host` if set, else `fallback_host`
          (derived from the gas_url) resolved by DNS as usual.
        - SNI is rotated from `cfg.sni_hosts`. This is the actual fronting
          knob: DPI sees TLS to e.g. `mail.google.com` while the HTTP layer
          we send afterwards targets `script.google.com`.
        - TCP_NODELAY on so small writes aren't held by Nagle.
        """
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.setblocking(False)
        target = self.cfg.connect_host or fallback_host
        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (target, 443)),
                timeout=self.cfg.tls_connect_timeout,
            )
            return await asyncio.wait_for(
                asyncio.open_connection(
                    sock=sock,
                    ssl=self._ssl_ctx(),
                    server_hostname=self._next_sni(),
                ),
                timeout=self.cfg.tls_connect_timeout,
            )
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise

    # ── Pool ────────────────────────────────────────────────────────
    async def _acquire(self, fallback_host: str):
        loop_now = asyncio.get_running_loop().time()
        async with self._pool_lock:
            while self._pool:
                reader, writer, created = self._pool.pop()
                if (loop_now - created) < self.cfg.conn_ttl and not reader.at_eof():
                    return reader, writer, created
                try:
                    writer.close()
                except Exception:
                    pass
        reader, writer = await self._open(fallback_host)
        return reader, writer, asyncio.get_running_loop().time()

    async def _release(self, reader, writer, created):
        loop_now = asyncio.get_running_loop().time()
        if (loop_now - created) >= self.cfg.conn_ttl or reader.at_eof():
            try:
                writer.close()
            except Exception:
                pass
            return
        async with self._pool_lock:
            if len(self._pool) < self.cfg.pool_max:
                self._pool.append((reader, writer, created))
            else:
                try:
                    writer.close()
                except Exception:
                    pass

    async def aclose(self) -> None:
        async with self._pool_lock:
            for _, w, _ in self._pool:
                try:
                    w.close()
                except Exception:
                    pass
            self._pool.clear()

    # ── HTTP/1.1 read/write ─────────────────────────────────────────
    async def _read_response(
        self, reader: asyncio.StreamReader
    ) -> tuple[int, dict[str, str], bytes]:
        raw = b""
        # Read headers
        while b"\r\n\r\n" not in raw:
            if len(raw) > 65536:
                raise RuntimeError("response headers exceed 64 KiB")
            chunk = await asyncio.wait_for(reader.read(8192), timeout=8.0)
            if not chunk:
                if not raw:
                    raise RuntimeError("connection closed before any response bytes")
                break
            raw += chunk
        if b"\r\n\r\n" not in raw:
            raise RuntimeError("incomplete response headers")

        head, body = raw.split(b"\r\n\r\n", 1)
        lines = head.split(b"\r\n")
        status_line = lines[0].decode("latin-1", "replace")
        # "HTTP/1.1 200 OK" — extract the status code
        parts = status_line.split(" ", 2)
        try:
            status = int(parts[1])
        except (IndexError, ValueError):
            status = 0

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.decode("latin-1", "replace").split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # Body framing
        te = headers.get("transfer-encoding", "").lower()
        if "chunked" in te:
            body = await self._read_chunked(reader, body)
        else:
            cl = headers.get("content-length")
            if cl is not None:
                try:
                    total = int(cl)
                except ValueError:
                    total = 0
                if total > self.cfg.max_response_body_bytes:
                    raise RuntimeError(
                        f"response Content-Length {total} exceeds cap "
                        f"{self.cfg.max_response_body_bytes}"
                    )
                remaining = total - len(body)
                while remaining > 0:
                    chunk = await asyncio.wait_for(
                        reader.read(min(remaining, 65536)), timeout=20.0
                    )
                    if not chunk:
                        break
                    body += chunk
                    remaining -= len(chunk)
            else:
                # No framing: short-timeout drain (keep-alive safe).
                while True:
                    try:
                        chunk = await asyncio.wait_for(reader.read(65536), timeout=2.0)
                    except asyncio.TimeoutError:
                        break
                    if not chunk:
                        break
                    body += chunk
                    if len(body) > self.cfg.max_response_body_bytes:
                        raise RuntimeError("response body cap exceeded while streaming")

        return status, headers, body

    async def _read_chunked(self, reader: asyncio.StreamReader, buf: bytes) -> bytes:
        out = b""
        cap = self.cfg.max_response_body_bytes
        while True:
            while b"\r\n" not in buf:
                more = await asyncio.wait_for(reader.read(8192), timeout=20.0)
                if not more:
                    return out
                buf += more
            end = buf.find(b"\r\n")
            size_str = buf[:end].decode("latin-1", "replace").strip()
            buf = buf[end + 2 :]
            try:
                size = int(size_str, 16)
            except ValueError:
                break
            if size == 0:
                break
            if size > cap or len(out) + size > cap:
                raise RuntimeError("chunked response cap exceeded")
            while len(buf) < size + 2:
                more = await asyncio.wait_for(reader.read(65536), timeout=20.0)
                if not more:
                    out += buf[:size]
                    return out
                buf += more
            out += buf[:size]
            buf = buf[size + 2 :]
        return out

    # ── Public API ──────────────────────────────────────────────────
    async def post(self, url, *, params=None, headers=None, content=b""):
        return await self._do_request("POST", url, params, headers, content)

    async def get(self, url, *, params=None, headers=None):
        return await self._do_request("GET", url, params, headers, b"")

    async def _do_request(
        self,
        method: str,
        url: str,
        params: Optional[dict],
        headers: Optional[dict],
        content: bytes | str,
    ) -> TransportResponse:
        return await asyncio.wait_for(
            self._send_with_redirects(method, url, params, headers, content),
            timeout=self.cfg.relay_timeout,
        )

    async def _send_with_redirects(
        self,
        method: str,
        url: str,
        params: Optional[dict],
        headers: Optional[dict],
        content: bytes | str,
    ) -> TransportResponse:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"unsupported scheme: {parsed.scheme!r}")
        if parsed.scheme == "http":
            # Fronting is meaningful over TLS; refuse plaintext to avoid
            # silently bypassing the SNI rotation that gives us cover.
            raise ValueError("FrontedGASTransport requires https URLs")

        path = parsed.path or "/"
        query = parsed.query
        if params:
            extra = urlencode(params, doseq=True)
            query = f"{query}&{extra}" if query else extra
        if query:
            path = f"{path}?{query}"

        body_bytes = content.encode("ascii") if isinstance(content, str) else content
        # http_host is the fronted HTTP target, NOT the parsed.netloc — that
        # is the whole point: TLS goes to a Google edge under a benign SNI,
        # but the HTTP Host says script.google.com.
        http_host = self.cfg.http_host

        reader, writer, created = await self._acquire(parsed.hostname or http_host)
        try:
            return await self._exchange_with_redirects(
                reader, writer, method, path, http_host, headers, body_bytes
            )
        finally:
            await self._release(reader, writer, created)

    async def _exchange_with_redirects(
        self,
        reader,
        writer,
        method: str,
        path: str,
        http_host: str,
        headers: Optional[dict],
        body: bytes,
    ) -> TransportResponse:
        cur_method = method
        cur_path = path
        cur_host = http_host
        cur_body = body

        for _ in range(MAX_REDIRECTS + 1):
            req = self._build_request_bytes(
                cur_method, cur_path, cur_host, headers, cur_body
            )
            writer.write(req)
            await writer.drain()

            status, resp_headers, resp_body = await self._read_response(reader)

            if status not in (301, 302, 303, 307, 308):
                return TransportResponse(
                    status_code=status, content=resp_body, headers=resp_headers
                )

            location = resp_headers.get("location")
            if not location:
                return TransportResponse(
                    status_code=status, content=resp_body, headers=resp_headers
                )

            # Apps Script /exec returns 302 → script.googleusercontent.com.
            # That host is served by the same Google edge IPs the TLS
            # connection is already on, so we follow on the same socket and
            # only swap the HTTP Host header, mirroring domain_fronter.py.
            redirect = urlparse(location)
            cur_path = (redirect.path or "/") + (
                f"?{redirect.query}" if redirect.query else ""
            )
            cur_host = redirect.netloc or cur_host
            if status in (307, 308):
                # method & body preserved
                pass
            else:
                cur_method = "GET"
                cur_body = b""

        # Too many redirects — return last response unchanged.
        return TransportResponse(
            status_code=status, content=resp_body, headers=resp_headers
        )

    def _build_request_bytes(
        self,
        method: str,
        path: str,
        host: str,
        headers: Optional[dict],
        body: bytes,
    ) -> bytes:
        lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}",
            f"User-Agent: {self.cfg.user_agent}",
            "Accept-Encoding: identity",
            "Connection: keep-alive",
        ]
        if headers:
            seen = {"host", "user-agent", "accept-encoding", "connection",
                    "content-length"}
            for k, v in headers.items():
                if k.lower() in seen:
                    continue
                lines.append(f"{k}: {v}")
        if body:
            lines.append(f"Content-Length: {len(body)}")
        else:
            lines.append("Content-Length: 0")
        head = "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n"
        return head + body


# ──────────────────────────────────────────────────────────────────────
# Factory — picks Direct vs Fronted from a small config blob
# ──────────────────────────────────────────────────────────────────────
def build_transport(
    *,
    mode: str,
    direct_client: Optional["httpx.AsyncClient"] = None,
    fronted: Optional[FrontedGASConfig] = None,
) -> Transport:
    """Pick a transport based on mode.

    mode="direct"  → DirectHttpxTransport (default; no fronting)
    mode="fronted" → FrontedGASTransport  (research; SNI fronting via Google edge)
    """
    if mode == "fronted":
        return FrontedGASTransport(fronted or FrontedGASConfig())
    if direct_client is None:
        raise ValueError("direct mode requires an httpx.AsyncClient")
    return DirectHttpxTransport(direct_client)


# ──────────────────────────────────────────────────────────────────────
# Optional CLI sanity probe — handy when iterating on the SNI pool.
#
#   python3 v2ray/fronted_gas_transport.py \
#       --gas-url https://script.google.com/macros/s/SID/exec \
#       --secret  YOUR_SECRET
# ──────────────────────────────────────────────────────────────────────
def _self_test() -> int:
    import argparse
    import base64

    p = argparse.ArgumentParser(description="fronted GAS transport probe")
    p.add_argument("--gas-url", required=True)
    p.add_argument("--secret", required=True)
    p.add_argument("--connect-host", default="",
                   help="Google edge IP (default: DNS resolve script.google.com)")
    args = p.parse_args()

    cfg = FrontedGASConfig(connect_host=args.connect_host or "")
    t = FrontedGASTransport(cfg)

    async def go():
        try:
            r = await t.get(
                args.gas_url,
                params={"health": "1"},
                headers={"X-MHR-Secret": args.secret},
            )
            print(f"status={r.status_code}")
            preview = r.content[:200]
            try:
                print("body:", preview.decode("utf-8", "replace"))
            except Exception:
                print("body(b64):", base64.b64encode(preview).decode())
        finally:
            await t.aclose()

    t0 = time.perf_counter()
    asyncio.run(go())
    print(f"elapsed: {(time.perf_counter() - t0) * 1000:.0f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

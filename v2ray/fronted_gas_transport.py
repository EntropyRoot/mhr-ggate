#!/usr/bin/env python3
"""
mhr-ggate | Fronted GAS Transport.

A raw-byte transport for ``client_relay.py``: takes the already-built
GAS request (base64 ASCII body, ``X-MHR-Secret`` / ``X-MHR-Method``
headers, ``?path=`` query) and ships it over a *domain-fronted* TLS
connection instead of plain httpx.

Three-way fronting split (the only trick that matters):

    connect_host  = Google edge IP        TCP destination
    sni_host      = www.google.com        TLS SNI extension (rotated)
    http_host     = script.google.com     HTTP/1.1 Host  /  H2 :authority

The Google edge terminates TLS for any of its hosted hostnames on the
same IPs and then dispatches by HTTP host. From the network's vantage
point the SNI is benign; the real destination is only revealed inside
the TLS tunnel.

Architecture
------------

    FrontedGASTransport
        ├── H2Transport         (one TLS conn, hundreds of streams)
        │      try this first when the `h2` lib is available
        │
        └── H1 connection pool  (TTL-aged, background-refilled)
               fallback when H2 is unavailable / failing

    Optional features (all toggle-able, all default-on when relevant):

      * Multi-Script-ID round-robin   — distribute load across N
        Apps Script deployments to dodge per-script Google quotas.
      * /dev fast-path probe          — Apps Script's /dev endpoint
        skips the 302 → script.googleusercontent.com redirect (~400 ms).
      * Container keepalive           — H2 PING every 4 min; the Apps
        Script container goes cold after ~5 min idle (~600-1500 ms
        cold-start hit on the next request without it).
      * Pool maintenance              — background task purges aged H1
        connections and refills below ``pool_min_idle``.
      * Script-ID blacklist           — short-term ignore-list for
        deployments that fail / time out, to stop them from poisoning
        tail latency.
      * Fan-out parallel relay        — race ``parallel_relay`` distinct
        Script-IDs concurrently, take the first success, cancel the
        rest. Optional, off by default.

Out of scope (mhr-cfw carries these for its web-proxy role; mhr-ggate
moves opaque Xray bytes so none apply): MITM, CA generation,
target-URL fetching, JSON web payload, batch ``fetchAll``, request
coalescing, range probes, per-target-host stats.
"""
from __future__ import annotations

import abc
import asyncio
import logging
import random
import re
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

try:
    from h2_transport import H2_AVAILABLE, H2Transport
except ImportError:  # pragma: no cover
    H2_AVAILABLE = False
    H2Transport = None  # type: ignore

log = logging.getLogger("mhr.transport")


# ──────────────────────────────────────────────────────────────────────
# Constants
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
POOL_MIN_IDLE = 4
POOL_TTL = 45.0
MAX_RESPONSE_BODY_BYTES = 200 * 1024 * 1024
MAX_REDIRECTS = 5
KEEPALIVE_INTERVAL = 240.0       # 4 min — Apps Script idle timeout is ~5 min
POOL_MAINTENANCE_INTERVAL = 3.0
SCRIPT_BLACKLIST_TTL = 600.0     # 10 min
H2_FAILURE_THRESHOLD = 3
H2_DISABLE_COOLDOWN = 60.0

# Matches the `<sid>` segment in `/macros/s/<sid>/(exec|dev)`.
_SID_PATH_RE = re.compile(r"^(.*?/macros/s/)([^/]+)(/(?:exec|dev).*)$")


# ──────────────────────────────────────────────────────────────────────
# Public response container
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
    """Tiny abstract interface that ``client_relay.py`` codes against."""

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
# DirectHttpxTransport — the no-fronting baseline
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
# FrontedGASConfig
# ──────────────────────────────────────────────────────────────────────
@dataclass
class FrontedGASConfig:
    """All knobs are optional. Defaults are tuned for the typical
    scMaxConcurrentPosts=100 xhttp workload.

    Only ``connect_host`` and ``sni_hosts`` are *fronting* knobs. The
    rest are throughput / resilience tuning. ``script_ids`` is empty
    by default; when empty, the SID is read from the gas_url path."""

    # ── Fronting (the actual research surface) ─────────────────────
    connect_host: str = ""
    sni_hosts: Sequence[str] = DEFAULT_SNI_POOL
    http_host: str = "script.google.com"
    verify_ssl: bool = True

    # ── Multi-deployment ──────────────────────────────────────────
    # When non-empty, the transport rewrites the SID segment of
    # ``/macros/s/<sid>/(exec|dev)`` on each request to round-robin
    # across this list (skipping currently-blacklisted IDs).
    script_ids: Sequence[str] = ()

    # ── HTTP/2 ─────────────────────────────────────────────────────
    enable_h2: bool = True
    h2_initial_window_size: int = 8 * 1024 * 1024

    # ── Container keepalive ───────────────────────────────────────
    enable_keepalive: bool = True
    keepalive_interval: float = KEEPALIVE_INTERVAL

    # ── /dev fast-path probe ──────────────────────────────────────
    enable_dev_probe: bool = True

    # ── Connection pool (H1 fallback) ─────────────────────────────
    pool_max: int = POOL_MAX
    pool_min_idle: int = POOL_MIN_IDLE
    conn_ttl: float = POOL_TTL
    enable_pool_maintenance: bool = True
    pool_maintenance_interval: float = POOL_MAINTENANCE_INTERVAL

    # ── Fan-out (off by default) ──────────────────────────────────
    parallel_relay: int = 1

    # ── Script-ID blacklist ───────────────────────────────────────
    script_blacklist_ttl: float = SCRIPT_BLACKLIST_TTL

    # ── Timeouts / size caps / UA ─────────────────────────────────
    tls_connect_timeout: float = TLS_CONNECT_TIMEOUT
    relay_timeout: float = RELAY_TIMEOUT
    max_response_body_bytes: int = MAX_RESPONSE_BODY_BYTES
    user_agent: str = "mhr-ggate-relay/2.0 (fronted)"


@dataclass
class FrontedStats:
    started_at: float = field(default_factory=time.time)
    h2_requests: int = 0
    h1_requests: int = 0
    h2_failures: int = 0
    h1_failures: int = 0
    fanout_wins: int = 0
    keepalive_pings: int = 0
    pool_opens: int = 0
    pool_reuses: int = 0
    blacklist_events: int = 0
    last_sni: str = ""
    dev_fast_path: bool = False

    def as_dict(self) -> dict:
        return {
            "uptime_sec": round(time.time() - self.started_at, 1),
            "h2_requests": self.h2_requests,
            "h1_requests": self.h1_requests,
            "h2_failures": self.h2_failures,
            "h1_failures": self.h1_failures,
            "fanout_wins": self.fanout_wins,
            "keepalive_pings": self.keepalive_pings,
            "pool_opens": self.pool_opens,
            "pool_reuses": self.pool_reuses,
            "blacklist_events": self.blacklist_events,
            "last_sni": self.last_sni,
            "dev_fast_path": self.dev_fast_path,
        }


# ──────────────────────────────────────────────────────────────────────
# FrontedGASTransport
# ──────────────────────────────────────────────────────────────────────
class FrontedGASTransport(Transport):
    """Fronted transport with H2 mux + H1 pool fallback + multi-SID +
    keepalive + /dev probe + (optional) fan-out."""

    def __init__(self, config: FrontedGASConfig):
        self.cfg = config
        self.stats = FrontedStats()

        self._sni_hosts = self._normalize_sni_pool(config.sni_hosts)
        self._sni_idx = 0

        self._script_ids: list[str] = [s for s in (config.script_ids or ()) if s]
        self._script_idx = 0
        self._sid_blacklist: dict[str, float] = {}

        # H1 pool: list of (reader, writer, created_at)
        self._pool: list[
            tuple[asyncio.StreamReader, asyncio.StreamWriter, float]
        ] = []
        self._pool_lock = asyncio.Lock()

        # H2 connection (lazy; created on first request when usable).
        self._h2: Optional[H2Transport] = None  # type: ignore[type-arg]
        self._h2_failure_streak = 0
        self._h2_disabled_until = 0.0
        self._h2_init_lock = asyncio.Lock()

        # /dev fast-path is only flipped on after a successful probe.
        self._dev_available = False

        # Background tasks (lazy-started on first request)
        self._bg_started = False
        self._bg_lock = asyncio.Lock()
        self._bg_tasks: set[asyncio.Task] = set()
        self._closed = False

    # ── Helpers / knobs ──────────────────────────────────────────────
    @staticmethod
    def _normalize_sni_pool(pool: Sequence[str]) -> list[str]:
        cleaned = [
            h.strip().lower().rstrip(".")
            for h in (pool or DEFAULT_SNI_POOL)
            if h
        ]
        return cleaned or list(DEFAULT_SNI_POOL)

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
        self.stats.last_sni = sni
        return sni

    # ── Script-ID rotation + blacklist ───────────────────────────────
    def _is_sid_blacklisted(self, sid: str) -> bool:
        until = self._sid_blacklist.get(sid, 0.0)
        if until and until > time.time():
            return True
        if until:
            self._sid_blacklist.pop(sid, None)
        return False

    def _blacklist_sid(self, sid: str, reason: str = "") -> None:
        # Single-SID configs get nowhere by blacklisting their only ID.
        if len(self._script_ids) <= 1:
            return
        self._sid_blacklist[sid] = time.time() + self.cfg.script_blacklist_ttl
        self.stats.blacklist_events += 1
        log.warning(
            "Blacklisted SID %s for %.0fs%s",
            sid[-8:] if len(sid) > 8 else sid,
            self.cfg.script_blacklist_ttl,
            f" ({reason})" if reason else "",
        )

    def _next_script_id(self) -> Optional[str]:
        if not self._script_ids:
            return None
        n = len(self._script_ids)
        for _ in range(n):
            sid = self._script_ids[self._script_idx % n]
            self._script_idx += 1
            if not self._is_sid_blacklisted(sid):
                return sid
        # All blacklisted — drop the oldest and try again rather than
        # stalling the relay entirely.
        for sid in list(self._sid_blacklist):
            self._sid_blacklist.pop(sid, None)
        sid = self._script_ids[self._script_idx % n]
        self._script_idx += 1
        return sid

    def _pick_fanout_sids(self) -> list[Optional[str]]:
        """Pick up to ``parallel_relay`` distinct non-blacklisted SIDs.
        Returns ``[None]`` when no SID list is configured (fan-out then
        becomes a no-op and the caller takes the single-shot path)."""
        n = max(1, self.cfg.parallel_relay)
        if not self._script_ids or n == 1:
            return [self._next_script_id()]
        primary = self._next_script_id()
        picked: list[Optional[str]] = [primary]
        for sid in self._script_ids:
            if len(picked) >= n:
                break
            if sid == primary or self._is_sid_blacklisted(sid):
                continue
            picked.append(sid)
        return picked

    # ── URL surgery: rewrite SID + dev/exec ──────────────────────────
    def _rewrite_path(self, base_path: str, sid: Optional[str]) -> str:
        """Rewrite the SID segment and the /exec or /dev tail.

        ``base_path`` is the path component of the original gas_url
        plus optional query string. We only touch the ``/macros/s/<sid>``
        part — anything else is preserved verbatim so a non-Apps-Script
        URL would round-trip unchanged."""
        match = _SID_PATH_RE.match(base_path)
        if not match:
            return base_path
        prefix, current_sid, tail = match.group(1), match.group(2), match.group(3)
        new_sid = sid or current_sid
        # Promote /exec → /dev when the probe has confirmed it works,
        # because /dev replies inline (no 302) and saves ~400 ms.
        if self._dev_available:
            tail = re.sub(r"^/exec(\b|$)", r"/dev\1", tail, count=1)
        return f"{prefix}{new_sid}{tail}"

    # ── Background tasks ─────────────────────────────────────────────
    def _spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)
        return task

    async def _ensure_bg_started(self) -> None:
        if self._bg_started or self._closed:
            return
        async with self._bg_lock:
            if self._bg_started or self._closed:
                return
            self._bg_started = True
            if self.cfg.enable_pool_maintenance:
                self._spawn(self._pool_maintenance_loop())

    async def _pool_maintenance_loop(self) -> None:
        """Purge aged / dead H1 conns; refill below pool_min_idle.

        Only relevant when H2 is unavailable or disabled — when H2 is
        carrying traffic, the H1 pool stays empty and this is a no-op."""
        try:
            while not self._closed:
                await asyncio.sleep(self.cfg.pool_maintenance_interval)
                if self._closed:
                    return
                # If H2 is healthy, don't burn handshakes maintaining an idle pool.
                if self._h2 is not None and self._h2.is_connected:
                    continue
                now = asyncio.get_running_loop().time()
                async with self._pool_lock:
                    alive = [
                        item for item in self._pool
                        if (now - item[2]) < self.cfg.conn_ttl and not item[0].at_eof()
                    ]
                    dead = len(self._pool) - len(alive)
                    self._pool = alive
                    idle = len(self._pool)
                if dead:
                    log.debug("pool maintenance: purged %d aged/dead conns", dead)
                needed = max(0, self.cfg.pool_min_idle - idle)
                if needed:
                    await asyncio.gather(
                        *(self._add_pool_conn() for _ in range(min(needed, 4))),
                        return_exceptions=True,
                    )
        except asyncio.CancelledError:
            return
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("pool maintenance loop crashed: %s", exc)

    async def _keepalive_loop(self) -> None:
        """Periodic H2 PING to keep the Apps Script container warm.

        Apps Script idles out a container at ~5 min; cold-starting
        on the next real request adds 600-1500 ms. A cheap PING every
        4 min keeps the upstream warm at near-zero cost."""
        try:
            while not self._closed and self._h2 is not None:
                await asyncio.sleep(self.cfg.keepalive_interval)
                if self._closed or self._h2 is None:
                    return
                if not self._h2.is_connected:
                    try:
                        await self._h2.reconnect()
                    except Exception as exc:
                        log.debug("keepalive reconnect failed: %s", exc)
                        continue
                try:
                    await self._h2.ping()
                    self.stats.keepalive_pings += 1
                except Exception as exc:
                    log.debug("keepalive ping failed: %s", exc)
        except asyncio.CancelledError:
            return

    # ── H2 lifecycle ─────────────────────────────────────────────────
    def _h2_usable(self) -> bool:
        return (
            self.cfg.enable_h2
            and H2_AVAILABLE
            and self._h2 is not None
            and self._h2.is_connected
            and time.time() >= self._h2_disabled_until
        )

    async def _ensure_h2(self, fallback_host: str) -> bool:
        """Bring up the H2 connection lazily on first use. Returns
        True if the H2 transport is connected and usable."""
        if not (self.cfg.enable_h2 and H2_AVAILABLE):
            return False
        if time.time() < self._h2_disabled_until:
            return False
        if self._h2 is not None and self._h2.is_connected:
            return True
        async with self._h2_init_lock:
            if self._h2 is not None and self._h2.is_connected:
                return True
            target = self.cfg.connect_host or fallback_host
            try:
                if self._h2 is None:
                    assert H2Transport is not None
                    self._h2 = H2Transport(
                        connect_host=target,
                        sni_hosts=self._sni_hosts,
                        verify_ssl=self.cfg.verify_ssl,
                        tls_connect_timeout=self.cfg.tls_connect_timeout,
                        initial_window_size=self.cfg.h2_initial_window_size,
                    )
                await asyncio.wait_for(
                    self._h2.ensure_connected(),
                    timeout=self.cfg.tls_connect_timeout + 2.0,
                )
                self._record_h2_success()
                if self.cfg.enable_keepalive:
                    self._spawn(self._keepalive_loop())
                # Probe /dev once on first connection.
                if self.cfg.enable_dev_probe and not self._dev_available:
                    self._spawn(self._probe_dev_path())
                return True
            except Exception as exc:
                self._record_h2_failure(exc)
                log.info("H2 unavailable, falling back to H1 (%s)", exc)
                return False

    def _record_h2_success(self) -> None:
        self._h2_failure_streak = 0

    def _record_h2_failure(self, exc: BaseException) -> None:
        self.stats.h2_failures += 1
        self._h2_failure_streak += 1
        if self._h2_failure_streak >= H2_FAILURE_THRESHOLD:
            self._h2_disabled_until = time.time() + H2_DISABLE_COOLDOWN
            log.warning(
                "H2 disabled for %.0fs after %d failures (%s)",
                H2_DISABLE_COOLDOWN, self._h2_failure_streak,
                type(exc).__name__,
            )
            self._h2_failure_streak = 0

    async def _probe_dev_path(self) -> None:
        """One-shot probe: does ``/dev`` reply inline? If yes, we save
        ~400 ms per request by skipping the /exec→ucontent redirect."""
        if self._h2 is None or not self._h2.is_connected:
            return
        if not self._script_ids and not _SID_PATH_RE.match("/macros/s/x/exec"):
            return
        # Pick any SID to probe — preference order: configured, else
        # we cannot probe without one, so bail.
        sid = self._next_script_id()
        if not sid:
            return
        path = f"/macros/s/{sid}/dev?path=/_mhr/health"
        try:
            status, _, body = await asyncio.wait_for(
                self._h2.request(
                    method="GET", path=path, host=self.cfg.http_host,
                    headers={"accept-encoding": "identity"},
                ),
                timeout=8.0,
            )
            # /dev returns 200 inline on a working deployment. If it
            # 302s or errors, leave _dev_available=False (default).
            if status == 200 and body:
                self._dev_available = True
                self.stats.dev_fast_path = True
                log.info("/dev fast-path active (no redirect, ~400 ms saved/req)")
        except Exception as exc:
            log.debug("/dev probe failed (sticking with /exec): %s", exc)

    # ── H1 pool ──────────────────────────────────────────────────────
    async def _open_h1(self, fallback_host: str):
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass
        sock.setblocking(False)
        target = self.cfg.connect_host or fallback_host
        try:
            await asyncio.wait_for(
                loop.sock_connect(sock, (target, 443)),
                timeout=self.cfg.tls_connect_timeout,
            )
            return await asyncio.wait_for(
                asyncio.open_connection(
                    sock=sock, ssl=self._ssl_ctx(),
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

    async def _add_pool_conn(self) -> None:
        try:
            target = self.cfg.connect_host or self.cfg.http_host
            r, w = await asyncio.wait_for(
                self._open_h1(target), timeout=self.cfg.tls_connect_timeout,
            )
        except Exception:
            return
        t = asyncio.get_running_loop().time()
        async with self._pool_lock:
            if len(self._pool) < self.cfg.pool_max:
                self._pool.append((r, w, t))
                self.stats.pool_opens += 1
            else:
                try:
                    w.close()
                except Exception:
                    pass

    async def _acquire_h1(self, fallback_host: str):
        loop_now = asyncio.get_running_loop().time()
        async with self._pool_lock:
            while self._pool:
                reader, writer, created = self._pool.pop()
                if (loop_now - created) < self.cfg.conn_ttl and not reader.at_eof():
                    self.stats.pool_reuses += 1
                    return reader, writer, created
                try:
                    writer.close()
                except Exception:
                    pass
        reader, writer = await self._open_h1(fallback_host)
        self.stats.pool_opens += 1
        return reader, writer, asyncio.get_running_loop().time()

    async def _release_h1(self, reader, writer, created):
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

    # ── Public API ───────────────────────────────────────────────────
    async def post(self, url, *, params=None, headers=None, content=b""):
        return await self._do_request("POST", url, params, headers, content)

    async def get(self, url, *, params=None, headers=None):
        return await self._do_request("GET", url, params, headers, b"")

    async def aclose(self) -> None:
        self._closed = True
        for task in list(self._bg_tasks):
            task.cancel()
        if self._bg_tasks:
            await asyncio.gather(*self._bg_tasks, return_exceptions=True)
        self._bg_tasks.clear()
        if self._h2 is not None:
            try:
                await self._h2.close()
            except Exception:
                pass
        async with self._pool_lock:
            for _, w, _ in self._pool:
                try:
                    w.close()
                except Exception:
                    pass
            self._pool.clear()

    # ── Core dispatch ────────────────────────────────────────────────
    async def _do_request(
        self,
        method: str,
        url: str,
        params: Optional[dict],
        headers: Optional[dict],
        content: bytes | str,
    ) -> TransportResponse:
        await self._ensure_bg_started()
        return await asyncio.wait_for(
            self._dispatch(method, url, params, headers, content),
            timeout=self.cfg.relay_timeout,
        )

    def _build_path(self, parsed_url, params: Optional[dict],
                    sid: Optional[str]) -> str:
        path = parsed_url.path or "/"
        query = parsed_url.query
        if params:
            extra = urlencode(params, doseq=True)
            query = f"{query}&{extra}" if query else extra
        full = f"{path}?{query}" if query else path
        return self._rewrite_path(full, sid)

    async def _dispatch(
        self,
        method: str,
        url: str,
        params: Optional[dict],
        headers: Optional[dict],
        content: bytes | str,
    ) -> TransportResponse:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            raise ValueError("FrontedGASTransport requires https URLs")

        body_bytes = content.encode("ascii") if isinstance(content, str) else content
        fallback_host = parsed.hostname or self.cfg.http_host

        # Fan-out path is ``parallel_relay > 1`` and at least 2 SIDs.
        if self.cfg.parallel_relay > 1 and len(self._script_ids) > 1:
            sids = self._pick_fanout_sids()
            if len([s for s in sids if s]) > 1:
                return await self._fanout(method, parsed, params, headers,
                                          body_bytes, fallback_host, sids)

        # Single-shot: try H2 first, fall back to H1 on failure.
        sid = self._next_script_id()
        last_exc: Optional[BaseException] = None
        if await self._ensure_h2(fallback_host):
            try:
                return await self._send_h2(
                    method, parsed, params, headers, body_bytes, sid,
                )
            except Exception as exc:
                last_exc = exc
                self._record_h2_failure(exc)
                log.debug("H2 send failed (%s), falling back to H1", exc)
                if sid is not None:
                    self._blacklist_sid(sid, reason=f"h2:{type(exc).__name__}")

        # H1 fallback.
        try:
            return await self._send_h1(
                method, parsed, params, headers, body_bytes, sid, fallback_host,
            )
        except Exception as exc:
            self.stats.h1_failures += 1
            if sid is not None:
                self._blacklist_sid(sid, reason=f"h1:{type(exc).__name__}")
            raise exc if last_exc is None else exc from last_exc

    async def _fanout(
        self, method, parsed, params, headers, body, fallback_host,
        sids: list[Optional[str]],
    ) -> TransportResponse:
        """Race ``len(sids)`` parallel requests; first success wins,
        the rest are cancelled. Failed racers get blacklisted so a
        slow/cold container stops poisoning subsequent fan-outs."""
        async def one(sid: Optional[str]) -> TransportResponse:
            if await self._ensure_h2(fallback_host):
                try:
                    return await self._send_h2(
                        method, parsed, params, headers, body, sid,
                    )
                except Exception as exc:
                    if sid is not None:
                        self._blacklist_sid(sid, reason=f"h2:{type(exc).__name__}")
                    raise
            try:
                return await self._send_h1(
                    method, parsed, params, headers, body, sid, fallback_host,
                )
            except Exception as exc:
                if sid is not None:
                    self._blacklist_sid(sid, reason=f"h1:{type(exc).__name__}")
                raise

        tasks = {asyncio.create_task(one(s)): s for s in sids}
        pending = set(tasks.keys())
        last_exc: Optional[BaseException] = None
        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending, return_when=asyncio.FIRST_COMPLETED,
                )
                for t in done:
                    exc = t.exception()
                    if exc is None:
                        self.stats.fanout_wins += 1
                        return t.result()
                    last_exc = exc
            if last_exc is not None:
                raise last_exc
            raise RuntimeError("fan-out: all racers failed")
        finally:
            for t in pending:
                t.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)

    # ── Send paths ───────────────────────────────────────────────────
    async def _send_h2(
        self, method, parsed, params, headers, body, sid: Optional[str],
    ) -> TransportResponse:
        assert self._h2 is not None
        path = self._build_path(parsed, params, sid)
        # H2 strips Host from request headers (it lives in :authority).
        # Drop Content-Length / Connection / Host / etc. — the H2 layer
        # owns them.
        h2_headers = self._sanitize_headers_for_h2(headers, len(body))
        status, resp_headers, resp_body = await self._h2.request(
            method=method, path=path, host=self.cfg.http_host,
            headers=h2_headers, body=body or None,
        )
        self.stats.h2_requests += 1
        self._record_h2_success()
        return TransportResponse(
            status_code=status, content=resp_body, headers=resp_headers,
        )

    @staticmethod
    def _sanitize_headers_for_h2(
        headers: Optional[dict], body_len: int,
    ) -> dict[str, str]:
        if not headers:
            return {}
        skip = {"host", "connection", "keep-alive", "content-length",
                "transfer-encoding", "upgrade", "proxy-connection", "te"}
        out: dict[str, str] = {}
        for k, v in headers.items():
            if k.lower() in skip:
                continue
            out[k.lower()] = str(v)
        return out

    async def _send_h1(
        self, method, parsed, params, headers, body, sid, fallback_host,
    ) -> TransportResponse:
        path = self._build_path(parsed, params, sid)
        reader, writer, created = await self._acquire_h1(fallback_host)
        try:
            resp = await self._h1_exchange(
                reader, writer, method, path, headers, body,
            )
            self.stats.h1_requests += 1
            return resp
        finally:
            await self._release_h1(reader, writer, created)

    async def _h1_exchange(
        self, reader, writer, method, path, headers, body,
    ) -> TransportResponse:
        cur_method, cur_path, cur_host, cur_body = (
            method, path, self.cfg.http_host, body,
        )
        last_status = 0
        last_headers: dict[str, str] = {}
        last_body = b""
        for _ in range(MAX_REDIRECTS + 1):
            req = self._build_h1_request(
                cur_method, cur_path, cur_host, headers, cur_body,
            )
            writer.write(req)
            await writer.drain()
            status, resp_headers, resp_body = await self._read_h1_response(reader)
            last_status, last_headers, last_body = status, resp_headers, resp_body
            if status not in (301, 302, 303, 307, 308):
                return TransportResponse(
                    status_code=status, content=resp_body, headers=resp_headers,
                )
            location = resp_headers.get("location")
            if not location:
                return TransportResponse(
                    status_code=status, content=resp_body, headers=resp_headers,
                )
            redirect = urlparse(location)
            cur_path = (redirect.path or "/") + (
                f"?{redirect.query}" if redirect.query else ""
            )
            cur_host = redirect.netloc or cur_host
            if status in (307, 308):
                pass  # method + body preserved
            else:
                cur_method = "GET"
                cur_body = b""
        return TransportResponse(
            status_code=last_status, content=last_body, headers=last_headers,
        )

    def _build_h1_request(
        self, method, path, host, headers, body,
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
        lines.append(f"Content-Length: {len(body) if body else 0}")
        head = "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n"
        return head + (body or b"")

    # ── HTTP/1.1 read path ───────────────────────────────────────────
    async def _read_h1_response(
        self, reader: asyncio.StreamReader,
    ) -> tuple[int, dict[str, str], bytes]:
        raw = b""
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
                        reader.read(min(remaining, 65536)), timeout=20.0,
                    )
                    if not chunk:
                        break
                    body += chunk
                    remaining -= len(chunk)
            else:
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
        """Strict RFC 7230 chunked decoder. See test_fronted_transport.py
        for the edge cases it rejects (bad size, missing CRLF, EOF mid-
        chunk, unconsumed trailers). Strict because the TLS connection
        is pooled — leftover bytes desync the next response."""
        out = bytearray()
        cap = self.cfg.max_response_body_bytes

        async def _need_line() -> bytes:
            nonlocal buf
            while b"\r\n" not in buf:
                more = await asyncio.wait_for(reader.read(8192), timeout=20.0)
                if not more:
                    raise RuntimeError("chunked: EOF while reading line")
                buf += more
                if len(buf) > 65536:
                    raise RuntimeError("chunked: line longer than 64 KiB")
            line, _, rest = buf.partition(b"\r\n")
            buf = rest
            return line

        async def _need_bytes(n: int) -> bytes:
            nonlocal buf
            while len(buf) < n:
                more = await asyncio.wait_for(
                    reader.read(min(65536, n - len(buf))), timeout=20.0,
                )
                if not more:
                    raise RuntimeError(
                        f"chunked: EOF after {len(out)} body bytes "
                        f"(needed {n - len(buf)} more in this chunk)"
                    )
                buf += more
            data, buf = buf[:n], buf[n:]
            return data

        while True:
            line = await _need_line()
            head = line.split(b";", 1)[0].strip()
            if not head:
                raise RuntimeError("chunked: empty chunk size line")
            try:
                size = int(head, 16)
            except ValueError as exc:
                raise RuntimeError(f"chunked: bad chunk size {head!r}") from exc
            if size < 0:
                raise RuntimeError(f"chunked: negative chunk size {size}")
            if size == 0:
                while True:
                    trailer = await _need_line()
                    if trailer == b"":
                        break
                break
            if size > cap or len(out) + size > cap:
                raise RuntimeError(f"chunked: response exceeds cap of {cap} bytes")
            chunk = await _need_bytes(size)
            out.extend(chunk)
            sep = await _need_bytes(2)
            if sep != b"\r\n":
                raise RuntimeError(f"chunked: missing CRLF after chunk data, got {sep!r}")
        return bytes(out)


# ──────────────────────────────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────────────────────────────
def build_transport(
    *,
    mode: str,
    direct_client: Optional["httpx.AsyncClient"] = None,
    fronted: Optional[FrontedGASConfig] = None,
) -> Transport:
    if mode == "fronted":
        return FrontedGASTransport(fronted or FrontedGASConfig())
    if direct_client is None:
        raise ValueError("direct mode requires an httpx.AsyncClient")
    return DirectHttpxTransport(direct_client)


# ──────────────────────────────────────────────────────────────────────
# CLI sanity probe
# ──────────────────────────────────────────────────────────────────────
def _self_test() -> int:
    import argparse
    import base64

    p = argparse.ArgumentParser(description="fronted GAS transport probe")
    p.add_argument("--gas-url", required=True)
    p.add_argument("--secret", required=True)
    p.add_argument("--connect-host", default="")
    p.add_argument("--script-id", action="append", default=[],
                   help="extra Apps Script ID for round-robin (repeatable)")
    p.add_argument("--no-h2", action="store_true",
                   help="disable HTTP/2; force H1 path")
    p.add_argument("--parallel", type=int, default=1)
    args = p.parse_args()

    cfg = FrontedGASConfig(
        connect_host=args.connect_host or "",
        script_ids=tuple(args.script_id),
        enable_h2=not args.no_h2,
        parallel_relay=args.parallel,
    )
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
            print("stats:", t.stats.as_dict())
        finally:
            await t.aclose()

    t0 = time.perf_counter()
    asyncio.run(go())
    print(f"elapsed: {(time.perf_counter() - t0) * 1000:.0f} ms")
    return 0


if __name__ == "__main__":
    raise SystemExit(_self_test())

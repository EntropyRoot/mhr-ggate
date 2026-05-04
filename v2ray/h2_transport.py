#!/usr/bin/env python3
"""
mhr-ggate | HTTP/2 transport over a domain-fronted TLS connection.

Why this file exists
====================
xray's xhttp/splithttp transport opens many small POSTs in parallel
(``scMaxConcurrentPosts: 100`` in the generated client config). On
HTTP/1.1 each POST holds a TCP+TLS connection for its lifetime, so a
30-connection pool tops out at 30 concurrent requests; the other 70 are
queued. HTTP/2 lifts that to one TLS connection × hundreds of
multiplexed streams, which is what this transport gives the relay.

Adapted from `mhr-cfw/src/h2_transport.py` (~490 lines) but trimmed:
no auto-decompression (our base64 bodies are already compact, gzip
costs more than it saves on small payloads) and no gzip/brotli/zstd
codec dependency.

Optional dependency
-------------------
``h2``. The transport is only constructed when ``h2`` is importable,
otherwise the parent ``FrontedGASTransport`` falls back to its
HTTP/1.1 path. ``H2_AVAILABLE`` is the public flag.
"""
from __future__ import annotations

import asyncio
import logging
import socket
import ssl
from dataclasses import dataclass
from typing import Optional, Sequence
from urllib.parse import urlparse

try:
    import certifi
except ImportError:  # optional
    certifi = None

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.settings

    H2_AVAILABLE = True
except ImportError:
    H2_AVAILABLE = False

log = logging.getLogger("mhr.h2")


@dataclass
class _StreamState:
    """In-flight state for one HTTP/2 stream."""
    status: int = 0
    headers: dict[str, str] = None  # type: ignore[assignment]
    data: bytearray = None  # type: ignore[assignment]
    done: asyncio.Event = None  # type: ignore[assignment]
    error: Optional[str] = None

    def __post_init__(self) -> None:
        if self.headers is None:
            self.headers = {}
        if self.data is None:
            self.data = bytearray()
        if self.done is None:
            self.done = asyncio.Event()


class H2Transport:
    """Persistent fronted HTTP/2 connection.

    All requests run as concurrent streams on a single TLS connection
    that is *fronted*: TCP→Google edge IP, SNI rotated through a
    Google-owned pool, ``:authority`` pinned to the real target
    (``script.google.com``).

    Auto-reconnects on read-loop EOF / TLS close-notify, with a 1-second
    minimum interval to prevent reconnect storms when many concurrent
    requests fail at once.
    """

    _RECONNECT_MIN_INTERVAL = 1.0

    def __init__(
        self,
        connect_host: str,
        sni_hosts: Sequence[str],
        *,
        verify_ssl: bool = True,
        tls_connect_timeout: float = 15.0,
        initial_window_size: int = 8 * 1024 * 1024,
        connection_window_increment: int = (2 ** 24) - 65535,
    ):
        if not H2_AVAILABLE:
            raise RuntimeError("h2 library is not installed; pip install h2")
        self._connect_host = connect_host
        self._sni_hosts = [h for h in (sni_hosts or []) if h] or ["www.google.com"]
        self._sni_idx = 0
        self._verify_ssl = verify_ssl
        self._tls_connect_timeout = tls_connect_timeout
        self._initial_window_size = initial_window_size
        self._connection_window_increment = connection_window_increment

        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        self._h2: Optional["h2.connection.H2Connection"] = None
        self._connected = False

        self._write_lock = asyncio.Lock()
        self._connect_lock = asyncio.Lock()
        self._read_task: Optional[asyncio.Task] = None
        self._conn_generation = 0
        self._last_reconnect_at = 0.0

        self._streams: dict[int, _StreamState] = {}

        self.total_requests = 0
        self.total_streams = 0
        self.last_sni: str = ""

    @property
    def is_connected(self) -> bool:
        return self._connected

    # ── Connection lifecycle ───────────────────────────────────────────
    async def ensure_connected(self) -> None:
        if self._connected:
            return
        async with self._connect_lock:
            if self._connected:
                return
            await self._do_connect()

    def _ssl_ctx(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        if certifi is not None:
            try:
                ctx.load_verify_locations(cafile=certifi.where())
            except Exception:
                pass
        # Advertise both — some DPI blocks h2-only ALPN. Server picks h2.
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        if not self._verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def _next_sni(self) -> str:
        sni = self._sni_hosts[self._sni_idx % len(self._sni_hosts)]
        self._sni_idx += 1
        return sni

    async def _do_connect(self) -> None:
        # Open the TCP socket first with TCP_NODELAY+keepalive *before*
        # the TLS handshake. Nagle would otherwise delay small H2 frames
        # by ~40-200 ms while it waits to coalesce.
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        except OSError:
            pass
        sock.setblocking(False)

        sni = self._next_sni()
        self.last_sni = sni
        try:
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_connect(sock, (self._connect_host, 443)),
                timeout=self._tls_connect_timeout,
            )
            self._reader, self._writer = await asyncio.wait_for(
                asyncio.open_connection(
                    sock=sock, ssl=self._ssl_ctx(), server_hostname=sni,
                ),
                timeout=self._tls_connect_timeout,
            )
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            raise

        ssl_obj = self._writer.get_extra_info("ssl_object")
        negotiated = ssl_obj.selected_alpn_protocol() if ssl_obj else None
        if negotiated != "h2":
            try:
                self._writer.close()
            except Exception:
                pass
            raise RuntimeError(f"H2 ALPN negotiation failed (got {negotiated!r})")

        cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        self._h2 = h2.connection.H2Connection(config=cfg)
        self._h2.initiate_connection()
        # Connection-level window: ~16 MiB. Per-stream: 8 MiB initial
        # window so even a fat POST doesn't stall on WINDOW_UPDATE.
        self._h2.increment_flow_control_window(self._connection_window_increment)
        self._h2.update_settings({
            h2.settings.SettingCodes.INITIAL_WINDOW_SIZE: self._initial_window_size,
            h2.settings.SettingCodes.ENABLE_PUSH: 0,
        })
        await self._flush()

        self._connected = True
        self._conn_generation += 1
        gen = self._conn_generation
        self._read_task = asyncio.create_task(self._reader_loop(gen))
        log.info(
            "H2 connected → %s (SNI=%s, ALPN=h2, TCP_NODELAY=on)",
            self._connect_host, sni,
        )

    async def reconnect(self) -> None:
        async with self._connect_lock:
            loop = asyncio.get_running_loop()
            elapsed = loop.time() - self._last_reconnect_at
            if elapsed < self._RECONNECT_MIN_INTERVAL:
                await asyncio.sleep(self._RECONNECT_MIN_INTERVAL - elapsed)
            self._last_reconnect_at = loop.time()
            await self._close_internal()
            await self._do_connect()

    async def _close_internal(self) -> None:
        self._connected = False
        read_task = self._read_task
        self._read_task = None
        if read_task:
            read_task.cancel()
            await asyncio.gather(read_task, return_exceptions=True)
        if self._writer is not None:
            try:
                writer = self._writer
                self._writer = None
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self._reader = None
        # Wake every pending stream so callers raise instead of hanging.
        for state in self._streams.values():
            if not state.done.is_set():
                state.error = "connection closed"
                state.done.set()
        self._streams.clear()

    async def close(self) -> None:
        if self._h2 is not None and self._connected:
            try:
                self._h2.close_connection()
                async with self._write_lock:
                    await self._flush()
            except Exception:
                pass
        await self._close_internal()

    # ── Public request API ─────────────────────────────────────────────
    async def request(
        self,
        method: str,
        path: str,
        host: str,
        *,
        headers: Optional[dict] = None,
        body: bytes | None = None,
        timeout: float = 25.0,
        follow_redirects: int = 5,
    ) -> tuple[int, dict[str, str], bytes]:
        """Issue a fronted H2 request. The ``host`` argument becomes the
        ``:authority`` pseudo-header (the real HTTP target — typically
        ``script.google.com``). Redirects open new streams on the same
        connection rather than re-handshaking TLS."""
        await self.ensure_connected()
        self.total_requests += 1

        cur_method = method
        cur_path = path
        cur_host = host
        cur_body = body
        cur_headers = headers

        for _ in range(follow_redirects + 1):
            status, resp_headers, resp_body = await self._single_request(
                cur_method, cur_path, cur_host, cur_headers, cur_body, timeout,
            )
            if status not in (301, 302, 303, 307, 308):
                return status, resp_headers, resp_body
            location = resp_headers.get("location", "")
            if not location:
                return status, resp_headers, resp_body
            redirect = urlparse(location)
            cur_path = (redirect.path or "/") + (
                f"?{redirect.query}" if redirect.query else ""
            )
            cur_host = redirect.netloc or cur_host
            if status not in (307, 308):
                cur_method = "GET"
                cur_body = None
            cur_headers = None
        return status, resp_headers, resp_body

    async def ping(self) -> None:
        if not self._connected or self._h2 is None:
            return
        try:
            async with self._write_lock:
                if not self._connected or self._h2 is None:
                    return
                self._h2.ping(b"\x00" * 8)
                await self._flush()
        except Exception as exc:
            log.debug("H2 ping failed: %s", exc)

    # ── Stream send/receive ────────────────────────────────────────────
    async def _single_request(
        self,
        method: str,
        path: str,
        host: str,
        headers: Optional[dict],
        body: bytes | None,
        timeout: float,
    ) -> tuple[int, dict[str, str], bytes]:
        if not self._connected:
            await self.ensure_connected()
        assert self._h2 is not None

        async with self._write_lock:
            try:
                stream_id = self._h2.get_next_available_stream_id()
            except Exception:
                # Connection went stale between requests — reconnect once.
                await self.reconnect()
                assert self._h2 is not None
                stream_id = self._h2.get_next_available_stream_id()

            h2_headers: list[tuple[str, str]] = [
                (":method", method),
                (":path", path),
                (":authority", host),
                (":scheme", "https"),
            ]
            if headers:
                for k, v in headers.items():
                    h2_headers.append((k.lower(), str(v)))

            end_stream = body is None or len(body) == 0
            self._h2.send_headers(stream_id, h2_headers, end_stream=end_stream)
            if body:
                self._send_body(stream_id, body)

            state = _StreamState()
            self._streams[stream_id] = state
            self.total_streams += 1
            await self._flush()

        try:
            await asyncio.wait_for(state.done.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            self._streams.pop(stream_id, None)
            raise TimeoutError(f"H2 stream {stream_id} timed out after {timeout}s")
        finally:
            self._streams.pop(stream_id, None)

        if state.error:
            raise ConnectionError(f"H2 stream error: {state.error}")
        return state.status, dict(state.headers), bytes(state.data)

    def _send_body(self, stream_id: int, body: bytes) -> None:
        assert self._h2 is not None
        view = memoryview(body)
        sent = 0
        total = len(view)
        while view:
            max_frame = self._h2.local_settings.max_frame_size
            window = self._h2.local_flow_control_window(stream_id)
            n = min(len(view), max_frame, window)
            if n <= 0:
                raise BufferError(
                    f"H2 flow control exhausted after {sent}/{total} bytes"
                )
            end = n >= len(view)
            self._h2.send_data(stream_id, bytes(view[:n]), end_stream=end)
            view = view[n:]
            sent += n

    # ── Background reader ──────────────────────────────────────────────
    async def _reader_loop(self, generation: int) -> None:
        try:
            while self._connected and self._reader is not None:
                data = await self._reader.read(65536)
                if not data:
                    log.debug("H2 remote closed connection")
                    break
                try:
                    events = self._h2.receive_data(data)  # type: ignore[union-attr]
                except Exception as exc:
                    log.warning("H2 protocol error: %s", exc)
                    break
                for event in events:
                    self._dispatch(event)
                async with self._write_lock:
                    await self._flush()
        except asyncio.CancelledError:
            return
        except ssl.SSLError as exc:
            # CDNs occasionally send data after close_notify. Common, harmless.
            if "APPLICATION_DATA_AFTER_CLOSE_NOTIFY" in str(exc):
                log.debug("H2 close_notify race: %s", exc)
            else:
                log.warning("H2 reader SSL error: %s", exc)
        except Exception as exc:
            log.warning("H2 reader error: %s", exc)
        finally:
            if generation == self._conn_generation:
                self._connected = False
                for state in self._streams.values():
                    if not state.done.is_set():
                        state.error = "connection lost"
                        state.done.set()

    def _dispatch(self, event) -> None:
        if isinstance(event, h2.events.ResponseReceived):
            state = self._streams.get(event.stream_id)
            if state is not None:
                for name, value in event.headers:
                    n = name if isinstance(name, str) else name.decode()
                    v = value if isinstance(value, str) else value.decode()
                    if n == ":status":
                        try:
                            state.status = int(v)
                        except ValueError:
                            pass
                    else:
                        state.headers[n] = v
        elif isinstance(event, h2.events.DataReceived):
            state = self._streams.get(event.stream_id)
            if state is not None:
                state.data.extend(event.data)
            assert self._h2 is not None
            self._h2.acknowledge_received_data(
                event.flow_controlled_length, event.stream_id,
            )
        elif isinstance(event, h2.events.StreamEnded):
            state = self._streams.get(event.stream_id)
            if state is not None:
                state.done.set()
        elif isinstance(event, h2.events.StreamReset):
            state = self._streams.get(event.stream_id)
            if state is not None:
                state.error = f"stream reset (code={event.error_code})"
                state.done.set()
        # WindowUpdated, SettingsAcknowledged, PingReceived, PingAckReceived,
        # ConnectionTerminated — h2 lib handles bookkeeping; nothing to do.

    async def _flush(self) -> None:
        if self._h2 is None or self._writer is None:
            return
        data = self._h2.data_to_send()
        if data:
            self._writer.write(data)
            await self._writer.drain()

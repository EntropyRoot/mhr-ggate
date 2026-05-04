"""Unit tests for v2ray/fronted_gas_transport.py.

These tests do *not* hit the network. They feed the transport a fake
asyncio reader/writer pair that replays a canned HTTP/1.1 response,
which is enough to exercise the request-building, redirect-following,
and response-parsing logic. The TLS/SNI handshake itself is exercised
by `_open()` and is left to integration tests against real Google IPs.
"""
from __future__ import annotations

import asyncio
import io
from typing import Optional

import pytest

from fronted_gas_transport import (  # type: ignore
    DEFAULT_SNI_POOL,
    FrontedGASConfig,
    FrontedGASTransport,
    TransportResponse,
    build_transport,
)


# ──────────────────────────────────────────────────────────────────────
# Fakes — a minimal stand-in for asyncio.StreamReader / StreamWriter
# ──────────────────────────────────────────────────────────────────────
class FakeReader:
    """asyncio-ish reader backed by a bytes buffer (or a queue of buffers)."""

    def __init__(self, payloads: list[bytes]):
        self._payloads = list(payloads)
        self._buf = io.BytesIO(self._payloads.pop(0) if self._payloads else b"")

    async def read(self, n: int) -> bytes:
        data = self._buf.read(n)
        if data:
            return data
        if self._payloads:
            self._buf = io.BytesIO(self._payloads.pop(0))
            return self._buf.read(n)
        return b""

    def at_eof(self) -> bool:
        # If the cursor is at the end and no more queued payloads, we're done.
        pos = self._buf.tell()
        end = self._buf.seek(0, io.SEEK_END)
        self._buf.seek(pos)
        return pos == end and not self._payloads


class FakeWriter:
    def __init__(self) -> None:
        self.written = bytearray()
        self.closed = False

    def write(self, data: bytes) -> None:
        self.written.extend(data)

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self.closed = True


# ──────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────
def _http_response(status: int, body: bytes, *, location: Optional[str] = None,
                   extra_headers: Optional[dict] = None) -> bytes:
    reason = {200: "OK", 302: "Found", 301: "Moved", 502: "Bad Gateway"}.get(
        status, "OK"
    )
    headers = [f"HTTP/1.1 {status} {reason}"]
    if location:
        headers.append(f"Location: {location}")
    headers.append(f"Content-Length: {len(body)}")
    headers.append("Content-Type: text/plain; charset=ascii")
    if extra_headers:
        for k, v in extra_headers.items():
            headers.append(f"{k}: {v}")
    return ("\r\n".join(headers) + "\r\n\r\n").encode() + body


def _install_stub_pool(transport: FrontedGASTransport, reader, writer) -> None:
    """Make `_acquire` hand back the canned reader/writer instead of
    really opening a TLS connection."""

    async def fake_acquire(_fallback_host: str):
        return reader, writer, asyncio.get_running_loop().time()

    async def fake_release(_r, _w, _c):
        pass

    transport._acquire = fake_acquire  # type: ignore[assignment]
    transport._release = fake_release  # type: ignore[assignment]


# ──────────────────────────────────────────────────────────────────────
# SNI rotation
# ──────────────────────────────────────────────────────────────────────
def test_default_sni_pool_is_google_owned():
    cfg = FrontedGASConfig()
    t = FrontedGASTransport(cfg)
    # Round-robin should hit each pool entry exactly once.
    seen = [t._next_sni() for _ in range(len(DEFAULT_SNI_POOL))]
    assert set(seen) == set(DEFAULT_SNI_POOL)


def test_custom_sni_pool_overrides_default_and_normalizes():
    cfg = FrontedGASConfig(sni_hosts=("Mail.Google.Com.", "  WWW.GOOGLE.COM "))
    t = FrontedGASTransport(cfg)
    assert t._next_sni() == "mail.google.com"
    assert t._next_sni() == "www.google.com"
    # rotation wraps
    assert t._next_sni() == "mail.google.com"


def test_empty_sni_pool_falls_back_to_default():
    cfg = FrontedGASConfig(sni_hosts=())
    t = FrontedGASTransport(cfg)
    assert t._next_sni() in DEFAULT_SNI_POOL


# ──────────────────────────────────────────────────────────────────────
# Request building — the *fronting* invariant
# ──────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_request_uses_fronted_http_host_not_url_host():
    """Even though gas_url's hostname is script.google.com, the HTTP
    Host header must come from cfg.http_host (the fronted target)."""
    cfg = FrontedGASConfig(http_host="script.google.com")
    t = FrontedGASTransport(cfg)

    reader = FakeReader([_http_response(200, b"aGVsbG8=")])  # b64("hello")
    writer = FakeWriter()
    _install_stub_pool(t, reader, writer)

    resp = await t.post(
        "https://script.google.com/macros/s/SID/exec",
        params={"path": "/mhr/abc/1"},
        headers={"X-MHR-Secret": "shh", "X-MHR-Method": "POST",
                 "Content-Type": "text/plain; charset=ascii"},
        content="aGVsbG8=",
    )
    assert isinstance(resp, TransportResponse)
    assert resp.status_code == 200
    assert resp.content == b"aGVsbG8="

    sent = writer.written.decode("latin-1")
    # Request line carries the *path* of the gas_url plus our params:
    assert sent.startswith("POST /macros/s/SID/exec?path=%2Fmhr%2Fabc%2F1 HTTP/1.1\r\n")
    # Host is the *fronted* HTTP host:
    assert "\r\nHost: script.google.com\r\n" in sent
    # Custom headers preserved:
    assert "\r\nX-MHR-Secret: shh\r\n" in sent
    assert "\r\nX-MHR-Method: POST\r\n" in sent
    # Body is the bytes we passed:
    assert sent.endswith("\r\n\r\naGVsbG8=")


@pytest.mark.asyncio
async def test_request_rejects_http_scheme():
    t = FrontedGASTransport(FrontedGASConfig())
    with pytest.raises(ValueError):
        await t.get("http://script.google.com/x")


# ──────────────────────────────────────────────────────────────────────
# Redirect follow on the same socket (Apps Script /exec → /macros/echo)
# ──────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_follows_302_redirect_on_same_connection():
    cfg = FrontedGASConfig()
    t = FrontedGASTransport(cfg)

    final_body = b"d29ya2luZw=="  # b64("working")
    reader = FakeReader([
        _http_response(302, b"",
                       location="https://script.googleusercontent.com/macros/echo?u=1"),
        _http_response(200, final_body),
    ])
    writer = FakeWriter()
    _install_stub_pool(t, reader, writer)

    resp = await t.get(
        "https://script.google.com/macros/s/SID/exec",
        headers={"X-MHR-Secret": "shh"},
    )
    assert resp.status_code == 200
    assert resp.content == final_body

    sent = writer.written.decode("latin-1")
    # Two requests on the same socket.
    assert sent.count("HTTP/1.1\r\n") == 2
    # Second request swapped Host to the redirect target.
    assert "Host: script.googleusercontent.com" in sent
    # 302 demotes POST→GET, but here the original was GET so it stays GET.
    assert "GET /macros/echo?u=1 HTTP/1.1" in sent


# ──────────────────────────────────────────────────────────────────────
# Chunked response body
# ──────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_chunked_response_is_decoded():
    cfg = FrontedGASConfig()
    t = FrontedGASTransport(cfg)

    chunked = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\nhello\r\n"
        b"6\r\n world\r\n"
        b"0\r\n\r\n"
    )
    reader = FakeReader([chunked])
    writer = FakeWriter()
    _install_stub_pool(t, reader, writer)

    resp = await t.get("https://script.google.com/macros/s/SID/exec")
    assert resp.status_code == 200
    assert resp.content == b"hello world"


@pytest.mark.asyncio
async def test_chunked_response_with_extensions_and_trailers():
    """RFC 7230: chunk-size MAY carry chunk-ext (";name=value"), and the
    final 0-chunk MAY be followed by trailer headers. Both must be
    consumed so the connection pool can safely reuse this socket."""
    cfg = FrontedGASConfig()
    t = FrontedGASTransport(cfg)

    chunked = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5;ext=ignored\r\nhello\r\n"
        b"6\r\n world\r\n"
        b"0\r\n"
        b"X-Trailer: yes\r\n"
        b"\r\n"
    )
    reader = FakeReader([chunked])
    writer = FakeWriter()
    _install_stub_pool(t, reader, writer)

    resp = await t.get("https://script.google.com/macros/s/SID/exec")
    assert resp.status_code == 200
    assert resp.content == b"hello world"
    # Trailer must have been drained — no leftover bytes for the next
    # response on this connection.
    assert reader.at_eof()


@pytest.mark.asyncio
async def test_chunked_response_rejects_bad_chunk_size():
    cfg = FrontedGASConfig()
    t = FrontedGASTransport(cfg)

    chunked = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"NotHex\r\nhello\r\n"
    )
    reader = FakeReader([chunked])
    writer = FakeWriter()
    _install_stub_pool(t, reader, writer)

    with pytest.raises(RuntimeError, match="bad chunk size"):
        await t.get("https://script.google.com/macros/s/SID/exec")


@pytest.mark.asyncio
async def test_chunked_response_rejects_premature_eof():
    """Connection closes mid-chunk → must raise, not return partial.
    Partial body in a tunnel transport == VMess desync."""
    cfg = FrontedGASConfig()
    t = FrontedGASTransport(cfg)

    truncated = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"a\r\nhel"          # promised 10 bytes, delivered 3
    )
    reader = FakeReader([truncated])
    writer = FakeWriter()
    _install_stub_pool(t, reader, writer)

    with pytest.raises(RuntimeError, match="EOF"):
        await t.get("https://script.google.com/macros/s/SID/exec")


@pytest.mark.asyncio
async def test_chunked_response_rejects_missing_trailing_crlf():
    """Each chunk-data MUST be followed by CRLF — anything else means
    we're out of sync with the stream and the next read would be junk."""
    cfg = FrontedGASConfig()
    t = FrontedGASTransport(cfg)

    bad = (
        b"HTTP/1.1 200 OK\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\nhelloXX"      # XX where CRLF should be
        b"0\r\n\r\n"
    )
    reader = FakeReader([bad])
    writer = FakeWriter()
    _install_stub_pool(t, reader, writer)

    with pytest.raises(RuntimeError, match="missing CRLF"):
        await t.get("https://script.google.com/macros/s/SID/exec")


# ──────────────────────────────────────────────────────────────────────
# Factory
# ──────────────────────────────────────────────────────────────────────
def test_build_transport_fronted_returns_fronted_instance():
    t = build_transport(mode="fronted", fronted=FrontedGASConfig())
    assert isinstance(t, FrontedGASTransport)


def test_build_transport_direct_requires_client():
    with pytest.raises(ValueError):
        build_transport(mode="direct")

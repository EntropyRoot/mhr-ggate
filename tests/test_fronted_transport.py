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
    """Force the H1 path against a canned reader/writer.

    Patches the H1 acquire/release helpers so we never open a real TLS
    connection, and disables H2 + background tasks so the dispatcher
    takes the H1 path deterministically. Also flips ``_bg_started`` so
    pool maintenance / keepalive never spawn during a unit test."""

    async def fake_acquire(_fallback_host: str):
        return reader, writer, asyncio.get_running_loop().time()

    async def fake_release(_r, _w, _c):
        pass

    transport._acquire_h1 = fake_acquire  # type: ignore[assignment]
    transport._release_h1 = fake_release  # type: ignore[assignment]
    # Force H1: pretend H2 is permanently disabled.
    transport.cfg.enable_h2 = False
    transport._bg_started = True  # skip background-task spawn


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


# ──────────────────────────────────────────────────────────────────────
# Multi-Script-ID rotation + URL rewriting
# ──────────────────────────────────────────────────────────────────────
def test_script_id_round_robin():
    cfg = FrontedGASConfig(script_ids=("SID_A", "SID_B", "SID_C"))
    t = FrontedGASTransport(cfg)
    seq = [t._next_script_id() for _ in range(6)]
    assert seq == ["SID_A", "SID_B", "SID_C", "SID_A", "SID_B", "SID_C"]


def test_script_id_blacklist_skips_until_ttl():
    import time as _time
    cfg = FrontedGASConfig(script_ids=("SID_A", "SID_B"),
                           script_blacklist_ttl=0.05)
    t = FrontedGASTransport(cfg)
    # Blacklist A; next picks should skip it until the TTL expires.
    t._blacklist_sid("SID_A", reason="test")
    picked = [t._next_script_id() for _ in range(4)]
    assert "SID_A" not in picked
    assert all(p == "SID_B" for p in picked)
    _time.sleep(0.06)
    # After TTL, A is back in the rotation.
    seen = set(t._next_script_id() for _ in range(6))
    assert "SID_A" in seen


def test_script_id_blacklist_noop_for_single_sid():
    """A single-SID config must never blacklist its only ID — that
    would deadlock the relay."""
    cfg = FrontedGASConfig(script_ids=("SID_ONLY",))
    t = FrontedGASTransport(cfg)
    t._blacklist_sid("SID_ONLY", reason="should be ignored")
    assert t._next_script_id() == "SID_ONLY"


def test_url_rewrite_swaps_sid_segment():
    cfg = FrontedGASConfig(script_ids=("SID_A", "SID_B"))
    t = FrontedGASTransport(cfg)
    base = "/macros/s/OLD/exec?path=%2Fmhr%2Fa"
    rewritten = t._rewrite_path(base, "SID_A")
    assert rewritten == "/macros/s/SID_A/exec?path=%2Fmhr%2Fa"


def test_url_rewrite_promotes_exec_to_dev_when_available():
    cfg = FrontedGASConfig(script_ids=("SID_A",))
    t = FrontedGASTransport(cfg)
    t._dev_available = True
    rewritten = t._rewrite_path("/macros/s/SID_A/exec?path=%2Fmhr", "SID_A")
    assert rewritten == "/macros/s/SID_A/dev?path=%2Fmhr"


def test_url_rewrite_leaves_non_apps_script_paths_alone():
    cfg = FrontedGASConfig()
    t = FrontedGASTransport(cfg)
    assert t._rewrite_path("/some/other/path", "SID_A") == "/some/other/path"


@pytest.mark.asyncio
async def test_dispatch_uses_rotated_sid_in_request_line():
    """Across two POSTs, the request line should swap SIDs."""
    cfg = FrontedGASConfig(script_ids=("SID_A", "SID_B"))
    t = FrontedGASTransport(cfg)

    # Two canned 200s back-to-back so two POSTs land successfully.
    reader = FakeReader([
        _http_response(200, b"YQ=="),
        _http_response(200, b"Yg=="),
    ])
    writer = FakeWriter()
    _install_stub_pool(t, reader, writer)

    await t.post("https://script.google.com/macros/s/IGN/exec",
                 params={"path": "/mhr/1"}, content="YQ==")
    await t.post("https://script.google.com/macros/s/IGN/exec",
                 params={"path": "/mhr/2"}, content="Yg==")

    sent = writer.written.decode("latin-1")
    # First request used SID_A, second used SID_B (round-robin).
    assert "POST /macros/s/SID_A/exec?path=%2Fmhr%2F1" in sent
    assert "POST /macros/s/SID_B/exec?path=%2Fmhr%2F2" in sent
    # The original SID from the URL ("IGN") must NOT appear.
    assert "/macros/s/IGN/" not in sent


# ──────────────────────────────────────────────────────────────────────
# Fan-out
# ──────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_fanout_winner_takes_all():
    """When two racers run, the first to succeed wins; the slow one
    must be cancelled and never observed by the caller."""
    cfg = FrontedGASConfig(
        script_ids=("FAST", "SLOW"),
        parallel_relay=2,
    )
    t = FrontedGASTransport(cfg)
    t.cfg.enable_h2 = False
    t._bg_started = True

    sent_per_sid: dict[str, int] = {}

    async def fake_send_h1(method, parsed, params, headers, body, sid, fallback_host):
        sent_per_sid[sid] = sent_per_sid.get(sid, 0) + 1
        if sid == "SLOW":
            await asyncio.sleep(0.5)  # loses the race
        return TransportResponse(status_code=200, content=b"OK", headers={})

    t._send_h1 = fake_send_h1  # type: ignore[assignment]

    resp = await t.post("https://script.google.com/macros/s/X/exec",
                        params={"path": "/mhr/x"}, content="aGk=")
    assert resp.status_code == 200
    assert resp.content == b"OK"
    # FAST returned, SLOW was racing too.
    assert sent_per_sid.get("FAST") == 1
    assert t.stats.fanout_wins == 1


# ──────────────────────────────────────────────────────────────────────
# H2 wiring (no real network — just verify the dispatcher prefers H2)
# ──────────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_dispatch_prefers_h2_when_available():
    cfg = FrontedGASConfig(script_ids=("SID_A",), enable_h2=True)
    t = FrontedGASTransport(cfg)
    t._bg_started = True

    # Pretend H2 is up by patching _ensure_h2 + _send_h2.
    h2_calls: list[dict] = []

    async def fake_ensure_h2(_):
        return True

    async def fake_send_h2(method, parsed, params, headers, body, sid):
        h2_calls.append({"sid": sid, "method": method,
                         "path": t._build_path(parsed, params, sid)})
        t.stats.h2_requests += 1
        return TransportResponse(status_code=200, content=b"OK", headers={})

    t._ensure_h2 = fake_ensure_h2     # type: ignore[assignment]
    t._send_h2 = fake_send_h2          # type: ignore[assignment]

    resp = await t.post("https://script.google.com/macros/s/IGN/exec",
                        params={"path": "/mhr/1"}, content="YQ==")
    assert resp.status_code == 200
    assert t.stats.h2_requests == 1
    assert h2_calls and h2_calls[0]["sid"] == "SID_A"
    assert "/macros/s/SID_A/exec?path=%2Fmhr%2F1" == h2_calls[0]["path"]


@pytest.mark.asyncio
async def test_dispatch_falls_back_to_h1_when_h2_send_fails():
    cfg = FrontedGASConfig(script_ids=("SID_A", "SID_B"), enable_h2=True)
    t = FrontedGASTransport(cfg)
    t._bg_started = True

    async def fake_ensure_h2(_):
        return True

    async def fake_send_h2_failing(*_args, **_kw):
        raise ConnectionError("simulated H2 failure")

    h1_payloads: list[str] = []

    async def fake_send_h1(method, parsed, params, headers, body, sid, fallback_host):
        h1_payloads.append(t._build_path(parsed, params, sid))
        return TransportResponse(status_code=200, content=b"OK", headers={})

    t._ensure_h2 = fake_ensure_h2          # type: ignore[assignment]
    t._send_h2 = fake_send_h2_failing      # type: ignore[assignment]
    t._send_h1 = fake_send_h1               # type: ignore[assignment]

    resp = await t.post("https://script.google.com/macros/s/IGN/exec",
                        params={"path": "/mhr/1"}, content="aGk=")
    assert resp.status_code == 200
    # H1 ran with the *next* SID after H2's SID was blacklisted.
    assert h1_payloads, "H1 fallback never executed"
    # Failed SID should be on the blacklist.
    assert t.stats.h2_failures >= 1


# ──────────────────────────────────────────────────────────────────────
# H2 lib detection (gracefully off when h2 isn't installed)
# ──────────────────────────────────────────────────────────────────────
def test_h2_disabled_when_lib_missing(monkeypatch):
    """If h2 isn't importable, _ensure_h2 must short-circuit to False
    instead of crashing — the H1 pool then carries traffic alone."""
    import fronted_gas_transport as F
    monkeypatch.setattr(F, "H2_AVAILABLE", False)
    cfg = FrontedGASConfig(enable_h2=True)
    t = F.FrontedGASTransport(cfg)
    assert t._h2_usable() is False

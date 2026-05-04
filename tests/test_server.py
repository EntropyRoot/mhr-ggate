"""End-to-end tests for server/server.py against a fake xray backend."""
from __future__ import annotations

import base64

import httpx
from fastapi.testclient import TestClient

from server import Config, make_app  # type: ignore


# ──────────────────────────────────────────────────────────
def _client(handler):
    cfg = Config(secret="test-secret-xyz-1234", xray_port=9999)

    def factory():
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    app = make_app(cfg, http_factory=factory)
    return TestClient(app)


def test_rejects_missing_secret():
    def handler(req): return httpx.Response(200, content=b"")
    with _client(handler) as c:
        r = c.post("/mhr/abc/0", content="")
        assert r.status_code == 403


def test_rejects_wrong_secret():
    def handler(req): return httpx.Response(200, content=b"")
    with _client(handler) as c:
        r = c.post("/mhr/abc/0", content="", headers={"X-MHR-Secret": "wrong"})
        assert r.status_code == 403


def test_post_decodes_base64_and_forwards_to_xray():
    captured = {}

    def handler(req: httpx.Request):
        captured["url"]    = str(req.url)
        captured["body"]   = req.content
        captured["method"] = req.method
        return httpx.Response(200, content=b"\x00\x01\x02RESP")

    payload = b"\x9d\x82\x01\x02\x03binary-vmess-bytes"
    encoded = base64.b64encode(payload).decode()

    with _client(handler) as c:
        r = c.post(
            "/mhr/sess/0",
            content=encoded,
            headers={
                "X-MHR-Secret": "test-secret-xyz-1234",
                "Content-Type": "text/plain; charset=ascii",
            },
        )
    assert r.status_code == 200
    assert base64.b64decode(r.text) == b"\x00\x01\x02RESP"
    assert captured["url"].endswith("/mhr/sess/0")
    assert captured["method"] == "POST"
    assert captured["body"] == payload


def test_get_forwards_path_and_returns_b64_response():
    seen = {}

    def handler(req: httpx.Request):
        seen["url"] = str(req.url)
        return httpx.Response(200, content=b"download-chunk-bytes\xff")

    with _client(handler) as c:
        r = c.get("/mhr/sess", headers={"X-MHR-Secret": "test-secret-xyz-1234"})
    assert r.status_code == 200
    assert base64.b64decode(r.text) == b"download-chunk-bytes\xff"
    assert seen["url"].endswith("/mhr/sess")


def test_oversized_post_is_rejected():
    def handler(req): raise AssertionError("xray must not be hit")

    cfg = Config(secret="test-secret-xyz-1234")
    app = make_app(cfg, http_factory=lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(handler)
    ))
    with TestClient(app) as c:
        huge = "A" * (cfg.max_body_bytes * 4)  # well over the cap
        r = c.post(
            "/mhr/x/0",
            content=huge,
            headers={"X-MHR-Secret": "test-secret-xyz-1234"},
        )
        assert r.status_code in (400, 413)


def test_health_endpoint_does_not_require_secret():
    cfg = Config(secret="test-secret-xyz-1234")
    app = make_app(cfg)
    with TestClient(app) as c:
        r = c.get("/_mhr/health")
        assert r.status_code == 200
        assert r.json() == {"ok": True}


def test_stats_endpoint_requires_secret():
    cfg = Config(secret="test-secret-xyz-1234")
    app = make_app(cfg)
    with TestClient(app) as c:
        r = c.get("/_mhr/stats")
        assert r.status_code == 403
        r = c.get("/_mhr/stats", headers={"X-MHR-Secret": "test-secret-xyz-1234"})
        assert r.status_code == 200
        assert "uptime_sec" in r.json()


def test_xray_unreachable_returns_502():
    def handler(req): raise httpx.ConnectError("xray down")

    with _client(handler) as c:
        r = c.post(
            "/mhr/x/0",
            content=base64.b64encode(b"hello").decode(),
            headers={"X-MHR-Secret": "test-secret-xyz-1234"},
        )
        assert r.status_code == 502

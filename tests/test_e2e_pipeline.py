"""End-to-end pipeline test.

Stitches:

    xray client -> client_relay -> (fake GAS) -> server.py -> (fake xray)

Both relay and server are real FastAPI apps; the fake GAS is just an
httpx.MockTransport that bridges the relay's outbound calls into the
server's TestClient. xray on the VPS side is replaced with another
MockTransport.

This is the test that actually proves the protocol design:
binary bytes survive base64 -> GAS -> base64 -> xray and back.
"""
from __future__ import annotations

import base64

import httpx
from fastapi.testclient import TestClient

from client_relay import Config as RelayCfg, make_app as make_relay_app  # type: ignore
from server import Config as SrvCfg, make_app as make_server_app          # type: ignore


SECRET = "shared-secret-abc-12345"


def _build_pipeline(xray_handler):
    # 1) VPS-side server, with xray upstream replaced
    srv_cfg = SrvCfg(secret=SECRET, xray_port=9999)
    srv_app = make_server_app(
        srv_cfg,
        http_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(xray_handler)
        ),
    )
    server_client = TestClient(srv_app)
    server_client.__enter__()  # eager lifespan startup

    # 2) fake GAS bridges relay -> server
    def fake_gas(req: httpx.Request) -> httpx.Response:
        forward_path = dict(req.url.params).get("path", "/")
        method = req.method.upper()
        headers = {k: v for k, v in req.headers.items()
                   if k.lower() not in ("host", "content-length")}
        if method == "POST":
            srv_resp = server_client.post(
                forward_path, content=req.content, headers=headers
            )
        else:
            srv_resp = server_client.get(forward_path, headers=headers)
        return httpx.Response(srv_resp.status_code, text=srv_resp.text)

    # 3) client-side relay, with outbound httpx pointed at fake_gas
    relay_cfg = RelayCfg(
        gas_url="https://script.google.com/macros/s/abc/exec",
        secret=SECRET,
    )
    relay_app = make_relay_app(
        relay_cfg,
        http_factory=lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(fake_gas)
        ),
    )
    relay_client = TestClient(relay_app)
    return relay_client, server_client, relay_cfg


def test_e2e_post_round_trip_preserves_binary_bytes():
    received = {}

    def fake_xray(req: httpx.Request) -> httpx.Response:
        received["path"]   = req.url.path
        received["body"]   = req.content
        received["method"] = req.method
        return httpx.Response(200, content=b"\x00\xff\xfeRESP\x9d")

    relay_client, server_client, _ = _build_pipeline(fake_xray)
    payload = bytes(range(256))  # all byte values 0x00..0xff

    try:
        with relay_client as rc:
            r = rc.post("/mhr/abc/0", content=payload)
    finally:
        server_client.__exit__(None, None, None)

    assert r.status_code == 200
    assert r.content == b"\x00\xff\xfeRESP\x9d"
    assert received["body"] == payload
    assert received["path"] == "/mhr/abc/0"
    assert received["method"] == "POST"


def test_e2e_get_round_trip():
    def fake_xray(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/mhr/abc"
        return httpx.Response(200, content=b"\x01\x02\x03DOWNLOAD")

    relay_client, server_client, _ = _build_pipeline(fake_xray)
    try:
        with relay_client as rc:
            r = rc.get("/mhr/abc")
    finally:
        server_client.__exit__(None, None, None)

    assert r.status_code == 200
    assert r.content == b"\x01\x02\x03DOWNLOAD"


def test_e2e_wrong_secret_is_rejected_at_vps():
    def fake_xray(req): raise AssertionError("xray must not be hit on auth failure")

    relay_client, server_client, relay_cfg = _build_pipeline(fake_xray)
    relay_cfg.secret = "wrong-secret"

    try:
        with relay_client as rc:
            r = rc.post("/mhr/x/0", content=b"hello")
    finally:
        server_client.__exit__(None, None, None)

    # server returned 403; relay surfaces non-5xx codes through
    assert r.status_code == 403


def test_e2e_large_payload_survives_round_trip():
    """1 MB payload survives base64 round-trip end to end."""
    big = (b"\x00\x01\x02\x03\xfe\xff" * 200_000)[:1_000_000]

    def fake_xray(req): return httpx.Response(200, content=req.content[::-1])

    relay_client, server_client, _ = _build_pipeline(fake_xray)
    try:
        with relay_client as rc:
            r = rc.post("/mhr/x/9", content=big)
    finally:
        server_client.__exit__(None, None, None)

    assert r.status_code == 200
    assert r.content == big[::-1]


def test_e2e_xray_502_propagates():
    def fake_xray(req): raise httpx.ConnectError("xray down")

    relay_client, server_client, _ = _build_pipeline(fake_xray)
    try:
        with relay_client as rc:
            r = rc.post("/mhr/x/0", content=b"hello")
    finally:
        server_client.__exit__(None, None, None)

    # server.py emits 502 -> relay treats as 5xx -> retries -> 502
    assert r.status_code == 502

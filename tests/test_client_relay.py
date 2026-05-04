"""Unit tests for v2ray/client_relay.py."""
from __future__ import annotations

import argparse
import base64
import textwrap
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from client_relay import (  # type: ignore
    Config,
    _decode_b64_lenient,
    _parse_listen,
    load_config,
    make_app,
    validate_config,
)


# ──────────────────────────────────────────────────────────
# config plumbing
def test_parse_listen_with_host_and_port():
    assert _parse_listen("0.0.0.0:9001") == ("0.0.0.0", 9001)


def test_parse_listen_port_only():
    assert _parse_listen("9001") == ("127.0.0.1", 9001)


def test_validate_rejects_placeholder_gas_url():
    cfg = Config(
        gas_url="https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec",
        secret="abcd1234efgh",
    )
    err = validate_config(cfg)
    assert err and "GAS" in err.upper()


def test_validate_rejects_default_secret():
    cfg = Config(gas_url="https://example.com/exec", secret="CHANGE_THIS_SECRET_KEY")
    err = validate_config(cfg)
    assert err and "SECRET" in err.upper()


def test_validate_rejects_weird_scheme():
    cfg = Config(gas_url="ftp://example.com/exec", secret="abcd1234efgh")
    err = validate_config(cfg)
    assert err is not None


def test_validate_accepts_valid_config():
    cfg = Config(
        gas_url="https://script.google.com/macros/s/abc/exec",
        secret="abcd1234efgh",
    )
    assert validate_config(cfg) is None


def test_load_config_from_toml(tmp_path: Path):
    cfg_file = tmp_path / "relay.toml"
    cfg_file.write_text(textwrap.dedent("""
        gas_url     = "https://script.google.com/macros/s/abc/exec"
        secret      = "abcd1234efgh"
        listen_port = 9090
    """).strip(), encoding="utf-8")
    args = argparse.Namespace(
        config=str(cfg_file),
        gas_url=None, secret=None, listen=None, log_level=None,
    )
    cfg = load_config(args)
    assert cfg.gas_url.endswith("/exec")
    assert cfg.secret == "abcd1234efgh"
    assert cfg.listen_port == 9090


# ──────────────────────────────────────────────────────────
# decoder edge cases
def test_decode_b64_lenient_handles_empty():
    assert _decode_b64_lenient("") == b""


def test_decode_b64_lenient_handles_missing_padding():
    raw = b"hello"
    encoded = base64.b64encode(raw).decode().rstrip("=")
    assert _decode_b64_lenient(encoded) == raw


def test_decode_b64_lenient_handles_whitespace():
    raw = b"\x00\x01\x02hello world"
    encoded = "  " + base64.b64encode(raw).decode() + "\n"
    assert _decode_b64_lenient(encoded) == raw


def test_decode_b64_lenient_swallows_bad_input():
    assert _decode_b64_lenient("@@@@not-base64@@@@") == b""


# ──────────────────────────────────────────────────────────
# the round trip: xray -> client_relay -> (mock GAS) -> back
def _build_relay_with_mock_gas(gas_handler):
    cfg = Config(
        gas_url="https://script.google.com/macros/s/abc/exec",
        secret="abcd1234efgh",
        listen_port=8000,
    )

    def factory():
        return httpx.AsyncClient(transport=httpx.MockTransport(gas_handler))

    app = make_app(cfg, http_factory=factory)
    return TestClient(app), cfg


def test_post_round_trip_through_mocked_gas():
    """xray would POST raw bytes to /mhr/sess/0; the relay must
    base64-encode them, send to GAS, decode the b64 response, return raw."""
    captured = {}

    def gas(req: httpx.Request):
        captured["url"]    = str(req.url)
        captured["secret"] = req.headers.get("x-mhr-secret")
        captured["body"]   = req.content
        return httpx.Response(200, text=base64.b64encode(b"\x9d\x9eRESPONSE\xff").decode())

    client, cfg = _build_relay_with_mock_gas(gas)
    payload = b"\x00\x01\x02vmess-bytes-from-xray\xff"

    with client:
        r = client.post("/mhr/sess123/0", content=payload)

    assert r.status_code == 200
    # raw bytes returned to xray, NOT base64
    assert r.content == b"\x9d\x9eRESPONSE\xff"
    # secret was forwarded
    assert captured["secret"] == "abcd1234efgh"
    # path was forwarded as ?path=/mhr/sess123/0
    assert "path=" in captured["url"]
    assert "%2Fmhr%2Fsess123%2F0" in captured["url"] or "/mhr/sess123/0" in captured["url"]
    # body sent to GAS was base64 of the original
    assert base64.b64decode(captured["body"]) == payload


def test_get_round_trip_through_mocked_gas():
    def gas(req: httpx.Request):
        return httpx.Response(200, text=base64.b64encode(b"download-pkt").decode())

    client, _ = _build_relay_with_mock_gas(gas)
    with client:
        r = client.get("/mhr/sess")
    assert r.status_code == 200
    assert r.content == b"download-pkt"


def test_relay_translates_5xx_to_502():
    def gas(req: httpx.Request):
        return httpx.Response(503, text="upstream went away")

    client, _ = _build_relay_with_mock_gas(gas)
    with client:
        r = client.post("/mhr/x/0", content=b"hello")
    # after retries exhaust, surface 502
    assert r.status_code == 502


def test_relay_health_endpoint_works():
    cfg = Config(gas_url="https://example.com/exec", secret="abcd1234efgh")
    app = make_app(cfg)
    with TestClient(app) as client:
        r = client.get("/_mhr/health")
        assert r.status_code == 200
        assert r.json() == {"ok": True}

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
    UpstreamDecodeError,
    _decode_b64_lenient,
    _decode_b64_strict,
    _is_hostname,
    _is_ipv4,
    _parse_listen,
    load_config,
    make_app,
    validate_config,
)
import pytest


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


# ──────────────────────────────────────────────────────────
# strict decoder
def test_decode_strict_accepts_valid_base64():
    raw = b"\x00\x01\x02hello"
    assert _decode_b64_strict(base64.b64encode(raw).decode()) == raw


def test_decode_strict_returns_empty_for_blank_body():
    # Empty/whitespace-only body is legitimate (server had nothing to send back).
    assert _decode_b64_strict("") == b""
    assert _decode_b64_strict("   \n\r ") == b""


def test_decode_strict_raises_on_corrupt_base64():
    with pytest.raises(UpstreamDecodeError):
        _decode_b64_strict("@@@@not-base64@@@@")


def test_decode_strict_raises_on_gas_error_envelope():
    envelope = '{"error":"timeout","code":502,"version":"2.0"}'
    with pytest.raises(UpstreamDecodeError) as excinfo:
        _decode_b64_strict(envelope)
    assert "GAS error envelope" in str(excinfo.value)


def test_decode_lenient_still_swallows_for_legacy_callers():
    # The lenient shim must keep returning b"" so no surprise breakage
    # in any caller that explicitly opted into permissive semantics.
    assert _decode_b64_lenient("@@@@not-base64@@@@") == b""


# ──────────────────────────────────────────────────────────
# fronted-mode validation
def test_validate_rejects_unknown_transport_mode():
    cfg = Config(gas_url="https://example.com/exec", secret="abcd1234efgh",
                 transport_mode="frontd")  # typo
    err = validate_config(cfg)
    assert err and "transport_mode" in err


def test_validate_rejects_fronted_with_http_url():
    cfg = Config(gas_url="http://example.com/exec", secret="abcd1234efgh",
                 transport_mode="fronted")
    err = validate_config(cfg)
    assert err and "https" in err.lower()


def test_validate_rejects_bad_connect_host():
    cfg = Config(
        gas_url="https://script.google.com/macros/s/abc/exec",
        secret="abcd1234efgh",
        transport_mode="fronted",
        front_connect_host="999.999.999.999",
    )
    err = validate_config(cfg)
    assert err and "front_connect_host" in err


def test_validate_rejects_bad_sni_hostname():
    cfg = Config(
        gas_url="https://script.google.com/macros/s/abc/exec",
        secret="abcd1234efgh",
        transport_mode="fronted",
        front_sni_hosts=["good.example.com", "not a host"],
    )
    err = validate_config(cfg)
    assert err and "front_sni_hosts" in err


def test_validate_rejects_empty_sni_entry():
    cfg = Config(
        gas_url="https://script.google.com/macros/s/abc/exec",
        secret="abcd1234efgh",
        transport_mode="fronted",
        front_sni_hosts=["good.example.com", ""],
    )
    err = validate_config(cfg)
    assert err and "empty" in err


def test_validate_rejects_bad_http_host():
    cfg = Config(
        gas_url="https://script.google.com/macros/s/abc/exec",
        secret="abcd1234efgh",
        transport_mode="fronted",
        front_http_host="",
    )
    err = validate_config(cfg)
    assert err and "front_http_host" in err


def test_validate_accepts_full_fronted_config():
    cfg = Config(
        gas_url="https://script.google.com/macros/s/abc/exec",
        secret="abcd1234efgh",
        transport_mode="fronted",
        front_connect_host="216.239.38.120",
        front_sni_hosts=["www.google.com", "mail.google.com"],
        front_http_host="script.google.com",
        front_verify_ssl=True,
    )
    assert validate_config(cfg) is None


def test_validate_accepts_dns_connect_host():
    """Empty connect_host means 'resolve via DNS' — also fine."""
    cfg = Config(
        gas_url="https://script.google.com/macros/s/abc/exec",
        secret="abcd1234efgh",
        transport_mode="fronted",
        front_connect_host="",
        front_sni_hosts=["www.google.com"],
    )
    assert validate_config(cfg) is None


def test_ipv4_helper_rejects_leading_zeros_and_out_of_range():
    assert _is_ipv4("216.239.38.120")
    assert not _is_ipv4("01.2.3.4")
    assert not _is_ipv4("256.0.0.1")
    assert not _is_ipv4("1.2.3")
    assert not _is_ipv4("1.2.3.4.5")


def test_hostname_helper_basic():
    assert _is_hostname("www.google.com")
    assert _is_hostname("a")
    assert not _is_hostname("")
    assert not _is_hostname("-bad.example.com")
    assert not _is_hostname("with space.example.com")


# ──────────────────────────────────────────────────────────
# 4xx pass-through (no decode attempt)
def test_relay_passes_through_4xx_with_non_base64_body():
    """When the upstream returns 4xx + a JSON error body (not base64),
    the relay must still surface the 4xx status to xray with an empty
    body — *not* retry it as a corrupt-base64 failure."""
    def gas(req: httpx.Request):
        return httpx.Response(403, text='{"detail":"forbidden"}')

    client, _ = _build_relay_with_mock_gas(gas)
    with client:
        r = client.post("/mhr/x/0", content=b"hello")
    assert r.status_code == 403
    assert r.content == b""


def test_relay_retries_corrupt_base64_on_2xx_then_502s():
    """A 200 with a non-base64 body is treated as upstream corruption:
    retry, then 502. xray must never see corrupt bytes — that desyncs
    the VMess inner protocol."""
    calls = {"n": 0}

    def gas(req: httpx.Request):
        calls["n"] += 1
        return httpx.Response(200, text="@@@not-base64@@@")

    client, _ = _build_relay_with_mock_gas(gas)
    with client:
        r = client.post("/mhr/x/0", content=b"hello")
    assert r.status_code == 502
    # default max_retries=2 → 3 total attempts
    assert calls["n"] == 3

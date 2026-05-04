"""Sanity tests for v2ray/generate_config.py."""
from __future__ import annotations

import base64
import json
import re

import pytest

from generate_config import (  # type: ignore
    build_client_config,
    build_relay_toml,
    build_vmess_link,
    is_uuid,
    parse_gas,
)


# ──────────────────────────────────────────────────────────
def test_uuid_validator_accepts_valid_uuids():
    assert is_uuid("11111111-2222-3333-4444-555555555555")
    assert is_uuid("aBcDeFaB-cDeF-aBcD-eFaB-cDeFaBcDeFaB")


def test_uuid_validator_rejects_garbage():
    assert not is_uuid("")
    assert not is_uuid("not-a-uuid")
    assert not is_uuid("11111111-2222-3333-4444")  # too short


def test_parse_gas_url_accepts_https():
    scheme, host, path = parse_gas("https://script.google.com/macros/s/abc/exec")
    assert scheme == "https"
    assert host == "script.google.com"
    assert path.endswith("/exec")


def test_parse_gas_url_rejects_bad_scheme():
    with pytest.raises(ValueError):
        parse_gas("ftp://example.com/x")


def test_parse_gas_url_rejects_missing_host():
    with pytest.raises(ValueError):
        parse_gas("https:///just-a-path")


# ──────────────────────────────────────────────────────────
def test_client_config_targets_local_relay():
    cfg = build_client_config(
        vmess_uuid="11111111-2222-3333-4444-555555555555",
        path="/mhr",
        relay_port=8000,
        socks_port=1080,
        http_port=8118,
    )
    out = cfg["outbounds"][0]
    assert out["protocol"] == "vmess"
    vnext = out["settings"]["vnext"][0]
    # the entire point of this rewrite: xray talks to localhost, NOT script.google.com
    assert vnext["address"] == "127.0.0.1"
    assert vnext["port"] == 8000
    assert out["streamSettings"]["network"] == "xhttp"
    assert out["streamSettings"]["xhttpSettings"]["mode"] == "packet-up"
    assert out["streamSettings"]["xhttpSettings"]["path"] == "/mhr"


def test_client_config_inbound_ports_match():
    cfg = build_client_config(
        vmess_uuid="11111111-2222-3333-4444-555555555555",
        path="/mhr",
        relay_port=8000,
        socks_port=1080,
        http_port=8118,
    )
    socks = next(i for i in cfg["inbounds"] if i["tag"] == "socks-in")
    http  = next(i for i in cfg["inbounds"] if i["tag"] == "http-in")
    assert socks["port"] == 1080
    assert http["port"]  == 8118
    assert socks["settings"]["udp"] is True


def test_client_config_routes_private_ips_direct():
    cfg = build_client_config(
        vmess_uuid="11111111-2222-3333-4444-555555555555",
        path="/mhr", relay_port=8000, socks_port=1080, http_port=8118,
    )
    rules = cfg["routing"]["rules"]
    private = next(r for r in rules if r.get("ip") == ["geoip:private"])
    assert private["outboundTag"] == "direct"


# ──────────────────────────────────────────────────────────
def test_relay_toml_has_required_keys():
    toml_str = build_relay_toml(
        gas_url="https://script.google.com/macros/s/X/exec",
        secret="abc12345xyz",
        port=8000,
    )
    assert 'gas_url' in toml_str
    assert 'secret' in toml_str
    assert 'listen_port' in toml_str
    # quoted properly
    assert '"abc12345xyz"' in toml_str


def test_vmess_link_decodes_to_local_relay():
    link = build_vmess_link(
        vmess_uuid="11111111-2222-3333-4444-555555555555",
        path="/mhr",
        relay_port=8000,
    )
    assert link.startswith("vmess://")
    encoded = link[len("vmess://"):]
    pad = "=" * ((-len(encoded)) % 4)
    payload = json.loads(base64.urlsafe_b64decode(encoded + pad))
    assert payload["add"] == "127.0.0.1"
    assert payload["port"] == "8000"
    assert payload["net"] == "xhttp"
    assert payload["mode"] == "packet-up"

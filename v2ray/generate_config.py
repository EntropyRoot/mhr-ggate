#!/usr/bin/env python3
"""
mhr-ggate | Config Generator

Builds three artifacts in one shot:
  1. client_config.json     -> xray client config (talks to LOCAL relay)
  2. relay.toml             -> client_relay.py config (talks to GAS)
  3. mhr.vmess              -> single shareable vmess:// link

Usage:
  python3 generate_config.py \
      --gas-url https://script.google.com/macros/s/XXX/exec \
      --secret  YOUR_SHARED_SECRET \
      --uuid    YOUR_UUID

If you don't pass --uuid a fresh one will be generated.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import textwrap
import uuid
from pathlib import Path
from urllib.parse import urlparse

# ─── DEFAULTS ───────────────────────────────────────────────
DEFAULT_GAS_URL    = "https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec"
DEFAULT_PATH       = "/mhr"
DEFAULT_RELAY_PORT = 8000
DEFAULT_SOCKS_PORT = 1080
DEFAULT_HTTP_PORT  = 8118
# ──────────────────────────────────────────────────────────

UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def is_uuid(value: str) -> bool:
    return bool(value) and bool(UUID_RE.match(value))


def parse_gas(gas_url: str) -> tuple[str, str, str]:
    parsed = urlparse(gas_url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"gas_url must be http/https: {gas_url!r}")
    if not parsed.netloc:
        raise ValueError(f"gas_url is missing host: {gas_url!r}")
    return parsed.scheme, parsed.netloc, parsed.path or "/"


def build_client_config(*, vmess_uuid: str, path: str,
                        relay_port: int, socks_port: int, http_port: int) -> dict:
    """xray config that points at the LOCAL relay, not GAS directly."""
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "socks-in",
                "port": socks_port,
                "listen": "127.0.0.1",
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True, "ip": "127.0.0.1"},
                "sniffing": {"enabled": True, "destOverride": ["http", "tls", "quic"]}
            },
            {
                "tag": "http-in",
                "port": http_port,
                "listen": "127.0.0.1",
                "protocol": "http",
                "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
            }
        ],
        "outbounds": [
            {
                "tag": "mhr-ggate",
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",      # local relay
                        "port": relay_port,
                        "users": [{
                            "id": vmess_uuid,
                            "alterId": 0,
                            "security": "auto"
                        }]
                    }]
                },
                "streamSettings": {
                    "network": "xhttp",
                    "xhttpSettings": {
                        "path": path,
                        "mode": "packet-up",
                        "scMaxEachPostBytes": 1000000,
                        "scMaxConcurrentPosts": 100,
                        "scMinPostsIntervalMs": 30
                    }
                },
                "mux": {
                    "enabled": True,
                    "concurrency": 8,
                    "xudpConcurrency": 16,
                    "xudpProxyUDP443": "allow"
                }
            },
            {"tag": "direct", "protocol": "freedom", "settings": {}},
            {"tag": "block",  "protocol": "blackhole"}
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"},
                {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"},
                {"type": "field", "network": "tcp,udp", "outboundTag": "mhr-ggate"}
            ]
        }
    }


def build_relay_toml(
    *,
    gas_url: str,
    secret: str,
    port: int,
    transport_mode: str = "direct",
    front_connect_host: str = "",
    front_sni_hosts: list[str] | None = None,
    front_script_ids: list[str] | None = None,
    front_parallel_relay: int = 1,
    front_pool_max: int = 16,
    front_pool_min_idle: int = 4,
    front_enable_h2: bool = True,
    front_enable_keepalive: bool = True,
    front_enable_dev_probe: bool = True,
) -> str:
    front_sni_hosts = front_sni_hosts or []
    front_script_ids = front_script_ids or []
    sni_repr = "[" + ", ".join(f'"{h}"' for h in front_sni_hosts) + "]"
    sid_repr = "[" + ", ".join(f'"{s}"' for s in front_script_ids) + "]"

    def _bool(b: bool) -> str:
        return "true" if b else "false"

    # Fronted-mode lines are emitted as comments when the user did not
    # explicitly opt in, so the file reads as documentation for the
    # research path without changing default behavior.
    if transport_mode == "fronted":
        front_lines = (
            'transport_mode             = "fronted"\n'
            f'front_connect_host         = "{front_connect_host}"\n'
            f'front_sni_hosts            = {sni_repr}\n'
            'front_http_host            = "script.google.com"\n'
            'front_verify_ssl           = true\n'
            "\n"
            "# Multi-deployment / H2 / fan-out — see "
            "docs/research-fronted-transport.md for tuning notes.\n"
            f'front_script_ids           = {sid_repr}\n'
            f'front_enable_h2            = {_bool(front_enable_h2)}\n'
            f'front_enable_keepalive     = {_bool(front_enable_keepalive)}\n'
            f'front_enable_dev_probe     = {_bool(front_enable_dev_probe)}\n'
            'front_enable_pool_maintenance = true\n'
            f'front_parallel_relay       = {int(front_parallel_relay)}\n'
            f'front_pool_max             = {int(front_pool_max)}\n'
            f'front_pool_min_idle        = {int(front_pool_min_idle)}\n'
        )
    else:
        front_lines = (
            'transport_mode             = "direct"\n'
            '# ── research / fronted mode (uncomment to enable) ──────────\n'
            '# transport_mode             = "fronted"\n'
            '# front_connect_host         = ""               # Google edge IP, "" → DNS\n'
            '# front_sni_hosts            = ["www.google.com", "mail.google.com"]\n'
            '# front_http_host            = "script.google.com"\n'
            '# front_verify_ssl           = true\n'
            '# front_script_ids           = []               # extra deployment IDs for round-robin\n'
            '# front_enable_h2            = true             # HTTP/2 multiplexing (needs `pip install h2`)\n'
            '# front_enable_keepalive     = true             # 4-min PING to keep Apps Script container warm\n'
            '# front_enable_dev_probe     = true             # try /dev fast-path (saves ~400 ms)\n'
            '# front_enable_pool_maintenance = true          # background H1 pool refill / purge\n'
            '# front_parallel_relay       = 1                # >1 races N script IDs (needs N+ front_script_ids)\n'
            '# front_pool_max             = 16\n'
            '# front_pool_min_idle        = 4\n'
        )
    return (
        "# mhr-ggate client relay config\n"
        "# generated by generate_config.py\n"
        "\n"
        f'gas_url           = "{gas_url}"\n'
        f'secret            = "{secret}"\n'
        'listen_host       = "127.0.0.1"\n'
        f'listen_port       = {port}\n'
        'upstream_timeout  = 60.0\n'
        'max_retries       = 2\n'
        'retry_backoff     = 0.4\n'
        'log_level         = "INFO"\n'
        'metrics_enabled   = true\n'
        "\n"
        "# ── outbound transport (see docs/research-fronted-transport.md) ──\n"
        f"{front_lines}"
    )


def build_vmess_link(*, vmess_uuid: str, path: str, relay_port: int,
                     remark: str = "mhr-ggate") -> str:
    """vmess:// link that targets the LOCAL relay.

    This is for clients (v2rayN/Hiddify) that don't use our generated
    client_config.json — they will still go through 127.0.0.1:relay_port.
    """
    payload = {
        "v":    "2",
        "ps":   remark,
        "add":  "127.0.0.1",
        "port": str(relay_port),
        "id":   vmess_uuid,
        "aid":  "0",
        "scy":  "auto",
        "net":  "xhttp",
        "type": "none",
        "host": "",
        "path": path,
        "tls":  "",
        "sni":  "",
        "alpn": "",
        "fp":   "",
        "mode": "packet-up"
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()
    return f"vmess://{encoded}"


def write_files(out_dir: Path, *, client_cfg: dict, relay_toml: str,
                vmess_link: str) -> dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        "client_config": out_dir / "client_config.json",
        "relay_toml":    out_dir / "relay.toml",
        "vmess_link":    out_dir / "mhr.vmess",
    }
    paths["client_config"].write_text(json.dumps(client_cfg, indent=2), encoding="utf-8")
    paths["relay_toml"].write_text(relay_toml, encoding="utf-8")
    paths["vmess_link"].write_text(vmess_link + "\n", encoding="utf-8")
    return paths


def banner(args, vmess_uuid: str, written: dict[str, Path]) -> str:
    return textwrap.dedent(f"""
        ============================================================
          mhr-ggate | configs generated
        ============================================================

          UUID         : {vmess_uuid}
          GAS URL      : {args.gas_url}
          Path         : {args.path}
          Relay port   : 127.0.0.1:{args.relay_port}
          SOCKS5       : 127.0.0.1:{args.socks_port}
          HTTP         : 127.0.0.1:{args.http_port}

          xray config  : {written['client_config']}
          relay config : {written['relay_toml']}
          vmess link   : {written['vmess_link']}

        next steps:
          1. start the local relay:
               python3 v2ray/client_relay.py --config {written['relay_toml']}
          2. start xray:
               xray run -config {written['client_config']}
          3. point your apps at SOCKS5 127.0.0.1:{args.socks_port}
             or HTTP 127.0.0.1:{args.http_port}
        ============================================================
    """).strip("\n")


def main() -> int:
    p = argparse.ArgumentParser(description="mhr-ggate config generator")
    p.add_argument("--gas-url",    default=DEFAULT_GAS_URL,
                   help="Google Apps Script /exec URL")
    p.add_argument("--secret",     default=os.environ.get("MHR_SECRET", ""),
                   help="shared secret with VPS (or set MHR_SECRET)")
    p.add_argument("--uuid",       default=None,
                   help="VMess UUID (one will be generated if omitted)")
    p.add_argument("--path",       default=DEFAULT_PATH,
                   help="xhttp path on the xray server (default /mhr)")
    p.add_argument("--relay-port", type=int, default=DEFAULT_RELAY_PORT)
    p.add_argument("--socks-port", type=int, default=DEFAULT_SOCKS_PORT)
    p.add_argument("--http-port",  type=int, default=DEFAULT_HTTP_PORT)
    p.add_argument("--out-dir",    default=".",
                   help="directory for the generated files")
    g = p.add_argument_group(
        "fronted transport",
        "Domain-fronting + H2 multiplexing + multi-deployment knobs. "
        "See docs/research-fronted-transport.md for the full menu.",
    )
    g.add_argument("--transport",  choices=("direct", "fronted"), default="direct",
                   help="outbound transport for the relay")
    g.add_argument("--front-connect-host", default="",
                   help="Google edge IP for fronted mode "
                        "(empty = DNS resolve script.google.com)")
    g.add_argument("--front-sni", action="append", default=[], metavar="HOST",
                   help="SNI host to add to the rotation pool (repeatable). "
                        "Defaults baked into FrontedGASConfig if omitted.")
    g.add_argument("--front-script-id", action="append", default=[],
                   metavar="SID",
                   help="extra Apps Script deployment ID for round-robin "
                        "(repeatable). Empty = single SID from the gas_url.")
    g.add_argument("--front-parallel", type=int, default=1, metavar="N",
                   help="fan-out factor: race N concurrent script IDs "
                        "(needs at least N --front-script-id entries)")
    g.add_argument("--front-pool-max", type=int, default=16, metavar="N",
                   help="max H1 connections in the fallback pool")
    g.add_argument("--front-pool-min-idle", type=int, default=4, metavar="N",
                   help="target idle H1 connections in the pool")
    g.add_argument("--no-h2", action="store_true",
                   help="emit front_enable_h2=false in the generated toml")
    g.add_argument("--no-keepalive", action="store_true",
                   help="emit front_enable_keepalive=false")
    g.add_argument("--no-dev-probe", action="store_true",
                   help="emit front_enable_dev_probe=false")
    args = p.parse_args()

    # validation
    errors = []
    if "YOUR_SCRIPT_ID" in args.gas_url:
        errors.append("--gas-url is still the placeholder; set the real /exec URL")
    if not args.secret or args.secret == "CHANGE_THIS_SECRET_KEY":
        errors.append("--secret is empty; pass --secret or set MHR_SECRET")
    try:
        parse_gas(args.gas_url)
    except ValueError as exc:
        errors.append(str(exc))
    if args.uuid and not is_uuid(args.uuid):
        errors.append(f"--uuid is malformed: {args.uuid!r}")
    if errors:
        for e in errors:
            print(f"[!] {e}", file=sys.stderr)
        return 2

    vmess_uuid = args.uuid or str(uuid.uuid4())
    client_cfg = build_client_config(
        vmess_uuid=vmess_uuid,
        path=args.path,
        relay_port=args.relay_port,
        socks_port=args.socks_port,
        http_port=args.http_port,
    )
    relay_toml = build_relay_toml(
        gas_url=args.gas_url,
        secret=args.secret,
        port=args.relay_port,
        transport_mode=args.transport,
        front_connect_host=args.front_connect_host,
        front_sni_hosts=args.front_sni,
        front_script_ids=args.front_script_id,
        front_parallel_relay=args.front_parallel,
        front_pool_max=args.front_pool_max,
        front_pool_min_idle=args.front_pool_min_idle,
        front_enable_h2=not args.no_h2,
        front_enable_keepalive=not args.no_keepalive,
        front_enable_dev_probe=not args.no_dev_probe,
    )
    vmess_link = build_vmess_link(
        vmess_uuid=vmess_uuid,
        path=args.path,
        relay_port=args.relay_port,
    )

    out_dir = Path(args.out_dir).resolve()
    written = write_files(out_dir,
                          client_cfg=client_cfg,
                          relay_toml=relay_toml,
                          vmess_link=vmess_link)
    print(banner(args, vmess_uuid, written))
    return 0


if __name__ == "__main__":
    sys.exit(main())

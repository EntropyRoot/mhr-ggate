#!/usr/bin/env bash
# mhr-ggate | one-shot VPS installer
#
# Run on a fresh Debian/Ubuntu VPS as root:
#
#   curl -fsSL https://raw.githubusercontent.com/.../scripts/install_server.sh | sudo bash -s -- \
#       --domain vpn.example.com \
#       --email  you@example.com \
#       --secret "$(openssl rand -hex 24)"
#
# What it does:
#   1. installs xray, python deps, nginx, certbot
#   2. drops the relay code into /opt/mhr-ggate
#   3. writes systemd units for xray + relay
#   4. requests a Let's Encrypt cert (if --domain is real DNS)
#   5. wires up nginx -> relay :8080 over TLS
#   6. prints the values you need on the client side

set -euo pipefail

DOMAIN=""
EMAIL=""
SECRET=""
RELAY_PORT="8080"
XRAY_PORT="10000"
INSTALL_DIR="/opt/mhr-ggate"
NO_TLS="0"

usage() {
  cat <<USAGE
usage: $0 --domain <fqdn> --email <addr> --secret <secret> [--no-tls]

  --domain   DNS name pointing at this VPS (required unless --no-tls)
  --email    contact for Let's Encrypt
  --secret   shared secret used by client_relay.py / GAS / server.py
  --no-tls   skip certbot (use a self-signed cert; harder to fingerprint
             but you'll have to set allowInsecure=true on the GAS side)

USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain) DOMAIN="$2"; shift 2 ;;
    --email)  EMAIL="$2";  shift 2 ;;
    --secret) SECRET="$2"; shift 2 ;;
    --no-tls) NO_TLS="1";  shift   ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$SECRET" ]]; then
  echo "[!] --secret is required" >&2
  exit 2
fi
if [[ "$NO_TLS" != "1" && -z "$DOMAIN" ]]; then
  echo "[!] --domain is required (or pass --no-tls)" >&2
  exit 2
fi
if [[ "$EUID" -ne 0 ]]; then
  echo "[!] run as root (sudo)" >&2
  exit 2
fi

echo "[*] installing system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl unzip jq nginx python3 python3-pip python3-venv \
  ufw openssl

if [[ "$NO_TLS" != "1" ]]; then
  apt-get install -y --no-install-recommends certbot python3-certbot-nginx
fi

echo "[*] installing xray-core..."
if ! command -v xray >/dev/null 2>&1; then
  bash -c "$(curl -fsSL https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" \
    @ install
fi
mkdir -p /var/log/xray /etc/xray /usr/local/etc/xray

UUID="$(xray uuid)"
echo "[*] generated UUID: $UUID"

echo "[*] writing $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
# this script is shipped alongside the rest of the repo. copy it in.
SRC_DIR="$(cd "$(dirname "$0")"/.. && pwd)"
cp -r "$SRC_DIR"/server "$INSTALL_DIR"/server
cp    "$SRC_DIR"/requirements.txt "$INSTALL_DIR"/

python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

echo "[*] inserting UUID into xray_server.json..."
python3 - <<PY
import json, pathlib
p = pathlib.Path("$INSTALL_DIR/server/xray_server.json")
data = json.loads(p.read_text())
data["inbounds"][0]["settings"]["clients"][0]["id"] = "$UUID"
p.write_text(json.dumps(data, indent=2))
PY
cp "$INSTALL_DIR/server/xray_server.json" /usr/local/etc/xray/config.json

echo "[*] writing systemd units..."
cat >/etc/systemd/system/mhr-relay.service <<UNIT
[Unit]
Description=mhr-ggate VPS relay
After=network.target xray.service

[Service]
Type=simple
Environment=MHR_SECRET=$SECRET
Environment=XRAY_PORT=$XRAY_PORT
Environment=LISTEN_PORT=$RELAY_PORT
Environment=PYTHONUNBUFFERED=1
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/.venv/bin/python $INSTALL_DIR/server/server.py
Restart=on-failure
RestartSec=2
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now xray.service
systemctl restart xray.service
systemctl enable --now mhr-relay.service

echo "[*] writing nginx site..."
SITE_FILE="/etc/nginx/sites-available/mhr-ggate"
if [[ "$NO_TLS" == "1" ]]; then
  # self-signed
  mkdir -p /etc/nginx/ssl
  if [[ ! -f /etc/nginx/ssl/mhr.crt ]]; then
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout /etc/nginx/ssl/mhr.key \
      -out    /etc/nginx/ssl/mhr.crt \
      -subj "/CN=mhr-ggate"
  fi
  CERT_FILE="/etc/nginx/ssl/mhr.crt"
  KEY_FILE="/etc/nginx/ssl/mhr.key"
  SERVER_NAME="_"
else
  SERVER_NAME="$DOMAIN"
  CERT_FILE="/etc/letsencrypt/live/$DOMAIN/fullchain.pem"
  KEY_FILE="/etc/letsencrypt/live/$DOMAIN/privkey.pem"
fi

cat >"$SITE_FILE" <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAME;

    # certbot ACME challenge
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
    location / { return 301 https://\$host\$request_uri; }
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name $SERVER_NAME;

    ssl_certificate     $CERT_FILE;
    ssl_certificate_key $KEY_FILE;
    ssl_protocols       TLSv1.2 TLSv1.3;
    ssl_ciphers         HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # nothing else on this server, so harden defaults
    server_tokens off;
    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 16m;
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_http_version 1.1;
    proxy_read_timeout 75s;

    location / {
        proxy_pass         http://127.0.0.1:$RELAY_PORT;
        proxy_set_header   Host \$host;
        proxy_set_header   X-Forwarded-For \$remote_addr;
        proxy_set_header   X-Forwarded-Proto \$scheme;
    }
}
NGINX

ln -sf "$SITE_FILE" /etc/nginx/sites-enabled/mhr-ggate
rm -f /etc/nginx/sites-enabled/default

if [[ "$NO_TLS" != "1" ]]; then
  systemctl reload nginx || systemctl restart nginx
  certbot --nginx --non-interactive --agree-tos \
    --email "$EMAIL" -d "$DOMAIN" --redirect || {
      echo "[!] certbot failed; falling back to self-signed" >&2
    }
fi

systemctl restart nginx

echo "[*] firewall (ufw)..."
ufw --force reset >/dev/null 2>&1 || true
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

cat <<DONE

============================================================
  mhr-ggate server install complete
============================================================

  VPS URL    : https://${DOMAIN:-<your-vps-ip>}
  Secret     : $SECRET
  UUID       : $UUID

  systemd:
    systemctl status xray
    systemctl status mhr-relay
    journalctl -u mhr-relay -f

  next, on your local machine:
    python3 v2ray/generate_config.py \\
      --gas-url "https://script.google.com/macros/s/.../exec" \\
      --secret  "$SECRET" \\
      --uuid    "$UUID"

  then deploy gas/Code.gs as a Web App and paste:
      VPS_URL = "https://${DOMAIN:-<your-vps-ip>}"
      SECRET  = "$SECRET"
============================================================
DONE

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
CONFIGURE_FIREWALL="1"
RESET_FIREWALL="0"
EXTRA_SSH_PORTS=""

usage() {
  cat <<USAGE
usage: $0 --domain <fqdn> --email <addr> --secret <secret> [options]

  --domain          DNS name pointing at this VPS (required unless --no-tls)
  --email           contact for Let's Encrypt
  --secret          shared secret used by client_relay.py / GAS / server.py
  --no-tls          skip certbot and use a self-signed certificate
  --no-firewall     do not change UFW at all
  --reset-firewall  reset UFW before applying rules (dangerous; off by default)
  --ssh-port <port> force-preserve an SSH port, can be passed multiple times

Firewall behavior:
  By default the installer PRESERVES existing UFW rules and only adds safe
  allows for detected SSH port(s), 80/tcp, and 443/tcp. It does not reset UFW
  unless --reset-firewall is explicitly passed.

USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain)
      [[ $# -ge 2 ]] || { echo "[!] --domain needs a value" >&2; exit 2; }
      DOMAIN="$2"; shift 2 ;;
    --email)
      [[ $# -ge 2 ]] || { echo "[!] --email needs a value" >&2; exit 2; }
      EMAIL="$2"; shift 2 ;;
    --secret)
      [[ $# -ge 2 ]] || { echo "[!] --secret needs a value" >&2; exit 2; }
      SECRET="$2"; shift 2 ;;
    --ssh-port)
      [[ $# -ge 2 ]] || { echo "[!] --ssh-port needs a value" >&2; exit 2; }
      EXTRA_SSH_PORTS="$EXTRA_SSH_PORTS $2"; shift 2 ;;
    --no-tls) NO_TLS="1"; shift ;;
    --no-firewall) CONFIGURE_FIREWALL="0"; shift ;;
    --reset-firewall) RESET_FIREWALL="1"; shift ;;
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

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    cp "$f" "$f.bak.$(date +%F-%H%M%S)"
  fi
}

valid_port() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] && (( $1 >= 1 && $1 <= 65535 ))
}

collect_ssh_ports() {
  local ports=() p

  # If installer is running over SSH, SSH_CONNECTION's 4th field is the
  # server-side port of the current session. This is the most important one.
  if [[ -n "${SSH_CONNECTION:-}" ]]; then
    p="$(awk '{print $4}' <<<"$SSH_CONNECTION" 2>/dev/null || true)"
    valid_port "$p" && ports+=("$p")
  fi

  # Ports currently listened on by sshd.
  while read -r p; do
    valid_port "$p" && ports+=("$p")
  done < <(ss -tulpn 2>/dev/null | awk '/sshd/ {n=split($5,a,":"); print a[n]}' | sort -nu || true)

  # Ports explicitly configured in sshd_config or sshd_config.d.
  while read -r p; do
    valid_port "$p" && ports+=("$p")
  done < <(grep -RhsE '^[[:space:]]*Port[[:space:]]+[0-9]+' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null | awk '{print $2}' | sort -nu || true)

  # User-forced ports.
  for p in $EXTRA_SSH_PORTS; do
    valid_port "$p" && ports+=("$p")
  done

  # Always keep 22 as a safety net.
  ports+=("22")

  printf '%s\n' "${ports[@]}" | awk '!seen[$0]++' | sort -nu
}

configure_firewall_safely() {
  if [[ "$CONFIGURE_FIREWALL" != "1" ]]; then
    echo "[*] firewall: skipped (--no-firewall)"
    return 0
  fi

  if ! command -v ufw >/dev/null 2>&1; then
    echo "[*] firewall: ufw not installed, skipping"
    return 0
  fi

  echo "[*] firewall (ufw safe mode)..."
  mapfile -t SSH_PORTS < <(collect_ssh_ports)
  echo "[*] preserving SSH port(s): ${SSH_PORTS[*]}"

  if [[ "$RESET_FIREWALL" == "1" ]]; then
    echo "[!] resetting UFW because --reset-firewall was explicitly requested"
    ufw --force reset >/dev/null 2>&1 || true
    ufw default deny incoming
    ufw default allow outgoing
  else
    echo "[*] preserving existing UFW rules (no reset)"
    if ! ufw status | grep -q '^Status: active'; then
      ufw default deny incoming
      ufw default allow outgoing
    fi
  fi

  for p in "${SSH_PORTS[@]}"; do
    ufw allow "${p}/tcp" comment 'mhr-ggate preserve ssh' >/dev/null || true
  done
  ufw allow 80/tcp comment 'mhr-ggate http' >/dev/null || true
  ufw allow 443/tcp comment 'mhr-ggate https' >/dev/null || true

  ufw --force enable
  ufw status verbose
}

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
if [[ ! -d "$SRC_DIR/server" || ! -f "$SRC_DIR/requirements.txt" ]]; then
  echo "[!] repository files not found next to installer." >&2
  echo "    Run this script from the cloned repository, e.g.:" >&2
  echo "      cd mhr-ggate && sudo bash scripts/install_server.sh ..." >&2
  echo "    Piping only install_server.sh into bash cannot work because server/ and requirements.txt are needed." >&2
  exit 2
fi
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
backup_file /usr/local/etc/xray/config.json
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
mkdir -p /var/www/html
backup_file "$SITE_FILE"

# If UFW is already active, make sure ACME/http/https are reachable before
# requesting certificates. This does not enable UFW if it was disabled.
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
  ufw allow 80/tcp comment 'mhr-ggate http' >/dev/null || true
  ufw allow 443/tcp comment 'mhr-ggate https' >/dev/null || true
fi

if [[ "$NO_TLS" == "1" ]]; then
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

  # Do NOT write an HTTPS nginx server before the certificate exists; nginx
  # would fail to reload. Use a temporary HTTP-only site for certbot webroot.
  cat >"$SITE_FILE" <<NGINX_HTTP
server {
    listen 80;
    listen [::]:80;
    server_name $SERVER_NAME;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    location / {
        return 200 "mhr-ggate bootstrap\n";
        add_header Content-Type text/plain;
    }
}
NGINX_HTTP

  ln -sf "$SITE_FILE" /etc/nginx/sites-enabled/mhr-ggate
  rm -f /etc/nginx/sites-enabled/default
  nginx -t
  systemctl reload nginx || systemctl restart nginx

  if ! certbot certonly --webroot -w /var/www/html --non-interactive --agree-tos \
      --email "$EMAIL" -d "$DOMAIN"; then
    echo "[!] certbot failed; falling back to self-signed certificate" >&2
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
      -keyout /etc/nginx/ssl/mhr.key \
      -out    /etc/nginx/ssl/mhr.crt \
      -subj "/CN=${DOMAIN:-mhr-ggate}"
    CERT_FILE="/etc/nginx/ssl/mhr.crt"
    KEY_FILE="/etc/nginx/ssl/mhr.key"
  fi
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
nginx -t
systemctl restart nginx

configure_firewall_safely

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

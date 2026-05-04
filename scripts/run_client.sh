#!/usr/bin/env bash
# mhr-ggate | start the local relay + xray client (Linux/macOS)
#
# Reads two files in the current directory by default:
#   - relay.toml         (client_relay config)
#   - client_config.json (xray client config)
#
# Both produced by `python3 v2ray/generate_config.py`.

set -euo pipefail

ROOT="${MHR_DIR:-$(pwd)}"
RELAY_CONFIG="${RELAY_CONFIG:-$ROOT/relay.toml}"
XRAY_CONFIG="${XRAY_CONFIG:-$ROOT/client_config.json}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
XRAY_BIN="${XRAY_BIN:-xray}"

for f in "$RELAY_CONFIG" "$XRAY_CONFIG"; do
  if [[ ! -f "$f" ]]; then
    echo "[!] missing config: $f" >&2
    exit 2
  fi
done

if ! command -v "$XRAY_BIN" >/dev/null 2>&1; then
  echo "[!] xray binary not found in PATH (set XRAY_BIN env)" >&2
  exit 2
fi

cleanup() {
  echo
  echo "[*] stopping..."
  [[ -n "${RELAY_PID:-}" ]] && kill "$RELAY_PID" 2>/dev/null || true
  [[ -n "${XRAY_PID:-}"  ]] && kill "$XRAY_PID"  2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

echo "[*] starting client_relay..."
"$PYTHON_BIN" "$ROOT/v2ray/client_relay.py" --config "$RELAY_CONFIG" &
RELAY_PID=$!

# wait for the relay to bind (5s max)
for i in $(seq 1 25); do
  if curl -fs http://127.0.0.1:8000/_mhr/health >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

echo "[*] starting xray..."
"$XRAY_BIN" run -config "$XRAY_CONFIG" &
XRAY_PID=$!

echo
echo "[*] mhr-ggate is up."
echo "    SOCKS5 : 127.0.0.1:1080"
echo "    HTTP   : 127.0.0.1:8118"
echo "    relay  : http://127.0.0.1:8000/_mhr/stats"
echo "    Ctrl+C to stop."

wait -n

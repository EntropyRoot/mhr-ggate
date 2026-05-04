# mhr-ggate

> 🇮🇷 [نسخه فارسی](README.fa.md)

Tunnel real VMess+xhttp traffic through Google Apps Script to your own VPS.
Built on the original `mhr-cfw` idea, but with a real xray tunnel underneath
so UDP, gaming, and any TCP app actually works — not just HTTP.

```
xray client (SOCKS5 / HTTP)
   └── 127.0.0.1:8000  client_relay.py        # base64-wraps each request
            └── https://script.google.com/macros/s/.../exec   # GAS Web App
                     └── https://your-vps      # nginx + TLS
                              └── 127.0.0.1:8080  server.py   # base64-unwraps
                                       └── 127.0.0.1:10000  xray (vmess+xhttp)
                                                └── internet
```

GAS runs on Google's domain, so it almost never gets blocked. Your VPS IP
is never dialled directly by the client — only GAS reaches it. Everything
stays inside a real VMess tunnel, so UDP and games keep working.

---

## what changed vs the original

The original prototype tried to point xray straight at `script.google.com`
using SplitHTTP+TLS. That can't work in practice:

| issue | why it broke |
|---|---|
| GAS doesn't speak VMess | xray's TLS handshake to GAS doesn't translate to a VMess server response |
| binary corruption in GAS | `e.postData.contents` is a string — VMess body bytes get mangled |
| SplitHTTP long-poll vs GAS 6-min cap | the default download leg is a long stream, GAS executions are short |
| no auth check, no error handling | the secret was forwarded but nothing verified it constant-time |

This rewrite fixes all of that:

1. **Adds a local `client_relay.py`** that sits between xray and GAS. It
   base64-wraps every outgoing body and unwraps every incoming one, so
   binary data survives the GAS round-trip cleanly.
2. **Switches the transport to `xhttp` with `mode = "packet-up"`** — every
   request is short and self-contained, no long-polling that GAS can't
   serve.
3. **Hardens `server.py`**: explicit base64 decode, constant-time secret
   check, oversized-payload limit, structured logging, `/_mhr/stats`,
   graceful retries on the relay side.
4. **Ships everything to actually run it**: install script, systemd
   units, nginx template, Docker compose, tests, Windows launcher.

---

## requirements

- a VPS outside Iran (any provider, any size)
- a free Google account
- [xray-core](https://github.com/XTLS/Xray-core) on the VPS (script
  installs it for you)
- Python 3.10+ on the VPS **and on your local machine** (for the relay)
- a v2ray-compatible client (`xray` CLI works, or v2rayN / NekoBox /
  Hiddify if you import the `vmess://` link)

---

## quickstart

### 1. clone

```bash
git clone https://github.com/Vuks1n/mhr-ggate
cd mhr-ggate
```

### 2. one-shot VPS install

On a fresh Debian/Ubuntu VPS (as root):

```bash
SECRET="$(openssl rand -hex 24)"
sudo bash scripts/install_server.sh \
    --domain vpn.example.com \
    --email  you@example.com \
    --secret "$SECRET"
```

That installs xray, sets up `/opt/mhr-ggate`, writes a `mhr-relay.service`
unit, configures nginx with Let's Encrypt, and prints the UUID +
`SECRET` you'll need next.

No domain? Use `--no-tls` and you'll get a self-signed cert. (The Code.gs
side will need `validateHttpsCertificates: false` — see comments in the
script.)

You can also run it via Docker — see `docker/docker-compose.yml`.

### 3. deploy the GAS Web App

1. open <https://script.google.com> → **New project**
2. paste `gas/Code.gs`
3. fill in the two consts at the top:

   ```js
   var VPS_URL = "https://vpn.example.com";
   var SECRET  = "...";   // same secret you passed to install_server.sh
   ```

4. **Deploy → New deployment → Web app**
   - Execute as: **Me**
   - Who has access: **Anyone**

5. copy the deployment URL — looks like
   `https://script.google.com/macros/s/.../exec`.

### 4. generate your client configs

Locally:

```bash
pip install -r requirements.txt

python3 v2ray/generate_config.py \
    --gas-url "https://script.google.com/macros/s/.../exec" \
    --secret  "$SECRET" \
    --uuid    "$UUID"      # the UUID install_server.sh printed
```

This writes three files to the current dir:

- `relay.toml` — config for `client_relay.py`
- `client_config.json` — xray client config
- `mhr.vmess` — single shareable vmess:// link (points at the local relay)

### 5. run it

#### Linux / macOS

```bash
bash scripts/run_client.sh
```

#### Windows (PowerShell)

```powershell
pwsh scripts\run_client.ps1
```

#### manually

```bash
# terminal 1
python3 v2ray/client_relay.py --config relay.toml

# terminal 2
xray run -config client_config.json
```

Either way you'll end up with:

- `socks5://127.0.0.1:1080`
- `http://127.0.0.1:8118`

Point your browser, game launcher, or apps at those.

---

## gaming / UDP

Set your launcher to SOCKS5 `127.0.0.1:1080`. On Windows you can use
[Proxifier](https://www.proxifier.com/) to wrap any game whose client
doesn't have built-in SOCKS5 support.

UDP is wrapped inside the VMess tunnel via xray's xudp mux — gaming and
voice work the same way they do over a normal VMess link.

---

## architecture

See [docs/architecture.md](docs/architecture.md) for the full picture
including a sequence diagram and an explanation of the base64 wrapping
discipline.

```
mhr-ggate/
├── gas/
│   └── Code.gs                   # paste into Google Apps Script
├── server/
│   ├── server.py                 # VPS relay (FastAPI)
│   └── xray_server.json          # xray inbound config (vmess + xhttp)
├── v2ray/
│   ├── client_relay.py           # local relay between xray client and GAS
│   └── generate_config.py        # produces relay.toml + client_config.json + mhr.vmess
├── scripts/
│   ├── install_server.sh         # one-shot VPS installer
│   ├── mhr-relay.service         # systemd unit for server.py
│   ├── mhr-client-relay.service  # systemd unit for client_relay.py (Linux clients)
│   ├── nginx.conf.template
│   ├── run_client.sh             # Linux launcher (relay + xray)
│   └── run_client.ps1            # Windows launcher
├── docker/
│   ├── Dockerfile.server
│   └── docker-compose.yml
├── tests/                         # 38 unit + e2e tests, including binary round-trip
└── requirements.txt
```

---

## monitoring

Both relays expose a tiny stats endpoint protected by `MHR_SECRET`:

```bash
curl -H "X-MHR-Secret: $SECRET" https://vpn.example.com/_mhr/stats
curl http://127.0.0.1:8000/_mhr/stats
```

Returns request counts, byte counters and the last error string.

---

## tests

```bash
pip install -r requirements.txt
pip install pytest
python -m pytest tests/ -v
```

The test suite includes a full pipeline test that wires
`client_relay → fake GAS → server.py → fake xray` together with no
network calls, and proves a 1 MiB binary payload survives the round
trip byte-for-byte.

---

## limits to be aware of

- **GAS quota**: free Google accounts get ~20 000 URL fetches per day.
  Plenty for personal browsing, fewer if you're streaming 4K. If you hit
  the cap, deploy a second Web App from another account and run two
  client_relay instances pointed at different `gas_url`s.
- **Latency**: every packet hops `client → GAS → VPS → xray → VPS → GAS
  → client`. Expect +60–200 ms vs a direct connection. Throughput is
  fine for browsing/gaming; not great for big sustained downloads.
- **xray version**: `xhttp` transport requires xray-core ≥ 1.8.16 (or
  the equivalent v2fly fork). The install script always pulls the
  latest.

---

## credits

- [mhr-cfw](https://github.com/denuitt1/mhr-cfw) — original GAS-as-relay idea
- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) — the actual tunnel

PRs welcome.

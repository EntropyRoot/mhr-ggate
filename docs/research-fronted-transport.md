# Fronted GAS Transport — research note

> Status: **research / experimental**. Not on by default. The relay
> still uses plain `httpx` unless `transport_mode = "fronted"` is set.

This note documents the new file `v2ray/fronted_gas_transport.py` and
why it looks the way it does. It is intentionally a *small* port of one
specific idea from
[`mhr-cfw/src/domain_fronter.py`](https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/domain_fronter.py),
not a fork.

---

## 1. What problem this solves

`client_relay.py` talks to `script.google.com` over plain `httpx`. In
networks where DPI inspects the TLS ClientHello SNI field, this is a
visible signal: every flow from the client carries
`server_name = script.google.com`.

**Domain fronting** decouples three things that DPI assumes are equal:

|                    | Direct httpx           | Fronted              |
| ------------------ | ---------------------- | -------------------- |
| TCP destination    | DNS(`script.google.com`) | a Google edge IP   |
| TLS SNI            | `script.google.com`    | `www.google.com`*    |
| HTTP `Host:` header| `script.google.com`    | `script.google.com`  |

*rotated across a small pool of Google-owned hostnames, see
`DEFAULT_SNI_POOL` in `v2ray/fronted_gas_transport.py`.*

The Google edge terminates TLS for *any* of its hostnames on the same
IPs, then dispatches by HTTP `Host`. So the on-wire SNI is benign while
the actual destination is unchanged. That is the entire trick.

> This is not a guarantee of evading any specific censor. It is a
> research surface for measuring whether SNI-based blocking applies to
> the GAS path in a given network.

## 2. What is *not* in this file (and why)

`mhr-cfw` is a full HTTPS web proxy. Its `domain_fronter.py` carries a
lot more than the fronting handshake itself:

* `mitm.py` — local CA + per-site certificate forging. Lets the proxy
  read inside the browser's HTTPS so it can rebuild it as a
  GAS/Worker call. **mhr-ggate does not need this.** The byte stream
  flowing through the relay is opaque Xray traffic; we don't introspect
  it, we don't terminate it, we don't need a certificate.
* `proxy_server.py` — the local HTTPS proxy that browsers point at.
  Irrelevant: xray talks to `client_relay.py` over plain HTTP/xhttp on
  127.0.0.1.
* `cert_installer.py` — installs the local CA into OS / browser stores.
  Irrelevant for the same reason as `mitm.py`.
* The `relay(method, url, headers, body)` payload model that builds a
  per-site web request to fetch a target URL. mhr-ggate's payload is
  not "fetch this URL", it is "carry these base64 bytes through GAS",
  which `client_relay.py` already constructs.

So the new file only ports the *plumbing* underneath that payload:

* `_open()` — TCP_NODELAY socket → asyncio TLS handshake with
  `server_hostname=` rotated.
* `_next_sni()` — round-robin SNI rotation.
* `_acquire()` / `_release()` — TTL'd connection pool.
* The HTTP/1.1 read/write loop with redirect follow on the same
  socket, mirroring `_relay_single` and `_read_http_response` from
  `domain_fronter.py`.

Not ported (out of scope for the research surface, can be added later
if benchmarks justify them):

* HTTP/2 multiplexing (`h2_transport.py`)
* Fan-out across multiple Apps Script deployments
* Batch collector (`fetchAll`)
* Request coalescing
* Per-host stats logger
* `_dev` fast-path detection

## 3. The mapping, line by line

```text
mhr-cfw DomainFronter.relay(method, url, headers, body)
    ↓ rewritten as
FrontedGASTransport.request(method, gas_url, params, headers, content)

mhr-cfw web payload JSON ({m, u, h, b, ct, k})
    ↓ DROPPED  (client_relay.py already built the GAS payload)

mhr-cfw MITM / CA / cert / browser HTTPS
    ↓ DROPPED  (this is not a web proxy)

mhr-cfw target URL fetch model
    ↓ DROPPED  (we don't call UrlFetchApp ourselves)

mhr-ggate base64 raw-body relay shape
    ↓ KEPT verbatim  (X-MHR-Secret, X-MHR-Method, ?path=, b64 ascii body)
```

Wire shape (unchanged from `client_relay.py`):

```http
POST /macros/s/<sid>/exec?path=/mhr/<sess>/<seq> HTTP/1.1
Host: script.google.com
User-Agent: mhr-ggate-relay/2.0 (fronted)
Accept-Encoding: identity
Connection: keep-alive
X-MHR-Secret: <secret>
X-MHR-Method: POST
Content-Type: text/plain; charset=ascii
Content-Length: <N>

<base64-ascii body, exactly as client_relay.py generated it>
```

The TLS underneath is opened to `connect_host` (e.g.
`216.239.38.120`) with `server_hostname=` cycling through
`{www.google.com, mail.google.com, accounts.google.com}`. From the
GAS server's perspective nothing changes — the request is identical.

## 4. Pipeline (where this fits)

```text
Xray client (xhttp, no TLS)
  → 127.0.0.1:8000   client_relay.py
                      └── transport: DirectHttpxTransport   (default)
                          or       FrontedGASTransport      (research)
                              ├── TCP    → Google edge IP
                              ├── TLS    → SNI = www.google.com  (rotated)
                              └── HTTP   → Host: script.google.com
                                          ?path=/mhr/<sess>/<seq>
                                          base64(raw xray bytes)
  → https://script.google.com/macros/s/<sid>/exec
  → gas/Code.gs (UrlFetchApp)
  → https://your-vps/mhr/<sess>/<seq>
  → server.py + nginx
  → 127.0.0.1:10000  Xray server
```

## 5. How to use

### Generate a relay config in fronted mode

```bash
python3 v2ray/generate_config.py \
    --gas-url https://script.google.com/macros/s/SID/exec \
    --secret  MY_SHARED_SECRET \
    --transport fronted \
    --front-connect-host 216.239.38.120 \
    --front-sni www.google.com \
    --front-sni mail.google.com
```

This writes `relay.toml` with:

```toml
transport_mode      = "fronted"
front_connect_host  = "216.239.38.120"
front_sni_hosts     = ["www.google.com", "mail.google.com"]
front_http_host     = "script.google.com"
front_verify_ssl    = true
```

### Sanity-probe the transport without spinning up the relay

```bash
python3 v2ray/fronted_gas_transport.py \
    --gas-url https://script.google.com/macros/s/SID/exec \
    --secret  MY_SHARED_SECRET \
    --connect-host 216.239.38.120
```

A successful run prints `status=200` and a small JSON body from
`gas/Code.gs`'s health branch.

## 6. Open questions / things to measure

These are the things the research surface is set up to answer:

* **Does SNI rotation matter or is `connect_host` alone enough?**
  Compare a fixed `connect_host` with a single SNI vs. with the rotation
  pool, on a network where direct mode is throttled.
* **Latency cost of fronting vs. httpx.** httpx pools more aggressively
  and uses HTTP/2 to Google. Expect a small p50 hit; measure p99 too.
* **Edge-IP stability.** `DEFAULT_GOOGLE_EDGE_IPS` is a sample. A real
  experiment should pull a fresh list (see
  `mhr-cfw/src/google_ip_scanner.py` and `CANDIDATE_IPS` in
  `mhr-cfw/src/constants.py`) and pin to one that responds well.
* **Redirect behavior.** `script.google.com/.../exec` typically returns
  302 → `script.googleusercontent.com`. We follow on the same TLS
  socket because both are served by the same Google edge. Verify this
  in your environment with `curl -v --resolve` first.
* **Failure modes.** What happens when the configured `connect_host`
  IP rotates out of Google's pool? Today: TLS handshake fails fast and
  the client_relay's existing retry loop applies. A future iteration
  could carry an IP scanner like the mhr-cfw one.

## 7. Source pointers

* Brain ported from: [`mhr-cfw/src/domain_fronter.py`][df] (specifically
  `_open`, `_next_sni`, `_acquire`/`_release`, `_relay_single`,
  `_read_http_response`).
* Constants reference: [`mhr-cfw/src/constants.py`][const]
  (`FRONT_SNI_POOL_GOOGLE`, `CANDIDATE_IPS`, `RELAY_TIMEOUT`, etc.).
* MITM/proxy parts intentionally **not** ported:
  [`mhr-cfw/src/mitm.py`][mitm],
  [`mhr-cfw/src/proxy_server.py`][proxy].

[df]:   https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/domain_fronter.py
[const]: https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/constants.py
[mitm]: https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/mitm.py
[proxy]: https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/proxy_server.py

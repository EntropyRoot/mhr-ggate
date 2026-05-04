# Fronted GAS Transport — research note

> Status: **research / experimental**. Not on by default. The relay
> still uses plain `httpx` unless `transport_mode = "fronted"` is set
> (or `--transport fronted` is passed on the CLI).

This note documents `v2ray/fronted_gas_transport.py` and
`v2ray/h2_transport.py` — the optional fronted outbound path used by
`client_relay.py`. The brain is ported from
[`mhr-cfw/src/domain_fronter.py`](https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/domain_fronter.py)
and [`mhr-cfw/src/h2_transport.py`](https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/h2_transport.py),
but stripped to only the parts that earn their keep when the payload
is opaque tunneled bytes (no MITM, no web-payload model, no target-
URL fetch).

---

## 1. The fronting trick (one paragraph)

`client_relay.py` talks to `script.google.com`. Direct httpx puts that
hostname into the TLS ClientHello SNI field, where DPI can see it.
**Domain fronting** decouples three things that DPI assumes are equal:

|                    | Direct httpx              | Fronted                |
| ------------------ | ------------------------- | ---------------------- |
| TCP destination    | DNS(`script.google.com`)  | a Google edge IP       |
| TLS SNI            | `script.google.com`       | `www.google.com`*      |
| HTTP `:authority` / `Host:` | `script.google.com` | `script.google.com`    |

*rotated across `DEFAULT_SNI_POOL` — currently
`{www.google.com, mail.google.com, accounts.google.com}`.*

The Google edge terminates TLS for *any* of its hosted hostnames on the
same IPs and dispatches by HTTP `Host` (or H2 `:authority`). That's the
whole trick.

## 2. What this code actually does — architecture

```
FrontedGASTransport
├─ HTTP/2 path (preferred)              v2ray/h2_transport.py
│   ONE TLS connection × hundreds of streams.
│   Tuned for xray xhttp's scMaxConcurrentPosts=100 workload.
│   Falls back to H1 if `h2` lib missing or H2 fails ≥3 times.
│
├─ HTTP/1.1 pool (fallback)
│   TTL'd connection pool with background maintenance.
│   pool_min_idle pre-warm + auto-purge of aged conns.
│   Strict RFC 7230 chunked decoder (rejects partials — partial body
│   in a tunnel transport == VMess desync).
│
├─ Multi-Script-ID rotation
│   Round-robin across `front_script_ids`, skipping IDs that are
│   short-term blacklisted after a failure / timeout.
│
├─ Fan-out (off by default)
│   `front_parallel_relay > 1` races N distinct script IDs in parallel,
│   takes the first success, cancels the rest. Cuts tail latency when
│   one container is cold/slow.
│
├─ /dev fast-path probe
│   On first H2 connect, probe the deployment's `/dev` endpoint. If it
│   replies inline (no 302 redirect to script.googleusercontent.com),
│   subsequent requests skip /exec → /dev — saves ~400 ms each.
│
├─ Container keepalive
│   Apps Script idles a container at ~5 min. A 4-min H2 PING keeps it
│   warm at near-zero cost, eliminating ~600-1500 ms cold-starts.
│
└─ Strict request building
    SNI rotation per new TLS handshake, TCP_NODELAY + SO_KEEPALIVE,
    Host header pinned to cfg.http_host, hop-by-hop headers stripped
    on the H2 side (Connection / Content-Length / TE / Upgrade live in
    the H2 frame layer, not the header block).
```

## 3. What is *not* in this code (and why)

`mhr-cfw` is a full HTTPS web proxy. Its `domain_fronter.py` carries a
lot more, none of which the byte-tunnel use case needs:

* `mitm.py` — local CA + per-site cert forging. We never see HTTPS
  inside the tunnel; we just carry it.
* `proxy_server.py` — the local HTTPS proxy that browsers point at.
  Irrelevant — xray uses our internal xhttp on `127.0.0.1:8000`.
* `cert_installer.py` — installs the local CA into OS / browser stores.
* The `relay(method, url, headers, body)` web-payload model.
* `codec.py` — gzip/br/zstd decoding for fetched HTML. Our base64
  payloads are already compact, recompressing costs more than it saves.
* Per-host stats / batch `fetchAll` / request coalescing — all bound
  to the multi-target web-proxy model. We have one target.
* Range probes / spool / progress bars — large-file streaming for
  browser downloads.

## 4. Wire shape (unchanged from the relay)

```http
POST /macros/s/<sid>/exec?path=/mhr/<sess>/<seq> HTTP/1.1
Host: script.google.com                    ← fronted
User-Agent: mhr-ggate-relay/2.0 (fronted)
Accept-Encoding: identity
Connection: keep-alive
X-MHR-Secret: <secret>
X-MHR-Method: POST
Content-Type: text/plain; charset=ascii
Content-Length: <N>

<base64-ascii body, exactly as client_relay.py generated it>
```

The TLS underneath is opened to `cfg.connect_host` (e.g.
`216.239.38.120`) with `server_hostname=` cycling through the SNI
rotation pool. From the upstream's perspective nothing changes.

When HTTP/2 is active, the request goes out as a single HEADERS frame
(`:method` / `:path` / `:authority` / `:scheme`) plus a DATA frame for
the body, all multiplexed onto the persistent connection alongside
every other in-flight request.

## 5. How to use — three ways

### Direct CLI (no config file)

```bash
python3 v2ray/client_relay.py \
    --gas-url https://script.google.com/macros/s/SID/exec \
    --secret  YOUR_SECRET \
    --transport fronted \
    --front-connect-host 216.239.38.120 \
    --front-sni www.google.com \
    --front-sni mail.google.com \
    --front-script-id ANOTHER_DEPLOYMENT_ID \
    --front-script-id THIRD_DEPLOYMENT_ID \
    --front-parallel 2
```

Tweaks: `--no-h2`, `--no-keepalive`, `--no-dev-probe`,
`--no-pool-maintenance`, `--front-insecure`, `--front-pool-max`,
`--front-pool-min-idle`. Run with `--help` for the full list.

### Environment variables

```bash
export MHR_TRANSPORT=fronted
export MHR_FRONT_CONNECT_HOST=216.239.38.120
python3 v2ray/client_relay.py --gas-url ... --secret ...
```

### Generate a fronted relay.toml

```bash
python3 v2ray/generate_config.py \
    --gas-url https://script.google.com/macros/s/SID/exec \
    --secret  YOUR_SECRET \
    --transport fronted \
    --front-connect-host 216.239.38.120 \
    --front-sni www.google.com \
    --front-sni mail.google.com \
    --front-script-id ANOTHER_DEPLOYMENT_ID \
    --front-parallel 2
```

Produces a `relay.toml` like:

```toml
gas_url           = "https://script.google.com/macros/s/SID/exec"
secret            = "YOUR_SECRET"
listen_host       = "127.0.0.1"
listen_port       = 8000

# ── outbound transport ──
transport_mode             = "fronted"
front_connect_host         = "216.239.38.120"
front_sni_hosts            = ["www.google.com", "mail.google.com"]
front_http_host            = "script.google.com"
front_verify_ssl           = true

front_script_ids           = ["ANOTHER_DEPLOYMENT_ID"]
front_enable_h2            = true
front_enable_keepalive     = true
front_enable_dev_probe     = true
front_enable_pool_maintenance = true
front_parallel_relay       = 2
front_pool_max             = 16
front_pool_min_idle        = 4
```

### Sanity-probe the transport without spinning up the relay

```bash
python3 v2ray/fronted_gas_transport.py \
    --gas-url https://script.google.com/macros/s/SID/exec \
    --secret  YOUR_SECRET \
    --connect-host 216.239.38.120 \
    --script-id ANOTHER_DEPLOYMENT_ID \
    --parallel 2
```

A successful run prints `status=200`, the GAS health-branch JSON, and
the transport's stats dict (`h2_requests`, `h1_requests`, `last_sni`,
`dev_fast_path`, etc.).

## 6. Configuration reference

| Field                             | CLI                        | Default                | Meaning |
| --------------------------------- | -------------------------- | ---------------------- | ------- |
| `transport_mode`                  | `--transport`              | `direct`               | `direct` (httpx) or `fronted` |
| `front_connect_host`              | `--front-connect-host`     | `""` (DNS)             | Google edge IP for the TCP socket |
| `front_sni_hosts`                 | `--front-sni` (repeatable) | Google SNI pool        | Rotation pool for `server_hostname=` |
| `front_http_host`                 | `--front-http-host`        | `script.google.com`    | HTTP `Host` / H2 `:authority` |
| `front_verify_ssl`                | `--front-insecure` flips off | `true`               | Verify Google's cert (only flip for debug) |
| `front_script_ids`                | `--front-script-id` (rep.) | `[]`                   | Round-robin pool of Apps Script deployments |
| `front_enable_h2`                 | `--no-h2` flips off        | `true`                 | HTTP/2 multiplexing path |
| `front_enable_keepalive`          | `--no-keepalive` flips off | `true`                 | 4-min PING to keep Apps Script container warm |
| `front_enable_dev_probe`          | `--no-dev-probe` flips off | `true`                 | Try `/dev` fast-path (saves ~400 ms / req) |
| `front_enable_pool_maintenance`   | `--no-pool-maintenance`    | `true`                 | Background H1 pool refill / purge |
| `front_parallel_relay`            | `--front-parallel`         | `1`                    | Fan-out factor (needs ≥N script IDs) |
| `front_pool_max`                  | `--front-pool-max`         | `16`                   | Max H1 connections in the fallback pool |
| `front_pool_min_idle`             | `--front-pool-min-idle`    | `4`                    | Idle conns the maintenance task keeps warm |

## 7. Tradeoffs / things to measure

These are the questions the research surface exists to answer:

* **H2 vs. H1 throughput.** With `scMaxConcurrentPosts=100`, the H1
  pool is bottlenecked by `pool_max`. H2 multiplexes — measure the
  difference under sustained load.
* **SNI rotation worth it?** Compare a fixed `connect_host` + single
  SNI vs. the rotation pool on a network where direct mode is
  throttled.
* **`/dev` vs `/exec`.** The probe automatically promotes when it
  works; measure the ~400 ms claim per round trip on your deployment.
* **Multi-deployment scaling.** Each Apps Script deployment has its
  own quota / concurrency limit. With 3-5 SIDs in `front_script_ids`,
  measure whether tail latency drops in proportion.
* **Fan-out at parallel=2 vs 3.** Parallel=2 with two SIDs gives the
  best p99 cut for "one container is cold"; parallel=3+ may not
  justify the extra Google quota burn.
* **Edge-IP stability.** `DEFAULT_GOOGLE_EDGE_IPS` is a sample. A real
  experiment should pull a fresh list (see
  `mhr-cfw/src/google_ip_scanner.py`) and pin to one that responds
  best from your network.
* **Failure modes.** Pull the network mid-stream while H2 is active —
  the read loop should detect EOF, the keepalive task should reconnect
  on its next tick, and the H1 pool should pick up traffic in between.
  None of these should produce corrupt body bytes (the strict chunked
  decoder + strict base64 decoder upstream guard against that).

## 8. Source pointers

* Brain ported from: [`mhr-cfw/src/domain_fronter.py`][df] (specifically
  `_open`, `_next_sni`, `_acquire`/`_release`, `_relay_single`,
  `_read_http_response`, `_pool_maintenance`, `_keepalive_loop`,
  `_blacklist_sid`, `_pick_fanout_sids`, `_relay_fanout`).
* H2 path ported from: [`mhr-cfw/src/h2_transport.py`][h2] (the
  whole thing, minus the `codec` dependency).
* Constants reference: [`mhr-cfw/src/constants.py`][const]
  (`FRONT_SNI_POOL_GOOGLE`, `CANDIDATE_IPS`, `RELAY_TIMEOUT`,
  `POOL_MAX`, `KEEPALIVE_INTERVAL` etc.).
* MITM/proxy parts intentionally **not** ported:
  [`mhr-cfw/src/mitm.py`][mitm],
  [`mhr-cfw/src/proxy_server.py`][proxy].

[df]:    https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/domain_fronter.py
[h2]:    https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/h2_transport.py
[const]: https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/constants.py
[mitm]:  https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/mitm.py
[proxy]: https://raw.githubusercontent.com/denuitt1/mhr-cfw/main/src/proxy_server.py

# whisper-id

A real, routable **IPv6 identity** and **safe egress** for any Python agent — in two calls.

```sh
pip install whisper-id            # add [socks] for requests+SOCKS: pip install "whisper-id[socks]"
```

```python
from whisper_id import register, egress
import requests

agent = register("my-bot")                       # a routable Whisper /128 identity
with egress():                                   # route this block through your /128
    requests.get("https://api64.ipify.org").text # ← leaves from your Whisper IPv6
```

That's it. Inside the `with` block the standard proxy env vars point at your local Whisper
proxy, so `requests`, `httpx`, `urllib`, and most libraries "just work"; on exit they're restored.

## API

| Call | Does |
|------|------|
| `register(name, *, new_key=False)` | Create a named agent — a routable `/128`. `new_key=True` mints a new agent **and** its own API key. → `Agent(address, id, name)` |
| `egress(agent=None, *, tier="socks5", set_env=True)` | Context manager: bring up egress bound to your `/128`. Yields `Egress` (`.port`, `.proxy_url`, `.socks_url`, `.proxies`). `tier="wireguard"` for a routed `/128`. |
| `verify(address)` | Keyless — is `address` a real Whisper agent? (DANE + DNSSEC + reverse-DNS + JWS) → `bool` |
| `verify_details(address)` | Keyless — the full verdict (`is_whisper_agent`, `fqdn`, `operator`, `tenant`, `dane_ok`, `jws_ok`, …) or `None` |
| `rdap(address)` | Keyless — the public RDAP record for a `/128`, or `None` |
| `egress_ip()` | Keyless — the IP this process leaves from (a `/128` when routed, else the platform's) → `str` |
| `ip()` | Your current egress IP via the CLI, proving it's your `/128`. → `str` |

Pass the proxy explicitly instead of via env if you prefer:

```python
with egress(set_env=False) as e:
    requests.get(url, proxies=e.proxies)
```

### Keyless / serverless (no CLI)

`verify`, `verify_details`, `rdap`, and `egress_ip` are **keyless** — pure HTTPS, **no `whisper` CLI and no key** — so they run anywhere, including serverless/edge functions:

```python
from whisper_id import verify, rdap
if verify(addr):                       # one HTTPS call; works in AWS Lambda, Cloudflare, etc.
    print(rdap(addr)["name"])
```

`register`, `egress`, and `ip` need the CLI (egress needs the local proxy; register needs your key).

## Requirements

For `register` / `egress` / `ip`, the `whisper` CLI on your `PATH` (this package is a thin,
dependency-free wrapper over it). The keyless calls above need nothing.

```sh
curl get.whisper.online | sh
```

For authenticated calls (`register`, `egress`, `ip`), set `WHISPER_API_KEY` in the environment
or run `whisper login`. `verify` is keyless. (`$WHISPER_BIN` overrides the CLI path.)

## Links

- Site — https://whisper.online
- CLI — https://github.com/whisper-sec/whisper-cli

MIT licensed.

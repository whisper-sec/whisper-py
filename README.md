# whisper-id

A real, routable **IPv6 identity**, **safe egress**, and the full **control plane** for any
Python agent — in two calls.

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

**Control plane** — pure-HTTP (no CLI), one HTTPS call each; needs your key (arg `key=…` or `WHISPER_API_KEY`):

| Call | Does |
|------|------|
| `list_agents(kind="agents")` | Your fleet (`kind` = `agents` \| `identities` \| `records`). → `list[dict]` |
| `policy(default=…, allow=…, block=…)` | Set your DNS resolver policy — or **read** it with no args. → `dict` |
| `logs(agent=…, kind=…, from_=…, to=…, limit=…)` | Recent DNS/conn/alloc activity (`kind` = `dns` \| `conn` \| `alloc`). → `list[dict]` |
| `identity(label, contact_email=…)` | Allocate your own `/128`; release with `identity(release=True, address=…)`. → `dict` |
| `agent(agent_or_address)` | One agent's detail + counters (id, or a `/128` — anything with `:` is an address). → `dict` |
| `revoke(agent)` | Fully revoke an agent (**irreversible**). → `dict` |

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

### Control plane — govern your fleet (no CLI)

With your key set, provision and govern agents over pure HTTPS — no `whisper` binary, so this
works in serverless/edge functions too:

```python
import os
from whisper_id import identity, list_agents, policy, logs, agent, revoke

os.environ["WHISPER_API_KEY"] = "whisper_live_…"   # or pass key=… to any call

a = identity("scout")                              # allocate a routable /128
print(a["address"], a["fqdn"])

policy(default="deny", allow=["api.github.com"])   # deny-by-default DNS policy
print(policy())                                    # read it back → {'default': 'deny', …}

for it in list_agents():                            # your fleet
    print(it["label"], it["address"])

print(agent(a["address"])["dns_queries"])          # per-agent counters
logs(agent=a["address"], kind="dns", from_="-1h")  # recent activity
revoke(a["address"])                               # irreversible
```

Every call is one HTTPS `POST` of `CALL whisper.agents({op, args})` to the control plane; it
raises `WhisperError` with the server's message on failure, and accepts both response shapes.
Set `WHISPER_CONTROL_URL` / `WHISPER_RDAP_URL` to point at a self-hosted deployment.

## Requirements

For `register` / `egress` / `ip`, the `whisper` CLI on your `PATH` (this package is a thin,
dependency-free wrapper over it). The keyless calls above need nothing.

```sh
curl get.whisper.online | sh
```

Set `WHISPER_API_KEY` in the environment (or run `whisper login`) for the CLI-backed calls
(`register`, `egress`, `ip`) and the pure-HTTP control plane (`identity`, `policy`, `logs`,
`agent`, `revoke`, `list_agents` — these take the key directly, no CLI). `verify` / `rdap` are
keyless. (`$WHISPER_BIN` overrides the CLI path.)

## Links

- Site — https://whisper.online
- CLI — https://github.com/whisper-sec/whisper-cli

MIT licensed.

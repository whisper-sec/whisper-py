# whisper-id

Three things for any Python agent, in one dependency-free package: query the **Whisper security graph** (3.6B nodes / 30B relationships, Cypher), give the agent a routable **IPv6 identity** with safe **egress**, and drive the full **control plane**.

```sh
pip install whisper-id            # add [socks] for requests+SOCKS: pip install "whisper-id[socks]"
```

## The security graph (keyless, zero setup)

The Whisper graph knows who operates a host, its threat posture, its look-alikes, the real origins behind a CDN, WHOIS history, and 20+ named investigations. The **direct read verbs run with no key at all** (rate-limited taste, ~100/window). One import, real answers:

```python
from whisper_id import graph

g = graph()                                  # no key needed for the read verbs

g.assess("8.8.8.8")                          # -> [{'host': '8.8.8.8', 'label': 'benign-allowlisted', 'band': 'INFO', ...}]
g.identify("api.openai.com")                 # who operates this host -> vendor + operator roles
g.origins("cloudflare.com")                  # the real origin IPs behind a CDN
g.explain("paypal.com")                      # threat-feed score + why
```

Set `WHISPER_API_KEY` (or `graph("whisper_live_...")`) to lift the rate limit and unlock **raw Cypher** and the **multi-step flows**:

```python
g = graph("whisper_live_...")                # keyed: unlimited + flows + raw Cypher

# raw Cypher, your own query, parameters bound as $-params (never string-built):
g.query("MATCH (h:HOSTNAME {name:$n})-[:RESOLVES_TO]->(ip) RETURN ip.name AS ip LIMIT 5", {"n": "github.com"})

# a named catalog recipe (a multi-step investigation, streamed over SSE):
g.typosquat("paypal.com")                    # look-alike sweep -> registered variants + verdict
g.run_flow("attack-surface", {"domain": "github.com"})   # any flow by its catalog slug

# discover the whole catalog (29 queries + flows) with no key, no network:
for r in g.recipes():
    print(r["method"], "keyless" if r["keyless"] else "keyed", r["docs_url"])
```

Every verb maps to a catalog entry with its own docs page under [whisper.security/docs](https://www.whisper.security/docs) (e.g. [`assess`](https://www.whisper.security/docs/whisper-graph/procedures/assess), [`identify`](https://www.whisper.security/docs/whisper-graph/procedures/identify)); `recipes()` carries the exact `docs_url` for each. The 13 direct reads are keyless; the 15 multi-step flows and the `submit` write channel are keyed. Full query reference: [whisper-catalog](https://github.com/whisper-sec/whisper-catalog).

## Identity + egress

```python
from whisper_id import register, egress
import requests

agent = register("my-bot")                       # a routable Whisper /128 identity
with egress():                                   # route this block through your /128
    requests.get("https://api64.ipify.org").text # leaves from your Whisper IPv6
```

Inside the `with` block the standard proxy env vars point at your local Whisper proxy, so `requests`, `httpx`, `urllib`, and most libraries just work; on exit they're restored. Pass the proxy explicitly if you prefer:

```python
with egress(set_env=False) as e:
    requests.get(url, proxies=e.proxies)
```

## API

| Call | Does |
|------|------|
| `graph(key=None)` | The security-graph namespace. Read verbs (`assess`, `identify`, `explain`, `variants`, `walk`, `origins`, `history`, ...) are **keyless** (rate-limited); `query` (raw Cypher), the flows, and `submit` need a key. `recipes()` lists the whole catalog. |
| `register(name, *, new_key=False)` | Create a named agent: a routable `/128`. `new_key=True` mints a new agent **and** its own API key. -> `Agent(address, id, name)` |
| `egress(agent=None, *, tier="socks5", set_env=True)` | Context manager: bring up egress bound to your `/128`. Yields `Egress` (`.port`, `.proxy_url`, `.socks_url`, `.proxies`). `tier="wireguard"` for a routed `/128`. |
| `verify(address)` | Keyless: is `address` a real Whisper agent? (DANE + DNSSEC + reverse-DNS + JWS) -> `bool` |
| `verify_details(address)` | Keyless: the full verdict (`is_whisper_agent`, `fqdn`, `operator`, `tenant`, `dane_ok`, `jws_ok`, ...) or `None` |
| `rdap(address)` | Keyless: the public RDAP record for a `/128`, or `None` |
| `egress_ip()` / `ip()` | Keyless / CLI: the IP this process leaves from -> `str` |

**Control plane**: pure-HTTP (no CLI), one HTTPS call each; needs your key (arg `key=...` or `WHISPER_API_KEY`):

| Call | Does |
|------|------|
| `list_agents(kind="agents")` | Your fleet (`kind` = `agents` \| `identities` \| `records`). -> `list[dict]` |
| `policy(default=..., allow=..., block=...)` | Set your DNS resolver policy, or **read** it with no args. -> `dict` |
| `logs(agent=..., kind=..., from_=..., to=..., limit=...)` | Recent DNS/conn/alloc activity (`kind` = `dns` \| `conn` \| `alloc`). -> `list[dict]` |
| `identity(label, contact_email=...)` | Allocate your own `/128`; release with `identity(release=True, address=...)`. -> `dict` |
| `agent(agent_or_address)` | One agent's detail + counters (id, or a `/128`, anything with `:` is an address). -> `dict` |
| `revoke(agent)` | Fully revoke an agent (**irreversible**). -> `dict` |

### Keyless / serverless (no key, no CLI)

The graph read verbs plus `verify`, `verify_details`, `rdap`, and `egress_ip` are **keyless**: pure HTTPS, no `whisper` CLI, no key, so they run anywhere including serverless/edge functions:

```python
from whisper_id import graph, verify, rdap

if verify(addr):                       # one HTTPS call; works in AWS Lambda, Cloudflare, etc.
    print(rdap(addr)["name"])
print(graph().assess(addr))            # keyless threat posture, same anywhere
```

`register`, `egress`, and `ip` need the CLI (egress needs the local proxy; register needs your key).

### Control plane: govern your fleet (no CLI)

```python
import os
from whisper_id import identity, list_agents, policy, logs, agent, revoke

os.environ["WHISPER_API_KEY"] = "whisper_live_..."   # or pass key=... to any call

a = identity("scout")                              # allocate a routable /128
policy(default="deny", allow=["api.github.com"])   # deny-by-default DNS policy
logs(agent=a["address"], kind="dns", from_="-1h")  # recent activity
revoke(a["address"])                               # irreversible
```

Every control call is one HTTPS `POST` of `CALL whisper.agents({op, args})`; it raises `WhisperError` with the server's message on failure. Set `WHISPER_CONTROL_URL` / `WHISPER_RDAP_URL` / `WHISPER_FLOW_RUN_URL` to point at a self-hosted deployment.

## Requirements

For `register` / `egress` / `ip`, the `whisper` CLI on your `PATH` (this package is a thin, dependency-free wrapper over it). The graph read verbs and the keyless calls above need nothing.

```sh
curl get.whisper.online | sh
```

Set `WHISPER_API_KEY` in the environment (or run `whisper login`) for the CLI-backed calls, the keyed graph (raw Cypher + flows + `submit`), and the control plane. The graph read verbs, `verify`, and `rdap` are keyless.

## Links

- Site: https://whisper.online
- Docs: https://www.whisper.security/docs
- Query catalog: https://github.com/whisper-sec/whisper-catalog
- CLI: https://github.com/whisper-sec/whisper-cli

MIT licensed.

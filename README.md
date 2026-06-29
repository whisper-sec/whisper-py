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
| `ip()` | Your current egress IP, proving it's your `/128`. → `str` |

Pass the proxy explicitly instead of via env if you prefer:

```python
with egress(set_env=False) as e:
    requests.get(url, proxies=e.proxies)
```

## Requirements

The `whisper` CLI on your `PATH` (this package is a thin, dependency-free wrapper over it):

```sh
curl get.whisper.online | sh
```

For authenticated calls (`register`, `egress`, `ip`), set `WHISPER_API_KEY` in the environment
or run `whisper login`. `verify` is keyless. (`$WHISPER_BIN` overrides the CLI path.)

## Links

- Site — https://whisper.online
- CLI — https://github.com/whisper-sec/whisper-cli

MIT licensed.

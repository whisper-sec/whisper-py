# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
"""whisper-id — a real, routable IPv6 identity and safe egress for any Python agent.

A thin, dependency-free wrapper over the ``whisper`` CLI (https://whisper.online).
The CLI holds the auth, the control plane, and the egress tunnel; this package gives
you a Pythonic ``register()`` / ``egress()`` / ``verify()`` / ``ip()`` surface over it.

    from whisper_id import register, egress

    agent = register("my-bot")            # a routable Whisper /128 identity
    with egress():                        # route this block's traffic via your /128
        import requests
        requests.get("https://api64.ipify.org").text   # leaves from your Whisper IPv6

Requires the ``whisper`` CLI on PATH (``curl get.whisper.online | sh``) and, for the
authenticated calls, ``WHISPER_API_KEY`` in the environment (or a logged-in CLI).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Optional

__all__ = [
    "register",
    "egress",
    "verify",
    "verify_details",
    "rdap",
    "egress_ip",
    "ip",
    # Control plane (pure-HTTP, no CLI) — the key unlocks these (Postel two-tier).
    "list_agents",
    "policy",
    "logs",
    "revoke",
    "identity",
    "agent",
    "Agent",
    "Egress",
    "WhisperError",
    "cli_path",
    "__version__",
]
__version__ = "0.3.0"

# The publicly-announced Whisper agent prefix (AS219419) — used to liberally recover a
# /128 from any control-plane envelope shape (Postel: be liberal in what we accept).
_ADDR_RE = re.compile(r"2a04:2a01:[0-9a-fA-F:]{2,}")
_HOSTPORT_RE = re.compile(r"127\.0\.0\.1:(\d{2,5})")
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy")

# Keyless public endpoint base (the same surface the CLI uses, server-side). Overridable for
# testing/self-host via $WHISPER_RDAP_URL. These calls carry NO key and need NO `whisper` CLI —
# they work in any runtime that can make an HTTPS request (serverless, edge, browsers).
def _rdap_base() -> str:
    return (os.environ.get("WHISPER_RDAP_URL") or "https://rdap.whisper.online").rstrip("/")


# Control-plane endpoint — the ONE authenticated verb `whisper.agents({op,args})`. Pure
# HTTPS (stdlib urllib, no `whisper` CLI); the key travels ONLY in the X-API-Key header.
# Overridable via $WHISPER_CONTROL_URL for self-host/pre-prod (Postel: liberal in, sane default).
def _control_url() -> str:
    return (os.environ.get("WHISPER_CONTROL_URL") or "https://graph.whisper.security/api/query").strip()


class WhisperError(RuntimeError):
    """A ``whisper`` CLI invocation failed, or the CLI is not installed."""


@dataclass(frozen=True)
class Agent:
    """A Whisper agent — a routable IPv6 /128 that is both the identity and the auth."""

    address: str
    id: Optional[str] = None
    name: Optional[str] = None


@dataclass
class Egress:
    """A live local egress proxy bound to your /128."""

    port: int
    address: Optional[str] = None

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def socks_url(self) -> str:
        return f"socks5h://127.0.0.1:{self.port}"

    @property
    def proxies(self) -> dict:
        """A requests/httpx-style proxies mapping for explicit per-call use."""
        return {"http": self.proxy_url, "https": self.proxy_url}


def cli_path() -> str:
    """Locate the ``whisper`` binary (``$WHISPER_BIN`` overrides ``PATH``)."""
    found = os.environ.get("WHISPER_BIN") or shutil.which("whisper")
    if not found:
        raise WhisperError(
            "the `whisper` CLI was not found on PATH. Install it with "
            "`curl get.whisper.online | sh` (see https://whisper.online)."
        )
    return found


def _run(args, *, timeout: int = 120, check: bool = True) -> subprocess.CompletedProcess:
    cmd = [cli_path(), *args]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:  # pragma: no cover - timing dependent
        raise WhisperError(f"`whisper {' '.join(args)}` timed out after {timeout}s") from exc
    if check and proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
        raise WhisperError(f"`whisper {' '.join(args)}` failed: {detail}")
    return proc


def _run_json(args, **kw):
    proc = _run(["--json", *args], **kw)
    out = (proc.stdout or "").strip()
    try:
        return json.loads(out)
    except json.JSONDecodeError as exc:
        raise WhisperError(
            f"could not parse JSON from `whisper {' '.join(args)}`: {out[:200]!r}"
        ) from exc


def _first_addr(obj) -> Optional[str]:
    """Pull the first Whisper /128 out of an arbitrary JSON envelope, or None."""
    match = _ADDR_RE.search(json.dumps(obj))
    return match.group(0) if match else None


def _get(obj, *keys):
    """Liberally fetch the first present key (one level deep), or None."""
    if isinstance(obj, dict):
        for key in keys:
            if obj.get(key):
                return obj[key]
        for value in obj.values():
            if isinstance(value, dict):
                got = _get(value, *keys)
                if got:
                    return got
    return None


def register(name: str, *, new_key: bool = False, timeout: int = 120) -> Agent:
    """Create a named agent identity — a routable Whisper IPv6 /128.

    Drives ``whisper create --name <name>``. Pass ``new_key=True`` to mint a brand-new
    agent *with its own API key* (``op:register``). Requires ``WHISPER_API_KEY`` (or a
    logged-in CLI), except ``new_key=True`` which bootstraps its own key.
    """
    if not name or not name.strip():
        raise WhisperError("register() needs a non-empty agent name")
    args = ["create", "--name", name]
    if new_key:
        args.append("--register")
    env = _run_json(args, timeout=timeout)
    addr = _first_addr(env)
    if not addr:
        raise WhisperError(f"no /128 returned by `whisper create`: {json.dumps(env)[:200]}")
    return Agent(address=addr, id=_get(env, "id", "agent_id", "agentId"), name=name)


@contextmanager
def egress(
    agent: Optional[str] = None,
    *,
    tier: str = "socks5",
    set_env: bool = True,
    timeout: int = 90,
) -> Iterator[Egress]:
    """Bring egress up bound to your /128 and route this block's traffic through it.

    Drives ``whisper connect --ensure`` (an idempotent, detached local proxy). While the
    ``with`` block is active the standard proxy env vars (HTTP_PROXY/HTTPS_PROXY/ALL_PROXY)
    point at the local proxy; on exit they are restored to their prior values. The proxy
    daemon itself is left running (it is shared and idempotent).

        with egress() as e:
            requests.get("https://api64.ipify.org")          # via your /128
            requests.get(url, proxies=e.proxies)             # or pass explicitly

    Set ``set_env=False`` to only start the proxy and receive the :class:`Egress` handle
    without mutating the process environment.
    """
    args = ["connect", "--ensure", "--tier", tier]
    if agent:
        args += ["--agent", agent]
    proc = _run(args, timeout=timeout)
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    match = _HOSTPORT_RE.search(text)
    if not match:
        raise WhisperError(
            f"could not determine the local proxy port from `whisper connect`: {text.strip()[:200]!r}"
        )
    handle = Egress(port=int(match.group(1)), address=agent)
    saved = {k: os.environ.get(k) for k in _PROXY_VARS} if set_env else {}
    try:
        if set_env:
            os.environ["HTTP_PROXY"] = os.environ["http_proxy"] = handle.proxy_url
            os.environ["HTTPS_PROXY"] = os.environ["https_proxy"] = handle.proxy_url
            os.environ["ALL_PROXY"] = os.environ["all_proxy"] = handle.socks_url
        yield handle
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _http_get(url: str, *, timeout: int) -> tuple[int, bytes]:
    """GET a keyless public endpoint; return (status, body). No CLI, no key, no auth header."""
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/rdap+json, application/json, */*", "User-Agent": f"whisper-id-py/{__version__}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only, our endpoint)
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:  # 404 = clean "not an agent", etc. — a real, decodable answer
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        raise WhisperError(f"could not reach {url}: {exc.reason}") from exc


def verify(address: str, *, timeout: int = 60) -> bool:
    """Return ``True`` iff ``address`` is a real Whisper agent.

    **Keyless and CLI-free** — a single HTTPS GET to the public ``/verify-identity`` endpoint,
    which runs the full server-side trust chain (DANE + DNSSEC + reverse-DNS + JWS). Works in
    any runtime (serverless, edge, browser). 200 ⇒ agent; 404 ⇒ not. Never raises on a negative
    verdict (returns ``False``); raises ``WhisperError`` only if the endpoint is unreachable.
    """
    return verify_details(address, timeout=timeout) is not None


def verify_details(address: str, *, timeout: int = 60) -> Optional[dict]:
    """Return the full verify verdict (``is_whisper_agent``, ``fqdn``, ``operator``, ``tenant``,
    ``dane_ok``, ``jws_ok``, ``evidence``, …) for a real Whisper agent, else ``None``. Keyless, CLI-free.
    """
    if not address or not address.strip():
        raise WhisperError("verify() needs an address")
    url = f"{_rdap_base()}/verify-identity?ip={urllib.parse.quote(address.strip(), safe='')}"
    status, body = _http_get(url, timeout=timeout)
    if status != 200:
        return None
    try:
        v = json.loads(body)
    except json.JSONDecodeError:
        return None
    return v if v.get("is_whisper_agent") else None


def rdap(address: str, *, timeout: int = 60) -> Optional[dict]:
    """Return the public RDAP record for a Whisper ``/128`` (handle, name, status, entities, …),
    or ``None`` if there is no record. Keyless, CLI-free.
    """
    if not address or not address.strip():
        raise WhisperError("rdap() needs an address")
    url = f"{_rdap_base()}/ip/{urllib.parse.quote(address.strip(), safe=':')}"  # path segment — keep literal colons
    status, body = _http_get(url, timeout=timeout)
    if status != 200:
        return None
    try:
        return json.loads(body)
    except json.JSONDecodeError:
        return None


def egress_ip(*, timeout: int = 60) -> str:
    """Return the caller's current egress IP as seen by Whisper (what this process leaves from).

    Keyless, CLI-free — useful inside a function/edge runtime to confirm which address you're
    egressing from (a Whisper ``/128`` when routed through ``whisper connect``, else the
    platform's own IP). Distinct from :func:`ip`, which uses the CLI to prove *your* ``/128``.
    """
    status, body = _http_get(f"{_rdap_base()}/egress-ip", timeout=timeout)
    if status != 200:
        raise WhisperError(f"egress-ip endpoint returned HTTP {status}")
    try:
        return json.loads(body).get("ip", "")
    except json.JSONDecodeError:
        return ""


def ip(*, timeout: int = 60) -> str:
    """Return the current egress IP, proving it is your Whisper /128 (drives ``whisper ip``)."""
    env = _run_json(["ip"], timeout=timeout)
    return _get(env, "ip", "agent") or _first_addr(env) or ""


# ---------------------------------------------------------------------------------------
# Control plane — pure-HTTP governance (no `whisper` CLI). The keyless calls above give
# everyone real value with no key; supply your ``whisper_live_`` key (arg or
# ``WHISPER_API_KEY``) and these unlock the full control plane (Postel two-tier). Every
# call is one HTTPS POST of the single verb ``CALL whisper.agents({op, args})`` to
# ``graph.whisper.security`` — stdlib ``urllib`` only, no extra dependencies.
# ---------------------------------------------------------------------------------------

def _escape_cypher(s: str) -> str:
    """Render ``s`` safe inside a single-quoted Cypher literal: double every backslash then
    every single quote (order matters), so a value can never break out of the map
    (``Tim O'Reilly`` → ``Tim O''Reilly``). Conservative-emit: injection-proof by construction.
    """
    return s.replace("\\", "\\\\").replace("'", "''")


def _cypher_lit(value) -> str:
    """Render a Python value as a deterministic Cypher literal."""
    if value is None:
        return "null"
    if isinstance(value, bool):  # bool BEFORE int — bool is an int subclass in Python
        return "true" if value else "false"
    if isinstance(value, str):
        return "'" + _escape_cypher(value) + "'"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)  # shortest round-tripping decimal
    if isinstance(value, dict):
        return _cypher_map(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_cypher_lit(e) for e in value) + "]"
    return "'" + _escape_cypher(str(value)) + "'"  # anything else → quoted string, never injects


def _cypher_map(m: dict) -> str:
    """Render a map literal with keys in SORTED order so the query is byte-stable."""
    if not m:
        return "{}"
    return "{" + ",".join(f"{k}:{_cypher_lit(m[k])}" for k in sorted(m)) + "}"


def _build_agents_query(op: str, args: Optional[dict] = None) -> str:
    """Build the one control verb: ``CALL whisper.agents({op:'<op>', args:{…}})``."""
    inner = _cypher_map(args) if args else "{}"
    return f"CALL whisper.agents({{op:'{_escape_cypher(op)}', args:{inner}}})"


def _http_post(url: str, payload: bytes, *, api_key: str, timeout: int) -> tuple[int, bytes]:
    """POST a JSON control query; return ``(status, body)``.

    The key travels ONLY in the ``X-API-Key`` header — never the body, never the URL, never
    a log line. A 4xx/5xx still carries a decodable problem body, so we read it (rather than
    raising) and let the caller surface the server's ``detail``.
    """
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": api_key,
            "User-Agent": f"whisper-id-py/{__version__}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https, our endpoint)
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:  # a problem object with a helpful `detail`
        return exc.code, exc.read()
    except urllib.error.URLError as exc:
        raise WhisperError(f"could not reach the Whisper control plane: {exc.reason}") from exc


def _decode_envelope(body: bytes, http_status: int):
    """Normalise a reply into ``(ok, status, result, error)``. LIBERAL in what it accepts —
    handles BOTH wire shapes the control plane may return:

      * flat: ``{ok, status, result, error}``
      * live: ``{columns, rows:[{op, ok, status, result, error}]}`` (procedure-row table)

    plus a bare RFC-7807 problem object on a 4xx. ``result`` is a ``{columns, rows}`` map.
    """
    try:
        data = json.loads(body or b"")
    except (json.JSONDecodeError, ValueError):
        return False, http_status, None, {"status": http_status, "detail": "control plane returned a non-JSON reply"}

    if isinstance(data, dict):
        # Flat shape: an explicit top-level ok flag.
        if "ok" in data:
            return bool(data.get("ok")), int(data.get("status") or http_status), data.get("result"), data.get("error")
        # Live shape: a procedure-row table; rows[0] carries the per-op envelope.
        rows = data.get("rows")
        if isinstance(rows, list) and rows:
            row0 = rows[0]
            if isinstance(row0, list):  # positional row aligned to columns
                row0 = dict(zip(data.get("columns") or [], row0))
            if isinstance(row0, dict) and ("ok" in row0 or "result" in row0 or "error" in row0):
                return (
                    bool(row0.get("ok", True)),
                    int(row0.get("status") or http_status),
                    row0.get("result"),
                    row0.get("error"),
                )
            return http_status < 400, http_status, data, None  # rows but no envelope → data is the table
        # A bare problem object (detail/title/type) with no ok/rows.
        if any(k in data for k in ("detail", "title", "type", "error")):
            err = data.get("error") if isinstance(data.get("error"), dict) else data
            return False, http_status, None, err

    # Shapeless-but-valid (or empty) → success with an empty result (read ops fail open).
    return http_status < 400, http_status, None, None


def _records(result: Optional[dict]) -> list:
    """Turn a ``{columns, rows}`` result into a list of column-keyed dicts (rows may already
    be dicts — accept either, Postel-liberal)."""
    if not isinstance(result, dict):
        return []
    cols = result.get("columns") or []
    out = []
    for row in result.get("rows") or []:
        if isinstance(row, dict):
            out.append(row)
        elif isinstance(row, (list, tuple)):
            out.append({cols[i]: row[i] for i in range(min(len(cols), len(row)))})
    return out


def _problem_detail(error: Optional[dict], status: int) -> str:
    """The single most-helpful line from a problem object: detail → title → type → status."""
    if isinstance(error, dict):
        for key in ("detail", "title", "type"):
            val = error.get(key)
            if val:
                return str(val)
    return f"control plane returned status {status}" if status else "control plane reported failure"


def _api_key(key: Optional[str]) -> str:
    resolved = (key or os.environ.get("WHISPER_API_KEY") or "").strip()
    if not resolved:
        raise WhisperError(
            "no API key — pass key='whisper_live_…' or set WHISPER_API_KEY. The control-plane "
            "calls (list_agents/policy/logs/revoke/identity/agent) act on your own tenant and "
            "need your key; the keyless calls (verify/rdap) do not."
        )
    return resolved


def _control(op: str, args: Optional[dict] = None, *, key: Optional[str], timeout: int) -> list:
    """POST ``CALL whisper.agents({op, args})`` and return the result as a list of records,
    or raise :class:`WhisperError` carrying the server's ``detail`` on ``ok:false``."""
    payload = json.dumps({"query": _build_agents_query(op, args)}).encode("utf-8")
    status, body = _http_post(_control_url(), payload, api_key=_api_key(key), timeout=timeout)
    ok, resolved_status, result, error = _decode_envelope(body, status)
    if not ok:
        raise WhisperError(_problem_detail(error, resolved_status))
    return _records(result)


def list_agents(kind: str = "agents", *, key: Optional[str] = None, timeout: int = 60) -> list:
    """List your tenant's fleet (``op:list``). **Pure-HTTP, key required.**

    ``kind`` = ``agents`` (default) | ``identities`` | ``records``. Returns a list of item
    maps — each ``{label, fqdn, address, agent, created, state}`` (the outer ``{kind,item}``
    wrapper is unwrapped for you).
    """
    recs = _control("list", {"kind": kind}, key=key, timeout=timeout)
    return [rec.get("item", rec) if isinstance(rec, dict) else rec for rec in recs]


def policy(
    default: Optional[str] = None,
    allow: Optional[list] = None,
    block: Optional[list] = None,
    *,
    key: Optional[str] = None,
    timeout: int = 60,
) -> dict:
    """Read or set your per-tenant DNS resolver policy (``op:policy``). **Pure-HTTP, key required.**

    Call with **no arguments to READ** the current policy. To SET it, pass any of
    ``default`` (``'allow'`` | ``'deny'``), ``allow`` (a list of names), ``block`` (a list of
    names). Returns the resulting policy as a ``{key: value}`` dict either way.
    """
    args: dict = {}
    if default is not None:
        args["default"] = default
    if allow is not None:
        args["allow"] = list(allow)
    if block is not None:
        args["block"] = list(block)
    recs = _control("policy", args, key=key, timeout=timeout)
    return {rec.get("key"): rec.get("value") for rec in recs if isinstance(rec, dict) and rec.get("key") is not None}


def logs(
    agent: Optional[str] = None,
    kind: Optional[str] = None,
    *,
    from_: Optional[object] = None,
    to: Optional[object] = None,
    limit: Optional[int] = None,
    key: Optional[str] = None,
    timeout: int = 60,
) -> list:
    """Recent activity from warm storage (``op:logs``). **Pure-HTTP, key required.**

    Optional narrows: ``agent`` (id or ``/128``), ``kind`` = ``dns`` | ``conn`` | ``alloc``
    (omit for all), ``from_``/``to`` (epoch-ms, RFC-3339, or relative like ``'-1h'`` — sent as
    the wire ``from``/``to``), ``limit`` (default 1000, cap 10000). Returns a list of event
    records (empty when the window has none).
    """
    args: dict = {}
    if agent:
        args["agent"] = agent
    if kind:
        args["kind"] = kind
    if from_ is not None:
        args["from"] = from_  # `from` is a Python keyword → accept `from_`, emit the wire `from`
    if to is not None:
        args["to"] = to
    if limit is not None:
        args["limit"] = limit
    return _control("logs", args, key=key, timeout=timeout)


def revoke(agent: str, *, key: Optional[str] = None, timeout: int = 60) -> dict:
    """Fully revoke an agent (``op:revoke``) — **IRREVERSIBLE**. **Pure-HTTP, key required.**

    ``agent`` is the agent id or its ``/128`` address. Returns the status record.
    """
    if not agent or not str(agent).strip():
        raise WhisperError("revoke() needs an agent id or /128 address")
    recs = _control("revoke", {"agent": str(agent).strip()}, key=key, timeout=timeout)
    return recs[0] if recs else {}


def identity(
    label: Optional[str] = None,
    contact_email: Optional[str] = None,
    *,
    release: bool = False,
    address: Optional[str] = None,
    key: Optional[str] = None,
    timeout: int = 60,
) -> dict:
    """Allocate — or release — your own ``/128`` identity (``op:identity``). **Pure-HTTP, key required.**

    Allocate: ``identity('my-label'[, contact_email='you@example.com'])`` → a record with
    ``agent, address, fqdn, ptr, state``. Release (irreversible):
    ``identity(release=True, address='<the /128>')``.
    """
    args: dict = {}
    if release:
        if not address or not str(address).strip():
            raise WhisperError("identity(release=True) needs address='<the /128 to release>'")
        args["release"] = True
        args["address"] = str(address).strip()
    else:
        if not label or not str(label).strip():
            raise WhisperError("identity() needs a non-empty label (or release=True with an address)")
        args["label"] = str(label).strip()
        if contact_email:
            args["contact_email"] = contact_email
    recs = _control("identity", args, key=key, timeout=timeout)
    return recs[0] if recs else {}


def agent(agent_or_address: str, *, key: Optional[str] = None, timeout: int = 60) -> dict:
    """One agent's detail and counters (``op:agent``). **Pure-HTTP, key required.**

    Accepts either selector (liberal): an agent id, or a ``/128`` address — a value
    containing ``:`` is treated as an address. Returns the detail record (``address, fqdn,
    ptr, label, state, dns_queries, bytes_up, …``).
    """
    selector = (agent_or_address or "").strip()
    if not selector:
        raise WhisperError("agent() needs an agent id or /128 address")
    args = {"address": selector} if ":" in selector else {"agent": selector}
    recs = _control("agent", args, key=key, timeout=timeout)
    return recs[0] if recs else {}

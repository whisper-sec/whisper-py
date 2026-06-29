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
    "Agent",
    "Egress",
    "WhisperError",
    "cli_path",
    "__version__",
]
__version__ = "0.2.0"

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

# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
"""Generate whisper_id/graph.py from the Whisper query catalog (sdk-methods.json).

One typed method per catalog entry, camelCase id, keyed. `direct` entries POST their
Cypher to the graph endpoint; `flow` entries are stubbed with a clear runs-via-workflow
note (they need the workflow runner, not a single /api/query POST). Run:

    python scripts/gen_graph.py path/to/sdk-methods.json

With no argument it looks for ../whisper-catalog/sdk-methods.json next to this repo.
The generated module keeps the SDK in lockstep with the catalog and stays em-dash-free.
"""
from __future__ import annotations

import json
import os
import sys


def _sanitize(text: str) -> str:
    """Strip non-ASCII typography so the emitted module is plain ASCII, em-dash-free."""
    replace = {
        "\u2014": " - ",  # em dash
        "\u2013": " - ",  # en dash
        "\u2018": "'",   # left single quote
        "\u2019": "'",   # right single quote
        "\u201c": '"',   # left double quote
        "\u201d": '"',   # right double quote
        "\u2026": "...",  # ellipsis
        "\u00a0": " ",    # non-breaking space
    }
    for bad, good in replace.items():
        text = text.replace(bad, good)
    return text


def _slug(run_via: str) -> str:
    """'run_workflow (attack-path)' -> 'attack-path'."""
    start = run_via.find("(")
    end = run_via.rfind(")")
    if start != -1 and end != -1 and end > start:
        return run_via[start + 1 : end].strip()
    return run_via.strip()


HEADER = '''# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
#
# GENERATED FILE - do not edit by hand.
# Regenerate with: python scripts/gen_graph.py (from the whisper-py repo root).
# Source of truth: the Whisper query catalog (sdk-methods.json / catalog.json).
"""The keyed Whisper graph namespace: one typed method per catalog query.

Everything here is Cypher, and Cypher needs an API key (Kaveh's rule), so the whole
namespace is KEYED. It reuses the exact keyed transport of the control plane: one HTTPS
POST to ``graph.whisper.security/api/query`` with the key ONLY in the ``X-API-Key`` header
(via the shared ``_api_key`` gate), never in the body or the URL. This is the same auth
path as ``list_agents``/``policy``/``logs``; there is no second auth mechanism.

    from whisper_id import graph

    g = graph()                          # key from WHISPER_API_KEY (or graph(key))
    g.identify("api.openai.com")         # -> [{host, vendor_id, canonical_name, ...}]
    g.assess("8.8.8.8")                  # -> [{host, label, band, ...}]
    g.query("CALL db.schema()")          # raw escape hatch, any read Cypher

``direct`` verbs run their Cypher against the graph and return a list of column-keyed
dicts. ``flow`` verbs are multi-step read flows driven by the workflow runner, not a
single ``/api/query`` POST, so they are stubbed here and raise ``NotImplementedError``
with a pointer at the runner; use :meth:`Graph.query` for their individual direct steps.

Wire shape (keyed): request ``{"query": <cypher>, "parameters": {...}}``; reply
``{"columns": [...], "rows": [{col: val, ...}], "statistics": {...}}`` with rows as
objects keyed by column name. Dependency posture is unchanged: stdlib ``urllib`` only.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import WhisperError, _api_key, _control_url, _http_post, _problem_detail, _records

import json

__all__ = ["Graph"]

_FLOW_RUNNER_NOTE = (
    "{method}() is a multi-step read flow. It runs via the Whisper workflow runner "
    "({run_via}), not a single POST to /api/query, so it is not callable through this "
    "keyed graph client yet. Use graph.query() for its individual direct Cypher steps, "
    "or the console/agent run endpoint for the full flow."
)


def _graph_query(
    cypher: str,
    params: Optional[Dict[str, Any]],
    *,
    api_key: str,
    timeout: int,
) -> List[Dict[str, Any]]:
    """POST one read Cypher to the keyed graph endpoint and return column-keyed dicts.

    Conservative-emit: sends exactly ``{"query": cypher, "parameters": params or {}}``.
    Liberal-accept: reads the ``{columns, rows, statistics}`` envelope, passes object
    rows through and zips positional rows onto the columns, and on a 4xx/5xx problem
    body raises :class:`WhisperError` carrying the server's ``detail``. The key travels
    only in the ``X-API-Key`` header (via the shared ``_http_post``), never the body.
    """
    payload = json.dumps({"query": cypher, "parameters": params or {}}).encode("utf-8")
    status, body = _http_post(_control_url(), payload, api_key=api_key, timeout=timeout)
    try:
        data = json.loads(body or b"")
    except (json.JSONDecodeError, ValueError):
        raise WhisperError(f"the Whisper graph returned a non-JSON reply (status {status})")
    if isinstance(data, dict):
        error = data.get("error")
        if status >= 400 or error:
            if isinstance(error, dict):
                problem = error
            elif error:
                problem = {"detail": str(error)}
            else:
                problem = data
            raise WhisperError(_problem_detail(problem, status))
        return _records(data)
    raise WhisperError(f"the Whisper graph returned an unexpected reply (status {status})")


class Graph:
    """A keyed client for the Whisper security graph (Cypher, so a key is required).

    The key is resolved lazily through the shared ``_api_key`` gate, so a missing key
    raises the same helpful ``WhisperError`` as the rest of the control plane, at call
    time. Pass it explicitly (``Graph("whisper_live_...")``) or set ``WHISPER_API_KEY``.
    """

    def __init__(self, api_key: Optional[str] = None, *, timeout: int = 60) -> None:
        self._api_key = api_key
        self._timeout = timeout

    def _q(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        return _graph_query(cypher, params, api_key=_api_key(self._api_key), timeout=self._timeout)

    def query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Run any read Cypher directly (the raw escape hatch), keyed like every verb.

        ``params`` are sent as the server-side ``$parameters`` map. Returns a list of
        column-keyed dicts. This is the general form the typed verbs below specialise.
        """
        return self._q(cypher, params)
'''


def _emit_method(m: dict) -> str:
    name = m["method"]
    mode = m["mode"]
    summary = _sanitize(m.get("summary") or "")
    returns = m.get("returns") or []
    params = m.get("params") or []
    cols = ", ".join(returns) if returns else "(none declared)"

    # Signature params: every catalog input becomes a typed, defaulted argument.
    sig_parts = ["self"]
    for p in params:
        default = p.get("default", "")
        sig_parts.append(f"{p['name']}: str = {default!r}")
    sig = ", ".join(sig_parts)

    lines = [f"    def {name}({sig}) -> List[Dict[str, Any]]:"]

    if mode == "direct":
        doc = [f'        """{summary}', ""]
        doc.append("        Direct Cypher against the keyed graph (an API key is required).")
        doc.append(f"        Columns: {cols}.")
        doc.append('        """')
        lines.extend(doc)
        cypher = m["cypher"]
        if params:
            pairs = ", ".join(f"{p['name']!r}: {p['name']}" for p in params)
            argmap = "{" + pairs + "}"
        else:
            argmap = "{}"
        lines.append(f"        return self._q({cypher!r}, {argmap})")
    else:  # flow
        run_via = _sanitize(m.get("runVia") or "")
        doc = [f'        """{summary}', ""]
        doc.append(f"        Multi-step read flow. Runs via the Whisper workflow runner ({run_via}),")
        doc.append("        not a single /api/query POST, so it is stubbed (raises NotImplementedError).")
        doc.append(f"        Columns (anchor step): {cols}.")
        doc.append('        """')
        lines.extend(doc)
        lines.append(
            f"        raise NotImplementedError("
            f'_FLOW_RUNNER_NOTE.format(method="{name}", run_via="{run_via}"))'
        )
    return "\n".join(lines)


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    if len(sys.argv) > 1:
        src = sys.argv[1]
    else:
        src = os.path.join(os.path.dirname(repo), "whisper-catalog", "sdk-methods.json")
    with open(src, "r", encoding="utf-8") as fh:
        catalog = json.load(fh)
    methods = catalog["methods"]

    body = [HEADER]
    for m in methods:
        body.append("")
        body.append(_emit_method(m))
    body.append("")

    out = os.path.join(repo, "whisper_id", "graph.py")
    text = "\n".join(body)
    text = _sanitize(text)
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {out} ({len(methods)} methods from {src})")


if __name__ == "__main__":
    main()

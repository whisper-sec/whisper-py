# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
"""Generate whisper_id/graph.py from the Whisper query catalog (sdk-methods.json).

One typed method per catalog entry, camelCase id, keyed. `direct` entries POST their
Cypher to the graph endpoint; `flow` entries run keyed via the gallery flow runner
(one POST to console.whisper.security/api/gallery/run, consumed as an SSE stream).
Every method's docstring links its docs page (docsBase + docPath). Run:

    python scripts/gen_graph.py path/to/sdk-methods.json

With no argument it looks for ../whisper-catalog/sdk-methods.json next to this repo.
The generated module keeps the SDK in lockstep with the catalog and stays em-dash-free.
"""
from __future__ import annotations

import json
import os
import re
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


def _slug(m: dict) -> str:
    """The flow's catalog id: flowRun.bodyShape.slug, else parsed from runVia."""
    flow_run = m.get("flowRun") or {}
    slug = (flow_run.get("bodyShape") or {}).get("slug")
    if slug:
        return slug
    run_via = m.get("runVia") or ""
    start = run_via.find("(")
    end = run_via.rfind(")")
    if start != -1 and end != -1 and end > start:
        return run_via[start + 1 : end].strip()
    return run_via.strip()


def _docs_url(m: dict, docs_base: str) -> str:
    """The entry's docs page: the prebuilt docsUrl, else docsBase + docPath."""
    return m.get("docsUrl") or (docs_base.rstrip("/") + (m.get("docPath") or ""))


def _sig_param(p: dict) -> str:
    """One typed, defaulted signature argument for a catalog param."""
    name = p["name"]
    default = p.get("default")
    if default is None:
        kind = p.get("kind") or "string"
        annot = {"number": "Optional[float]", "any": "Optional[Any]"}.get(kind, "Optional[str]")
        return f"{name}: {annot} = None"
    return f"{name}: {type(default).__name__} = {default!r}"


HEADER = '''# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
#
# GENERATED FILE - do not edit by hand.
# Regenerate with: python scripts/gen_graph.py (from the whisper-py repo root).
# Source of truth: the Whisper query catalog (sdk-methods.json / catalog.json).
"""The keyed Whisper graph namespace: one typed method per catalog query.

Everything here is Cypher (or a flow of Cypher), and Cypher needs an API key (Kaveh's
rule), so the whole namespace is KEYED. It reuses the exact keyed transport of the
control plane: the key travels ONLY in the ``X-API-Key`` header (via the shared
``_api_key`` gate), never in the body or the URL. This is the same auth path as
``list_agents``/``policy``/``logs``; there is no second auth mechanism.

    from whisper_id import graph

    g = graph()                          # key from WHISPER_API_KEY (or graph(key))
    g.identify("api.openai.com")         # -> [{host, vendor_id, canonical_name, ...}]
    g.assess("8.8.8.8")                  # -> [{host, label, band, ...}]
    g.typosquat("paypal.com")            # multi-step flow -> {steps, context, output}
    g.query("CALL db.schema()")          # raw escape hatch, any read Cypher

``direct`` verbs POST their Cypher to ``graph.whisper.security/api/query`` and return a
list of column-keyed dicts. ``flow`` verbs are multi-step reads run by the gallery flow
runner: one keyed POST to ``console.whisper.security/api/gallery/run``, consumed as a
Server-Sent-Events stream. They return the flow result (``steps``, ``context``,
``output``, ``totalLatencyMs``) and stream progress through ``on_event``;
:meth:`Graph.run_flow` runs any flow by its catalog slug. Every method's docstring links
its docs page under https://www.whisper.security/docs.

Wire shape (direct): request ``{"query": <cypher>, "parameters": {...}}``; reply
``{"columns": [...], "rows": [{col: val, ...}], "statistics": {...}}`` with rows as
objects keyed by column name. Dependency posture is unchanged: stdlib ``urllib`` only.
"""
from __future__ import annotations

from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from . import WhisperError, __version__, _api_key, _control_url, _http_post, _problem_detail, _records

import json
import os
import urllib.error
import urllib.request

__all__ = ["Graph"]


def _flow_run_url() -> str:
    """The gallery flow-run endpoint (SSE). Overridable via $WHISPER_FLOW_RUN_URL for
    self-host/pre-prod, same pattern as ``_control_url`` (Postel: liberal in, sane default)."""
    return (os.environ.get("WHISPER_FLOW_RUN_URL") or "https://console.whisper.security/api/gallery/run").strip()


def _drop_none(params: Dict[str, Any]) -> Dict[str, Any]:
    """Omit None-valued arguments: the graph API wants absent, not null (conservative-emit)."""
    return {k: v for k, v in params.items() if v is not None}


def _sse_post(url: str, payload: bytes, *, api_key: str, timeout: int) -> Iterator[Tuple[str, str]]:
    """POST one JSON body and stream the Server-Sent-Events reply as (event, data) pairs.

    Conservative-emit: the key travels only in the ``X-API-Key`` header. Liberal-accept:
    tolerates ``\\r\\n`` line endings, multi-line ``data:`` fields (joined with newlines),
    comment lines, and a missing ``event:`` name (yielded as ``message`` per the SSE spec).
    A 4xx/5xx problem body raises :class:`WhisperError` carrying the server's ``detail``.
    """
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "X-API-Key": api_key,
            "User-Agent": f"whisper-id-py/{__version__}",
        },
    )
    try:
        resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 (https, our endpoint)
    except urllib.error.HTTPError as exc:
        body = exc.read()
        try:
            problem = json.loads(body or b"")
        except (json.JSONDecodeError, ValueError):
            problem = {"detail": (body or b"").decode("utf-8", "replace").strip()[:200] or None}
        raise WhisperError(_problem_detail(problem if isinstance(problem, dict) else None, exc.code))
    except urllib.error.URLError as exc:
        raise WhisperError(f"could not reach the Whisper flow runner: {exc.reason}") from exc
    with resp:
        event: Optional[str] = None
        data: List[str] = []
        for raw in resp:
            line = raw.decode("utf-8", "replace").rstrip("\\r\\n")
            if not line:
                if event or data:
                    yield event or "message", "\\n".join(data)
                event, data = None, []
            elif line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
            # other SSE fields (id:, retry:, : comments) are ignored, liberal-accept
        if event or data:
            yield event or "message", "\\n".join(data)


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

        See: https://www.whisper.security/docs/cypher-api
        """
        return self._q(cypher, params)

    def run_flow(
        self,
        slug: str,
        inputs: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        *,
        on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None,
    ) -> Dict[str, Any]:
        """Run any catalog flow by its slug via the gallery flow runner (keyed, SSE).

        POSTs ``{"slug", "inputs", "params"}`` to the flow-run endpoint and consumes the
        Server-Sent-Events stream: per-step tables accumulate under ``steps``, the final
        ``complete`` event's per-step rows land in ``context``, and the formatted report
        (when the flow presents one) in ``output``. ``on_event(name, data)`` fires for
        every streamed event as it arrives (start / step-start / step / graph / prune /
        complete). A streamed ``error`` event raises :class:`WhisperError`.

        See: https://www.whisper.security/docs/recipes
        """
        payload = json.dumps(
            {"slug": slug, "inputs": inputs or {}, "params": params or {}}
        ).encode("utf-8")
        result: Dict[str, Any] = {
            "slug": slug, "steps": [], "context": {}, "output": None, "totalLatencyMs": None,
        }
        events = _sse_post(_flow_run_url(), payload, api_key=_api_key(self._api_key), timeout=self._timeout)
        for name, data in events:
            try:
                event = json.loads(data) if data else {}
            except (json.JSONDecodeError, ValueError):
                event = {"raw": data}
            if not isinstance(event, dict):
                event = {"value": event}
            if on_event is not None:
                on_event(name, event)
            if name == "step":
                result["steps"].append(event)
                if event.get("id") == "__present" and event.get("output") is not None:
                    result["output"] = event["output"]
            elif name == "complete":
                result["context"] = event.get("context") or {}
                if event.get("totalLatencyMs") is not None:
                    result["totalLatencyMs"] = event["totalLatencyMs"]
            elif name == "error":
                detail = event.get("message") or data or "unknown error"
                raise WhisperError(f"flow '{slug}' failed: {detail}")
        return result
'''


def _emit_method(m: dict, docs_base: str) -> str:
    name = m["method"]
    mode = m["mode"]
    summary = _sanitize(m.get("summary") or "")
    returns = m.get("returns") or []
    params = m.get("params") or []
    cols = ", ".join(returns) if returns else "(none declared)"
    docs_url = _docs_url(m, docs_base)

    # Signature params: every catalog input becomes a typed, defaulted argument.
    sig_parts = ["self"]
    for p in params:
        if p["name"] in ("params", "on_event", "self"):
            raise SystemExit(f"catalog param name collides with the flow signature: {name}.{p['name']}")
        sig_parts.append(_sig_param(p))

    if mode == "direct":
        sig = ", ".join(sig_parts)
        lines = [f"    def {name}({sig}) -> List[Dict[str, Any]]:"]
        doc = [f'        """{summary}', ""]
        doc.append("        Direct Cypher against the keyed graph (an API key is required).")
        doc.append(f"        Columns: {cols}.")
        doc.append("")
        doc.append(f"        See: {docs_url}")
        doc.append('        """')
        lines.extend(doc)
        cypher = m["cypher"]
        if params:
            pairs = ", ".join(f"{p['name']!r}: {p['name']}" for p in params)
            argmap = "_drop_none({" + pairs + "})"
        else:
            argmap = "{}"
        lines.append(f"        return self._q({cypher!r}, {argmap})")
    else:  # flow: runs keyed via the gallery flow runner (SSE)
        slug = _slug(m)
        sig_parts.append("params: Optional[Dict[str, Any]] = None")
        sig_parts.append("on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None")
        sig = ", ".join(sig_parts)
        lines = [f"    def {name}({sig}) -> Dict[str, Any]:"]
        doc = [f'        """{summary}', ""]
        doc.append("        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs")
        doc.append(f"        {{slug: {slug!r}, inputs, params}} and consumes the event stream. Returns")
        doc.append("        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.")
        doc.append(f"        Anchor columns: {cols}.")
        doc.append("")
        doc.append(f"        See: {docs_url}")
        doc.append('        """')
        lines.extend(doc)
        if params:
            pairs = ", ".join(f"{p['name']!r}: {p['name']}" for p in params)
            inputs = "_drop_none({" + pairs + "})"
        else:
            inputs = "{}"
        lines.append(f"        return self.run_flow({slug!r}, {inputs}, params, on_event=on_event)")
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
    docs_base = catalog.get("docsBase") or "https://www.whisper.security"

    body = [HEADER]
    for m in methods:
        body.append("")
        body.append(_emit_method(m, docs_base))
    body.append("")

    out = os.path.join(repo, "whisper_id", "graph.py")
    text = "\n".join(body)
    text = _sanitize(text)
    if re.search(r"[^\x00-\x7f]", text):
        raise SystemExit("generated module is not pure ASCII; extend _sanitize")
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {out} ({len(methods)} methods from {src})")


if __name__ == "__main__":
    main()

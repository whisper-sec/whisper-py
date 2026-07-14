# SPDX-License-Identifier: MIT
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
    tolerates ``\r\n`` line endings, multi-line ``data:`` fields (joined with newlines),
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
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if not line:
                if event or data:
                    yield event or "message", "\n".join(data)
                event, data = None, []
            elif line.startswith("event:"):
                event = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
            # other SSE fields (id:, retry:, : comments) are ignored, liberal-accept
        if event or data:
            yield event or "message", "\n".join(data)


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

        POSTs ``{"slug", "value", "paramValues"}`` to the flow-run endpoint and consumes the
        Server-Sent-Events stream: per-step tables accumulate under ``steps``, the final
        ``complete`` event's per-step rows land in ``context``, and the formatted report
        (when the flow presents one) in ``output``. ``on_event(name, data)`` fires for
        every streamed event as it arrives (start / step-start / step / graph / prune /
        complete). A streamed ``error`` event raises :class:`WhisperError`.

        The runner's wire contract is {slug, value, paramValues}: ``value`` is the ONE
        primary entity (a host / IP / ASN), or ``values`` for a bulk list; ``paramValues``
        carries every other input plus every tuning knob. The FIRST ``inputs`` entry becomes
        the anchor ``value``; every other input and every ``params`` knob rides in
        ``paramValues``. We send ONLY the keys the runner reads: an ``inputs``/``params`` map
        is silently ignored, so the flow would fall back to its default anchor.

        See: https://www.whisper.security/docs/recipes
        """
        param_values: Dict[str, Any] = {}
        value: Optional[Any] = None
        values: Optional[List[str]] = None
        first = True
        for _name, _val in (inputs or {}).items():
            if _val is None:
                continue
            if first:
                if isinstance(_val, (list, tuple)):
                    values = [str(x) for x in _val]
                else:
                    value = str(_val)
                first = False
            else:
                param_values[_name] = _val
        for _key, _val in (params or {}).items():
            param_values[_key] = _val
        body: Dict[str, Any] = {"slug": slug}
        if value is not None:
            body["value"] = value
        if values is not None:
            body["values"] = values
        if param_values:
            body["paramValues"] = param_values
        payload = json.dumps(body).encode("utf-8")
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


    def anycastDnsRootSovereignty(self, country: str = 'BR', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Assess how resilient a country's core DNS is if it were cut off from the world.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'anycast-dns-root-sovereignty', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: distinctLetters, totalInstances, globalCount, localCount, hostingAsns.

        See: https://www.whisper.security/docs/recipes/compliance
        """
        return self.run_flow('anycast-dns-root-sovereignty', _drop_none({'country': country}), params, on_event=on_event)

    def attackPath(self, value: str = 'paypal.com', other: str = 'paypa1.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Find the choke points an attacker would target - and how any two things connect.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'attack-path', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: indicator, type, available, cached, found, score, level, explanation, factors, sources, advisory.

        See: https://www.whisper.security/docs/recipes/attack-path
        """
        return self.run_flow('attack-path', _drop_none({'value': value, 'other': other}), params, on_event=on_event)

    def attackSurface(self, domain: str = 'github.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Map everything about a domain that's exposed to the outside world, scored for risk.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'attack-surface', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: indicator, type, available, cached, found, score, level, explanation, factors, sources, advisory.

        See: https://www.whisper.security/docs/recipes/pentest-recon
        """
        return self.run_flow('attack-surface', _drop_none({'domain': domain}), params, on_event=on_event)

    def bgpHijackExposure(self, value: str = 'AS13335', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Grade a network's routing security and trace conflicts to the domains they'd expose.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'bgp-hijack-exposure', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: prefix, is_moas, conflicting_asn.

        See: https://www.whisper.security/docs/recipes/bgp-routing
        """
        return self.run_flow('bgp-hijack-exposure', _drop_none({'value': value}), params, on_event=on_event)

    def blastRadius(self, indicator: str = 'ns1.dreamhost.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Pick one asset and see what would break if it failed - and what it depends on in turn.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'blast-radius', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: labels, name.

        See: https://www.whisper.security/docs/recipes/soc
        """
        return self.run_flow('blast-radius', _drop_none({'indicator': indicator}), params, on_event=on_event)

    def buildTakedownEvidencePackage(self, domain: str = 'ickaoex.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Assemble a ready-to-submit dossier for taking down a scam or phishing domain.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'build-takedown-evidence-package', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: indicator, type, available, cached, found, score, level, explanation, factors, sources, advisory.

        See: https://www.whisper.security/docs/recipes/threat-intel
        """
        return self.run_flow('build-takedown-evidence-package', _drop_none({'domain': domain}), params, on_event=on_event)

    def discoverAiAgentInfrastructure(self, value: str = 'github.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Map an organisation's externally visible AI and agent endpoints from the outside.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'discover-ai-agent-infrastructure', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: hostname, ips.

        See: https://www.whisper.security/docs/recipes/pentest-recon
        """
        return self.run_flow('discover-ai-agent-infrastructure', _drop_none({'value': value}), params, on_event=on_event)

    def indicator(self, indicator: str = 'theblackservicenetwork.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Investigate one suspicious domain, IP, or network in depth and get a clear picture of the threat and everything connected to it.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'indicator', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: host, label, band, sub_labels, coverage, evidence.

        See: https://www.whisper.security/docs/recipes/soc
        """
        return self.run_flow('indicator', _drop_none({'indicator': indicator}), params, on_event=on_event)

    def indicatorEnrichment(self, value: str = 'google.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Turn one domain or IP into a full context card - owner, hosting, mail, location, reputation at a glance.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'indicator-enrichment', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: attribute, value.

        See: https://www.whisper.security/docs/recipes/dns-email
        """
        return self.run_flow('indicator-enrichment', _drop_none({'value': value}), params, on_event=on_event)

    def infrastructureMapping(self, value: str = 'cloudflare.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Trace one indicator to its true owner and full estate, even behind privacy screens and CDNs.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'infrastructure-mapping', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: canonical_name, vendor_id, category, roles, host_class.

        See: https://www.whisper.security/docs/recipes/compliance
        """
        return self.run_flow('infrastructure-mapping', _drop_none({'value': value}), params, on_event=on_event)

    def mapSupplyChainConcentration(self, domain: str = 'atlassian.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Grade an organisation for over-reliance on single providers, regions, or facilities.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'map-supply-chain-concentration', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: provider, asn, region, country.

        See: https://www.whisper.security/docs/recipes/compliance
        """
        return self.run_flow('map-supply-chain-concentration', _drop_none({'domain': domain}), params, on_event=on_event)

    def nameserverHijackDnsConsistency(self, value: str = 'google.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Check a domain's name servers for the misconfigurations that enable DNS hijacking.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'nameserver-hijack-dns-consistency', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: nameserver, ips, status.

        See: https://www.whisper.security/docs/recipes/dns-email
        """
        return self.run_flow('nameserver-hijack-dns-consistency', _drop_none({'value': value}), params, on_event=on_event)

    def routeHealth(self, target: str = '1.1.1.0/24', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Profile a network or address block into a full routing and reachability health card.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'route-health', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: prefix, multi_origin, anycast, withdrawn.

        See: https://www.whisper.security/docs/recipes/bgp-routing
        """
        return self.run_flow('route-health', _drop_none({'target': target}), params, on_event=on_event)

    def subdomainTakeover(self, value: str = 'github.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Find subdomains that point at abandoned services an attacker could claim.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'subdomain-takeover', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: subdomain, ips.

        See: https://www.whisper.security/docs/recipes/pentest-recon
        """
        return self.run_flow('subdomain-takeover', _drop_none({'value': value}), params, on_event=on_event)

    def typosquat(self, domain: str = 'paypal.com', params: Optional[Dict[str, Any]] = None, on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Find registered look-alikes of your brand and check which ones are dangerous.

        Multi-step flow, run keyed via the gallery flow runner (SSE): POSTs
        {slug: 'typosquat', value, paramValues} and consumes the event stream. Returns
        {slug, steps, context, output, totalLatencyMs}; on_event streams progress.
        Anchor columns: variant, method, confidence.

        See: https://www.whisper.security/docs/recipes/brand-protection
        """
        return self.run_flow('typosquat', _drop_none({'domain': domain}), params, on_event=on_event)

    def identify(self, v: str = 'api.openai.com') -> List[Dict[str, Any]]:
        """Name the vendor and operator role behind a host or IP in one call.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: host, vendor_id, canonical_name, category, roles, host_class, band.

        See: https://www.whisper.security/docs/whisper-graph/procedures/identify
        """
        return self._q('CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band', _drop_none({'v': v}))

    def assess(self, v: str = '8.8.8.8') -> List[Dict[str, Any]]:
        """Get a labelled threat posture for a host or IP - malicious, benign, or unknown.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: host, label, band, sub_labels, coverage, evidence.

        See: https://www.whisper.security/docs/whisper-graph/procedures
        """
        return self._q('CALL whisper.assess([$v]) YIELD host, label, band, sub_labels, coverage, evidence', _drop_none({'v': v}))

    def variants(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Generate look-alike domain variants of a brand and see which are registered.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: variant, method, exists, confidence.

        See: https://www.whisper.security/docs/whisper-graph/procedures/variants
        """
        return self._q('CALL whisper.variants($v) YIELD variant, method, exists, confidence', _drop_none({'v': v}))

    def walk(self, v: str = 'cloudflare.com') -> List[Dict[str, Any]]:
        """Walk the graph to the nearest known vendors behind a host, with the channel and confidence.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: coverage, host, nearest_known_vendors, no_atlas_match, siblings.

        See: https://www.whisper.security/docs/whisper-graph/procedures
        """
        return self._q('CALL whisper.walk($v) YIELD coverage, host, nearest_known_vendors, no_atlas_match, siblings', _drop_none({'v': v}))

    def explain(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Score an indicator against the threat feeds and explain exactly why.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: indicator, score, level, explanation, sources.

        See: https://www.whisper.security/docs/whisper-graph/procedures/explain
        """
        return self._q('CALL whisper.explain($v) YIELD indicator, score, level, explanation, sources', _drop_none({'v': v}))

    def pslTldplusone(self, v: str = 'www.foo.co.uk') -> List[Dict[str, Any]]:
        """Reduce any hostname to its registrable apex (eTLD+1) via the Public Suffix List.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: apex.

        See: https://www.whisper.security/docs/whisper-graph/procedures/helpers
        """
        return self._q('CALL whisper.psl.tldPlusOne($v) YIELD apex', _drop_none({'v': v}))

    def pslAffiliation(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Check whether a domain is a PSL private-section suffix and who submitted it.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence.

        See: https://www.whisper.security/docs/whisper-graph/procedures/helpers
        """
        return self._q('CALL whisper.psl.affiliation($v) YIELD found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence', _drop_none({'v': v}))

    def origins(self, v: str = 'cloudflare.com') -> List[Dict[str, Any]]:
        """Find the real origin IPs behind a CDN-fronted domain, ranked by confidence.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: ip, confidence, methods, asn, asnName, kind.

        See: https://www.whisper.security/docs/whisper-graph/procedures/origins
        """
        return self._q('CALL whisper.origins($v) YIELD ip, confidence, methods, asn, asnName, kind', _drop_none({'v': v}))

    def history(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Get the full historical WHOIS timeline for a domain.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: indicator, type, queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers, cached.

        See: https://www.whisper.security/docs/whisper-graph/procedures/history
        """
        return self._q('CALL whisper.history($v)', _drop_none({'v': v}))

    def historyWhois(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Get the WHOIS-only historical timeline for a domain.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers.

        See: https://www.whisper.security/docs/whisper-graph/procedures/history
        """
        return self._q('CALL whisper.history.whois($v) YIELD queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers', _drop_none({'v': v}))

    def asset(self, v: str = 'AS-CLOUDFLARE') -> List[Dict[str, Any]]:
        """List the member ASNs of an AS-SET macro.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: asSetName, memberAsn, sourceRir.

        See: https://www.whisper.security/docs/whisper-graph/procedures
        """
        return self._q('CALL whisper.asSet($v) YIELD asSetName, memberAsn, sourceRir', _drop_none({'v': v}))

    def lookupTorRelay(self, v: str = '185.220.101.33') -> List[Dict[str, Any]]:
        """Check whether an IP is a known Tor exit relay.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: indicator, found, fingerprint, exitAddressCount, source, ingestedAt.

        See: https://www.whisper.security/docs/whisper-graph/procedures/helpers
        """
        return self._q('CALL whisper.lookupTorRelay($v) YIELD indicator, found, fingerprint, exitAddressCount, source, ingestedAt', _drop_none({'v': v}))

    def dbSchema(self) -> List[Dict[str, Any]]:
        """List every node and relationship type in the graph with counts and examples.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: type, name, count, description, example, sourceLabels, targetLabels, fastPatterns, slowPatterns, bestPractices.

        See: https://www.whisper.security/docs/whisper-graph/schema
        """
        return self._q('CALL db.schema()', {})

    def submit(self, kind: str = 'indicator', identifier_kind: str = 'ip', value: str = '203.0.113.5', observation_id: Optional[str] = None, confidence: Optional[float] = None, first_seen: Optional[str] = None, provenance: Optional[str] = None, query: Optional[str] = None, results: Optional[Any] = None, comment: Optional[str] = None, severity: Optional[str] = None, v: Optional[float] = None) -> List[Dict[str, Any]]:
        """Contribute an indicator observation or feedback back into the graph (requires an API key).

        Direct Cypher against the keyed graph (an API key is required).
        Columns: observation_id, kind, accepted, idempotent, promotion_state, k_bucket, advisory, v.

        See: https://www.whisper.security/docs/cypher-api
        """
        return self._q('CALL whisper.submit({kind:$kind, identifier_kind:$identifier_kind, value:$value})', _drop_none({'kind': kind, 'identifier_kind': identifier_kind, 'value': value, 'observation_id': observation_id, 'confidence': confidence, 'first_seen': first_seen, 'provenance': provenance, 'query': query, 'results': results, 'comment': comment, 'severity': severity, 'v': v}))

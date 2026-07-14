# SPDX-License-Identifier: MIT
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


    def anycastDnsRootSovereignty(self, country: str = 'BR') -> List[Dict[str, Any]]:
        """Assess how resilient a country's core DNS is if it were cut off from the world.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (anycast-dns-root-sovereignty)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): distinctLetters, totalInstances, globalCount, localCount, hostingAsns.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="anycastDnsRootSovereignty", run_via="run_workflow (anycast-dns-root-sovereignty)"))

    def attackPath(self, value: str = 'paypal.com', other: str = 'paypa1.com') -> List[Dict[str, Any]]:
        """Find the choke points an attacker would target - and how any two things connect.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (attack-path)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): indicator, type, available, cached, found, score, level, explanation, factors, sources, advisory.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="attackPath", run_via="run_workflow (attack-path)"))

    def attackSurface(self, domain: str = 'github.com') -> List[Dict[str, Any]]:
        """Map everything about a domain that's exposed to the outside world, scored for risk.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (attack-surface)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): indicator, type, available, cached, found, score, level, explanation, factors, sources, advisory.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="attackSurface", run_via="run_workflow (attack-surface)"))

    def bgpHijackExposure(self, value: str = 'AS13335') -> List[Dict[str, Any]]:
        """Grade a network's routing security and trace conflicts to the domains they'd expose.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (bgp-hijack-exposure)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): prefix, is_moas, conflicting_asn.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="bgpHijackExposure", run_via="run_workflow (bgp-hijack-exposure)"))

    def blastRadius(self, indicator: str = 'ns1.dreamhost.com') -> List[Dict[str, Any]]:
        """Pick one asset and see what would break if it failed - and what it depends on in turn.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (blast-radius)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): labels, name.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="blastRadius", run_via="run_workflow (blast-radius)"))

    def buildTakedownEvidencePackage(self, domain: str = 'ickaoex.com') -> List[Dict[str, Any]]:
        """Assemble a ready-to-submit dossier for taking down a scam or phishing domain.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (build-takedown-evidence-package)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): indicator, type, available, cached, found, score, level, explanation, factors, sources, advisory.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="buildTakedownEvidencePackage", run_via="run_workflow (build-takedown-evidence-package)"))

    def discoverAiAgentInfrastructure(self, value: str = 'github.com') -> List[Dict[str, Any]]:
        """Map an organisation's externally visible AI and agent endpoints from the outside.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (discover-ai-agent-infrastructure)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): hostname, ips.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="discoverAiAgentInfrastructure", run_via="run_workflow (discover-ai-agent-infrastructure)"))

    def indicator(self, indicator: str = 'theblackservicenetwork.com') -> List[Dict[str, Any]]:
        """Investigate one suspicious domain, IP, or network in depth and get a clear picture of the threat and everything connected to it.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (indicator)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): host, label, band, sub_labels, coverage, evidence.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="indicator", run_via="run_workflow (indicator)"))

    def indicatorEnrichment(self, value: str = 'google.com') -> List[Dict[str, Any]]:
        """Turn one domain or IP into a full context card - owner, hosting, mail, location, reputation at a glance.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (indicator-enrichment)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): attribute, value.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="indicatorEnrichment", run_via="run_workflow (indicator-enrichment)"))

    def infrastructureMapping(self, value: str = 'cloudflare.com') -> List[Dict[str, Any]]:
        """Trace one indicator to its true owner and full estate, even behind privacy screens and CDNs.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (infrastructure-mapping)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): canonical_name, vendor_id, category, roles, host_class.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="infrastructureMapping", run_via="run_workflow (infrastructure-mapping)"))

    def mapSupplyChainConcentration(self, domain: str = 'atlassian.com') -> List[Dict[str, Any]]:
        """Grade an organisation for over-reliance on single providers, regions, or facilities.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (map-supply-chain-concentration)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): provider, asn, region, country.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="mapSupplyChainConcentration", run_via="run_workflow (map-supply-chain-concentration)"))

    def nameserverHijackDnsConsistency(self, value: str = 'google.com') -> List[Dict[str, Any]]:
        """Check a domain's name servers for the misconfigurations that enable DNS hijacking.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (nameserver-hijack-dns-consistency)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): nameserver, ips, status.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="nameserverHijackDnsConsistency", run_via="run_workflow (nameserver-hijack-dns-consistency)"))

    def routeHealth(self, target: str = '1.1.1.0/24') -> List[Dict[str, Any]]:
        """Profile a network or address block into a full routing and reachability health card.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (route-health)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): prefix, multi_origin, anycast, withdrawn.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="routeHealth", run_via="run_workflow (route-health)"))

    def subdomainTakeover(self, value: str = 'github.com') -> List[Dict[str, Any]]:
        """Find subdomains that point at abandoned services an attacker could claim.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (subdomain-takeover)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): subdomain, ips.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="subdomainTakeover", run_via="run_workflow (subdomain-takeover)"))

    def typosquat(self, domain: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Find registered look-alikes of your brand and check which ones are dangerous.

        Multi-step read flow. Runs via the Whisper workflow runner (run_workflow (typosquat)),
        not a single /api/query POST, so it is stubbed (raises NotImplementedError).
        Columns (anchor step): variant, method, confidence.
        """
        raise NotImplementedError(_FLOW_RUNNER_NOTE.format(method="typosquat", run_via="run_workflow (typosquat)"))

    def identify(self, v: str = 'api.openai.com') -> List[Dict[str, Any]]:
        """Name the vendor and operator role behind a host or IP in one call.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: host, vendor_id, canonical_name, category, roles, host_class, band.
        """
        return self._q('CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, category, roles, host_class, band', {'v': v})

    def assess(self, v: str = '8.8.8.8') -> List[Dict[str, Any]]:
        """Get a labelled threat posture for a host or IP - malicious, benign, or unknown.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: host, label, band, sub_labels, coverage, evidence.
        """
        return self._q('CALL whisper.assess([$v]) YIELD host, label, band, sub_labels, coverage, evidence', {'v': v})

    def variants(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Generate look-alike domain variants of a brand and see which are registered.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: variant, method, exists, confidence.
        """
        return self._q('CALL whisper.variants($v) YIELD variant, method, exists, confidence', {'v': v})

    def walk(self, v: str = 'cloudflare.com') -> List[Dict[str, Any]]:
        """Walk the graph to the nearest known vendors behind a host, with the channel and confidence.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: coverage, host, nearest_known_vendors, no_atlas_match, siblings.
        """
        return self._q('CALL whisper.walk($v) YIELD coverage, host, nearest_known_vendors, no_atlas_match, siblings', {'v': v})

    def explain(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Score an indicator against the threat feeds and explain exactly why.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: indicator, score, level, explanation, sources.
        """
        return self._q('CALL whisper.explain($v) YIELD indicator, score, level, explanation, sources', {'v': v})

    def pslTldplusone(self, v: str = 'www.foo.co.uk') -> List[Dict[str, Any]]:
        """Reduce any hostname to its registrable apex (eTLD+1) via the Public Suffix List.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: apex.
        """
        return self._q('CALL whisper.psl.tldPlusOne($v) YIELD apex', {'v': v})

    def pslAffiliation(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Check whether a domain is a PSL private-section suffix and who submitted it.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence.
        """
        return self._q('CALL whisper.psl.affiliation($v) YIELD found, suffix, submitterOrg, submitterLogin, evidenceKind, confidence', {'v': v})

    def origins(self, v: str = 'cloudflare.com') -> List[Dict[str, Any]]:
        """Find the real origin IPs behind a CDN-fronted domain, ranked by confidence.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: ip, confidence, methods, asn, asnName, kind.
        """
        return self._q('CALL whisper.origins($v) YIELD ip, confidence, methods, asn, asnName, kind', {'v': v})

    def history(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Get the full historical WHOIS timeline for a domain.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: indicator, type, queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers, cached.
        """
        return self._q('CALL whisper.history($v)', {'v': v})

    def historyWhois(self, v: str = 'paypal.com') -> List[Dict[str, Any]]:
        """Get the WHOIS-only historical timeline for a domain.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers.
        """
        return self._q('CALL whisper.history.whois($v) YIELD queryTime, createDate, updateDate, expiryDate, registrar, registrant, country, nameServers', {'v': v})

    def asset(self, v: str = 'AS-CLOUDFLARE') -> List[Dict[str, Any]]:
        """List the member ASNs of an AS-SET macro.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: asSetName, memberAsn, sourceRir.
        """
        return self._q('CALL whisper.asSet($v) YIELD asSetName, memberAsn, sourceRir', {'v': v})

    def lookupTorRelay(self, v: str = '185.220.101.33') -> List[Dict[str, Any]]:
        """Check whether an IP is a known Tor exit relay.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: indicator, found, fingerprint, exitAddressCount, source, ingestedAt.
        """
        return self._q('CALL whisper.lookupTorRelay($v) YIELD indicator, found, fingerprint, exitAddressCount, source, ingestedAt', {'v': v})

    def dbSchema(self) -> List[Dict[str, Any]]:
        """List every node and relationship type in the graph with counts and examples.

        Direct Cypher against the keyed graph (an API key is required).
        Columns: type, name, count, description, example, sourceLabels, targetLabels, fastPatterns, slowPatterns, bestPractices.
        """
        return self._q('CALL db.schema()', {})

    def submit(self, kind: str = 'indicator') -> List[Dict[str, Any]]:
        """Contribute an indicator observation or feedback back into the graph (requires an API key).

        Direct Cypher against the keyed graph (an API key is required).
        Columns: (none declared).
        """
        return self._q('CALL whisper.submit({kind:$kind, /* + indicator/feedback fields */})', {'kind': kind})

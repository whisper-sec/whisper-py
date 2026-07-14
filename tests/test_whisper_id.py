# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
"""Unit tests for whisper-id: the CLI is mocked, so these run anywhere (no live box)."""
from __future__ import annotations

import json
import os
import subprocess
from types import SimpleNamespace

import pytest

import whisper_id
from whisper_id import Agent, WhisperError, egress, ip, register, verify


def _proc(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess(args=["whisper"], returncode=code, stdout=stdout, stderr=stderr)


@pytest.fixture(autouse=True)
def _fake_cli(monkeypatch):
    # Pretend the binary exists so cli_path() resolves without hitting the real PATH.
    monkeypatch.setenv("WHISPER_BIN", "/usr/bin/whisper")
    # Clean proxy env for deterministic save/restore assertions.
    for k in whisper_id._PROXY_VARS:
        monkeypatch.delenv(k, raising=False)


def _capture(monkeypatch, proc):
    calls = []

    def fake_run(cmd, **kw):
        calls.append(cmd)
        return proc

    monkeypatch.setattr(subprocess, "run", fake_run)
    return calls


def test_cli_path_missing(monkeypatch):
    monkeypatch.delenv("WHISPER_BIN", raising=False)
    monkeypatch.setattr(whisper_id.shutil, "which", lambda _: None)
    with pytest.raises(WhisperError, match="not found on PATH"):
        whisper_id.cli_path()


def test_register_parses_address(monkeypatch):
    calls = _capture(monkeypatch, _proc(stdout='{"agent":"2a04:2a01:b69a:6717:dead:beef:1:2","id":"ag_123"}'))
    a = register("my-bot")
    assert isinstance(a, Agent)
    assert a.address == "2a04:2a01:b69a:6717:dead:beef:1:2"
    assert a.id == "ag_123"
    assert a.name == "my-bot"
    assert calls[0][1:] == ["--json", "create", "--name", "my-bot"]


def test_register_new_key_flag(monkeypatch):
    calls = _capture(monkeypatch, _proc(stdout='{"address":"2a04:2a01:1::9"}'))
    register("boot", new_key=True)
    assert "--register" in calls[0]


def test_register_requires_name():
    with pytest.raises(WhisperError, match="non-empty"):
        register("  ")


def test_register_no_address_raises(monkeypatch):
    _capture(monkeypatch, _proc(stdout='{"ok":true}'))
    with pytest.raises(WhisperError, match="no /128"):
        register("x")


def test_egress_sets_and_restores_env(monkeypatch):
    os.environ["HTTP_PROXY"] = "http://old:1"  # must be restored exactly
    _capture(monkeypatch, _proc(stdout="whisper: connection up on 127.0.0.1:36123\n"))
    with egress() as e:
        assert e.port == 36123
        assert e.proxy_url == "http://127.0.0.1:36123"
        assert e.socks_url == "socks5h://127.0.0.1:36123"
        assert os.environ["HTTP_PROXY"] == "http://127.0.0.1:36123"
        assert os.environ["ALL_PROXY"] == "socks5h://127.0.0.1:36123"
    assert os.environ["HTTP_PROXY"] == "http://old:1"  # restored
    assert "ALL_PROXY" not in os.environ  # was unset before → unset after
    del os.environ["HTTP_PROXY"]


def test_egress_set_env_false_leaves_environ(monkeypatch):
    _capture(monkeypatch, _proc(stdout="connection up on 127.0.0.1:40000"))
    with egress(set_env=False) as e:
        assert e.port == 40000
        assert "HTTP_PROXY" not in os.environ


def test_egress_passes_agent_and_tier(monkeypatch):
    calls = _capture(monkeypatch, _proc(stdout="up on 127.0.0.1:5555"))
    with egress(agent="2a04:2a01:1::1", tier="wireguard"):
        pass
    cmd = calls[0]
    assert "--agent" in cmd and "2a04:2a01:1::1" in cmd
    assert "wireguard" in cmd


def test_egress_no_port_raises(monkeypatch):
    _capture(monkeypatch, _proc(stdout="something went sideways"))
    with pytest.raises(WhisperError, match="could not determine"):
        with egress():
            pass


def _http(monkeypatch, status, body):
    """Stub the keyless HTTP layer (verify/rdap/egress_ip are CLI-free now)."""
    monkeypatch.setattr(whisper_id, "_http_get", lambda url, *, timeout: (status, body.encode() if isinstance(body, str) else body))


def test_verify_true_on_200_agent(monkeypatch):
    _http(monkeypatch, 200, '{"is_whisper_agent":true,"fqdn":"x.agents.whisper.online","dane_ok":true}')
    assert whisper_id.verify("2a04:2a01:1::1") is True


def test_verify_false_on_404(monkeypatch):
    _http(monkeypatch, 404, '{"is_whisper_agent":false}')
    assert whisper_id.verify("2001:db8::1") is False


def test_verify_false_when_200_but_not_agent(monkeypatch):
    _http(monkeypatch, 200, '{"is_whisper_agent":false}')
    assert whisper_id.verify("2001:db8::1") is False


def test_verify_details_returns_verdict(monkeypatch):
    _http(monkeypatch, 200, '{"is_whisper_agent":true,"operator":"tABC","dane_ok":true,"jws_ok":true}')
    d = whisper_id.verify_details("2a04:2a01:1::1")
    assert d and d["operator"] == "tABC" and d["dane_ok"] is True


def test_rdap_returns_record_or_none(monkeypatch):
    _http(monkeypatch, 200, '{"handle":"ag1","name":"scout","status":["active"]}')
    assert whisper_id.rdap("2a04:2a01:1::1")["name"] == "scout"
    _http(monkeypatch, 404, "not found")
    assert whisper_id.rdap("2001:db8::1") is None


def test_egress_ip(monkeypatch):
    _http(monkeypatch, 200, '{"ip":"2a04:2a01:1::a"}')
    assert whisper_id.egress_ip() == "2a04:2a01:1::a"


def test_verify_requires_address():
    import pytest as _pytest
    with _pytest.raises(WhisperError):
        whisper_id.verify("  ")


def test_ip_returns_address(monkeypatch):
    _capture(monkeypatch, _proc(stdout='{"agent":"2a04:2a01:1::a","ip":"2a04:2a01:1::a","verified":true}'))
    assert ip() == "2a04:2a01:1::a"


def test_run_check_raises_with_stderr(monkeypatch):
    _capture(monkeypatch, _proc(code=1, stderr="boom"))
    with pytest.raises(WhisperError, match="boom"):
        ip()


# --- Control plane (pure-HTTP governance) ---------------------------------------------

from whisper_id import agent, identity, list_agents, logs, policy, revoke  # noqa: E402


def _post(monkeypatch, status, body):
    """Stub the control-plane POST layer; capture the (url, payload, api_key) it was called with."""
    seen = {}

    def fake_post(url, payload, *, api_key, timeout):
        seen["url"] = url
        seen["payload"] = payload
        seen["query"] = json.loads(payload)["query"]
        seen["api_key"] = api_key
        return status, body.encode() if isinstance(body, str) else body

    monkeypatch.setattr(whisper_id, "_http_post", fake_post)
    return seen


@pytest.fixture(autouse=True)
def _key_env(monkeypatch):
    monkeypatch.setenv("WHISPER_API_KEY", "whisper_live_TESTKEY")


# -- Cypher builder (conservative-emit: sorted keys, doubled quotes, injection-proof) --

def test_build_query_sorts_keys_and_escapes_quotes():
    q = whisper_id._build_agents_query("policy", {"default": "deny", "block": ["x.com", "y.com"], "allow": ["z.com"]})
    assert q == "CALL whisper.agents({op:'policy', args:{allow:['z.com'],block:['x.com','y.com'],default:'deny'}})"


def test_build_query_doubles_single_quote_no_breakout():
    q = whisper_id._build_agents_query("identity", {"label": "Tim O'Reilly'}) RETURN 1 //"})
    assert "Tim O''Reilly''}) RETURN 1 //" in q  # quotes doubled → trapped inside the literal
    assert q.count("op:'identity'") == 1


def test_build_query_empty_args():
    assert whisper_id._build_agents_query("policy", {}) == "CALL whisper.agents({op:'policy', args:{}})"


def test_cypher_lit_types():
    assert whisper_id._cypher_lit(True) == "true"
    assert whisper_id._cypher_lit(False) == "false"
    assert whisper_id._cypher_lit(None) == "null"
    assert whisper_id._cypher_lit(1000) == "1000"


# -- Envelope decoder (liberal-accept: both wire shapes) -------------------------------

def test_list_agents_flat_shape(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({
        "ok": True, "status": 200,
        "result": {"columns": ["kind", "item"],
                   "rows": [["agents", {"label": "scout", "address": "2a04:2a01:1::9"}]]},
        "error": None,
    }))
    fleet = list_agents()
    assert fleet == [{"label": "scout", "address": "2a04:2a01:1::9"}]  # item unwrapped
    assert seen["query"] == "CALL whisper.agents({op:'list', args:{kind:'agents'}})"
    assert seen["api_key"] == "whisper_live_TESTKEY"


def test_list_agents_live_row_shape(monkeypatch):
    # Live procedure-row table: rows[0] carries the per-op envelope.
    _post(monkeypatch, 200, json.dumps({
        "columns": ["op", "ok", "status", "result", "error", "retry_after"],
        "rows": [{"op": "list", "ok": True, "status": 200,
                  "result": {"columns": ["kind", "item"], "rows": [["agents", {"label": "b1"}]]},
                  "error": None, "retry_after": None}],
    }))
    assert list_agents() == [{"label": "b1"}]


def test_list_agents_kind_passthrough(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({"ok": True, "result": {"columns": [], "rows": []}}))
    list_agents("identities")
    assert seen["query"] == "CALL whisper.agents({op:'list', args:{kind:'identities'}})"


# -- policy: read (no args) vs set ------------------------------------------------------

def test_policy_read_no_args(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({
        "ok": True, "result": {"columns": ["key", "value"], "rows": [["default", "allow"]]}}))
    assert policy() == {"default": "allow"}
    assert seen["query"] == "CALL whisper.agents({op:'policy', args:{}})"  # no args ⇒ read


def test_policy_set_sorts_args(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({
        "ok": True, "result": {"columns": ["key", "value"], "rows": [["default", "deny"]]}}))
    policy(default="deny", block=["x.com"], allow=["z.com"])
    assert seen["query"] == "CALL whisper.agents({op:'policy', args:{allow:['z.com'],block:['x.com'],default:'deny'}})"


# -- logs: from_ → wire `from`, kind narrow --------------------------------------------

def test_logs_from_keyword_maps_to_wire_from(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({
        "ok": True, "result": {"columns": ["ts", "kind"], "rows": [[1, "dns"]]}}))
    out = logs(kind="dns", from_="-1h", limit=50)
    assert out == [{"ts": 1, "kind": "dns"}]
    assert seen["query"] == "CALL whisper.agents({op:'logs', args:{from:'-1h',kind:'dns',limit:50}})"


def test_logs_empty_window(monkeypatch):
    _post(monkeypatch, 200, json.dumps({"ok": True, "result": {"columns": ["ts"], "rows": []}}))
    assert logs() == []


# -- revoke / identity / agent ---------------------------------------------------------

def test_revoke_sends_agent(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({
        "ok": True, "result": {"columns": ["status"], "rows": [["revoked"]]}}))
    assert revoke("ag_123") == {"status": "revoked"}
    assert seen["query"] == "CALL whisper.agents({op:'revoke', args:{agent:'ag_123'}})"


def test_revoke_requires_agent():
    with pytest.raises(WhisperError, match="needs an agent"):
        revoke("  ")


def test_identity_allocate(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({
        "ok": True, "result": {"columns": ["address", "fqdn"], "rows": [["2a04:2a01:1::a", "a.agents.whisper.online"]]}}))
    rec = identity("my-label", contact_email="me@example.com")
    assert rec["address"] == "2a04:2a01:1::a"
    assert seen["query"] == (
        "CALL whisper.agents({op:'identity', args:{contact_email:'me@example.com',label:'my-label'}})")


def test_identity_release(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({"ok": True, "result": {"columns": ["state"], "rows": [["released"]]}}))
    identity(release=True, address="2a04:2a01:1::a")
    assert seen["query"] == "CALL whisper.agents({op:'identity', args:{address:'2a04:2a01:1::a',release:true}})"


def test_identity_release_needs_address():
    with pytest.raises(WhisperError, match="needs address"):
        identity(release=True)


def test_identity_allocate_needs_label():
    with pytest.raises(WhisperError, match="non-empty label"):
        identity()


def test_agent_colon_is_address(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({"ok": True, "result": {"columns": ["address"], "rows": [["2a04:2a01:1::a"]]}}))
    agent("2a04:2a01:1::a")
    assert seen["query"] == "CALL whisper.agents({op:'agent', args:{address:'2a04:2a01:1::a'}})"


def test_agent_id_selector(monkeypatch):
    seen = _post(monkeypatch, 200, json.dumps({"ok": True, "result": {"columns": ["agent"], "rows": [["ag_9"]]}}))
    agent("ag_9")
    assert seen["query"] == "CALL whisper.agents({op:'agent', args:{agent:'ag_9'}})"


# -- error handling: ok:false, bare problem, no key ------------------------------------

def test_ok_false_raises_with_detail(monkeypatch):
    _post(monkeypatch, 403, json.dumps({
        "ok": False, "status": 403,
        "error": {"type": "about:blank", "title": "forbidden", "status": 403, "detail": "scope admin:dns required"}}))
    with pytest.raises(WhisperError, match="scope admin:dns required"):
        policy(default="deny")


def test_bare_problem_object_raises(monkeypatch):
    _post(monkeypatch, 400, json.dumps({"type": "x", "title": "bad", "detail": "malformed address"}))
    with pytest.raises(WhisperError, match="malformed address"):
        agent("2a04:2a01:1::a")


def test_no_key_raises(monkeypatch):
    monkeypatch.delenv("WHISPER_API_KEY", raising=False)
    with pytest.raises(WhisperError, match="no API key"):
        list_agents(key=None)


def test_explicit_key_arg_used(monkeypatch):
    monkeypatch.delenv("WHISPER_API_KEY", raising=False)
    seen = _post(monkeypatch, 200, json.dumps({"ok": True, "result": {"columns": [], "rows": []}}))
    list_agents(key="whisper_live_ARG")
    assert seen["api_key"] == "whisper_live_ARG"


def test_non_json_reply_raises(monkeypatch):
    _post(monkeypatch, 502, "<html>bad gateway</html>")
    with pytest.raises(WhisperError, match="non-JSON"):
        list_agents()


# --- Keyed graph namespace (Cypher, so a key is required) -----------------------------

import importlib  # noqa: E402

from whisper_id import Graph, graph  # noqa: E402

# The public `graph` name is the factory function (it shadows the submodule attribute on
# the package), so reach the module itself through sys.modules to monkeypatch its transport.
graph_mod = importlib.import_module("whisper_id.graph")


def _gpost(monkeypatch, status, body):
    """Stub the graph POST layer; capture the (url, query, parameters, api_key) sent."""
    seen = {}

    def fake_post(url, payload, *, api_key, timeout):
        parsed = json.loads(payload)
        seen["url"] = url
        seen["query"] = parsed["query"]
        seen["parameters"] = parsed["parameters"]
        seen["api_key"] = api_key
        return status, body.encode() if isinstance(body, str) else body

    monkeypatch.setattr(graph_mod, "_http_post", fake_post)
    return seen


def test_graph_direct_emits_query_and_parameters(monkeypatch):
    seen = _gpost(monkeypatch, 200, json.dumps({
        "columns": ["host", "vendor_id"],
        "rows": [{"host": "api.openai.com", "vendor_id": "openai"}],
        "statistics": {"rowCount": 1, "executionTimeMs": 3},
    }))
    out = graph().identify("api.openai.com")
    assert out == [{"host": "api.openai.com", "vendor_id": "openai"}]
    assert seen["query"] == (
        "CALL whisper.identify([$v]) YIELD host, vendor_id, canonical_name, "
        "category, roles, host_class, band")
    assert seen["parameters"] == {"v": "api.openai.com"}
    assert seen["api_key"] == "whisper_live_TESTKEY"
    assert seen["url"] == whisper_id._control_url()  # same keyed endpoint as the control plane


def test_graph_object_rows_pass_through(monkeypatch):
    _gpost(monkeypatch, 200, json.dumps({
        "columns": ["host", "label", "band"],
        "rows": [{"host": "8.8.8.8", "label": "benign", "band": "LOW"}],
        "statistics": {"rowCount": 1},
    }))
    assert graph().assess("8.8.8.8") == [{"host": "8.8.8.8", "label": "benign", "band": "LOW"}]


def test_graph_positional_rows_zip_to_columns(monkeypatch):
    # Postel-liberal: accept positional rows too, zipping them onto the columns.
    _gpost(monkeypatch, 200, json.dumps({
        "columns": ["apex"],
        "rows": [["foo.co.uk"]],
        "statistics": {"rowCount": 1},
    }))
    assert graph().pslTldplusone("www.foo.co.uk") == [{"apex": "foo.co.uk"}]


def test_graph_raw_query_escape_hatch(monkeypatch):
    seen = _gpost(monkeypatch, 200, json.dumps({
        "columns": ["type", "name"], "rows": [{"type": "NODE", "name": "HOSTNAME"}]}))
    out = graph().query("CALL db.schema()")
    assert out == [{"type": "NODE", "name": "HOSTNAME"}]
    assert seen["query"] == "CALL db.schema()"
    assert seen["parameters"] == {}


def test_graph_db_schema_sends_empty_parameters(monkeypatch):
    seen = _gpost(monkeypatch, 200, json.dumps({"columns": [], "rows": []}))
    graph().dbSchema()
    assert seen["query"] == "CALL db.schema()"
    assert seen["parameters"] == {}


def test_graph_no_key_raises_shared_error(monkeypatch):
    monkeypatch.delenv("WHISPER_API_KEY", raising=False)
    with pytest.raises(WhisperError, match="no API key"):
        Graph().identify("api.openai.com")


def test_graph_explicit_key_used(monkeypatch):
    monkeypatch.delenv("WHISPER_API_KEY", raising=False)
    seen = _gpost(monkeypatch, 200, json.dumps({"columns": [], "rows": []}))
    Graph("whisper_live_ARG").assess("8.8.8.8")
    assert seen["api_key"] == "whisper_live_ARG"


def test_graph_problem_body_surfaces_detail(monkeypatch):
    _gpost(monkeypatch, 401, json.dumps({
        "type": "about:blank", "title": "unauthorized", "status": 401,
        "detail": "invalid or missing API key"}))
    with pytest.raises(WhisperError, match="invalid or missing API key"):
        graph().identify("api.openai.com")


def test_graph_error_field_surfaces_detail(monkeypatch):
    # A 200 with an inline error string still surfaces as a WhisperError (liberal-accept).
    _gpost(monkeypatch, 200, json.dumps({"error": "syntax error near YIELD"}))
    with pytest.raises(WhisperError, match="syntax error near YIELD"):
        graph().query("CALL bogus()")


def test_graph_non_json_reply_raises(monkeypatch):
    _gpost(monkeypatch, 502, "<html>bad gateway</html>")
    with pytest.raises(WhisperError, match="non-JSON"):
        graph().identify("api.openai.com")


_FLOW_METHODS = [
    "anycastDnsRootSovereignty", "attackPath", "attackSurface", "bgpHijackExposure",
    "blastRadius", "buildTakedownEvidencePackage", "discoverAiAgentInfrastructure",
    "indicator", "indicatorEnrichment", "infrastructureMapping",
    "mapSupplyChainConcentration", "nameserverHijackDnsConsistency", "routeHealth",
    "subdomainTakeover", "typosquat",
]


@pytest.mark.parametrize("name", _FLOW_METHODS)
def test_graph_flow_methods_stub_with_workflow_note(name):
    g = graph()
    with pytest.raises(NotImplementedError, match="workflow runner"):
        getattr(g, name)()


def test_graph_factory_passes_timeout():
    g = graph(timeout=5)
    assert isinstance(g, Graph)
    assert g._timeout == 5


def test_graph_all_catalog_methods_present():
    # 14 direct + 15 flow = 29 verbs, plus the raw query() escape hatch.
    direct = ["identify", "assess", "variants", "walk", "explain", "pslTldplusone",
              "pslAffiliation", "origins", "history", "historyWhois", "asset",
              "lookupTorRelay", "dbSchema", "submit"]
    for name in direct + _FLOW_METHODS:
        assert callable(getattr(Graph, name)), name

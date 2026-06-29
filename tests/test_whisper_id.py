# SPDX-License-Identifier: MIT
# Copyright (c) 2026 viaGraph B.V. (Whisper Security)
"""Unit tests for whisper-id — the CLI is mocked, so these run anywhere (no live box)."""
from __future__ import annotations

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


def test_verify_truthy_on_zero_exit(monkeypatch):
    _capture(monkeypatch, _proc(code=0))
    assert verify("2a04:2a01:1::1") is True


def test_verify_false_on_nonzero(monkeypatch):
    _capture(monkeypatch, _proc(code=3, stderr="not a whisper agent"))
    assert verify("2001:db8::1") is False


def test_ip_returns_address(monkeypatch):
    _capture(monkeypatch, _proc(stdout='{"agent":"2a04:2a01:1::a","ip":"2a04:2a01:1::a","verified":true}'))
    assert ip() == "2a04:2a01:1::a"


def test_run_check_raises_with_stderr(monkeypatch):
    _capture(monkeypatch, _proc(code=1, stderr="boom"))
    with pytest.raises(WhisperError, match="boom"):
        ip()

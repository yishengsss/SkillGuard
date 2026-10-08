"""Deployment tool discovery uses inert subprocess/RPC boundaries only."""
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from ops import server


@pytest.fixture
def deployment_boundary(monkeypatch):
    calls = []
    monkeypatch.setattr(server, '_env', lambda: {'OWNER_PRIVATE_KEY': 'inert-fixture-key'})
    monkeypatch.setattr(server, '_rpc_url', lambda: 'http://fixture.invalid')
    monkeypatch.setattr(server, '_w3', lambda: SimpleNamespace(eth=SimpleNamespace(chain_id=31337)))
    monkeypatch.setattr(server, 'w3_or_url', lambda _: SimpleNamespace(eth=SimpleNamespace(chain_id=31337)))
    monkeypatch.setattr(server, '_fund_local', lambda _: None)
    monkeypatch.setattr(server, '_deployment', lambda: {'SkillRegistry': 'fixture-registry', 'SkillLicense': 'fixture-license'})
    def invoke(command, **kwargs):
        calls.append(command)
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr(subprocess, 'run', invoke)
    return calls


def test_deploy_uses_foundry_user_install_without_path(tmp_path, monkeypatch, deployment_boundary):
    home = tmp_path / 'home'
    executable = home / '.foundry/bin/forge'
    executable.parent.mkdir(parents=True)
    executable.write_text('#!/bin/sh\nexit 0\n')
    executable.chmod(0o755)
    monkeypatch.setattr(Path, 'home', classmethod(lambda _: home))
    monkeypatch.setattr(shutil, 'which', lambda _: None)
    result = server.deploy()
    assert deployment_boundary[0][0] == str(executable)
    assert deployment_boundary[0][1:] == ['script', 'script/Deploy.s.sol', '--rpc-url', 'http://fixture.invalid', '--broadcast']
    assert result == {'registry': 'fixture-registry', 'license': 'fixture-license'}


def test_deploy_prefers_forge_from_path(monkeypatch, deployment_boundary):
    monkeypatch.setattr(shutil, 'which', lambda _: '/fixture/bin/forge')
    server.deploy()
    assert deployment_boundary[0][0] == '/fixture/bin/forge'


def test_missing_forge_stops_before_loading_wallet_config(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, 'home', classmethod(lambda _: tmp_path))
    monkeypatch.setattr(shutil, 'which', lambda _: None)
    def forbidden():
        raise AssertionError('wallet configuration must not be loaded without forge')
    monkeypatch.setattr(server, '_env', forbidden)
    with pytest.raises(server.OpsError, match='forge'):
        server.deploy()

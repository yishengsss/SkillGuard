"""BOT deployment validates live receipts/code before activating a deployment."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from ops import server

REGISTRY = '0x0000000000000000000000000000000000000011'
LICENSE = '0x0000000000000000000000000000000000000022'
OWNER = '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A'
TXS = ['0x' + f'{i:064x}' for i in range(1, 5)]


@pytest.fixture
def bot_boundary(tmp_path, monkeypatch):
    deployed = tmp_path / 'deployments.json'
    original = b'{"chainId":31337,"SkillRegistry":"previous","SkillLicense":"previous"}\n'
    deployed.write_bytes(original)
    monkeypatch.setattr(server, 'PROJECT_ROOT', tmp_path)
    monkeypatch.setattr(server, 'DEPLOYMENTS', deployed)
    monkeypatch.setattr(server, '_forge_executable', lambda: '/fixture/forge')
    monkeypatch.setattr(server, '_env', lambda: {'OWNER_PRIVATE_KEY': '0x' + '11' * 32})
    monkeypatch.setattr(server, '_rpc_url', lambda: 'http://fixture.invalid')

    state = {'chain': 968, 'failed_receipt': None, 'missing_code': None,
             'miswired': False, 'exit_code': 0, 'calls': []}

    class Eth:
        @property
        def chain_id(self):
            return state['chain']

        block_number = 50

        def get_code(self, address):
            return b'' if address == state['missing_code'] else b'\x60\x00'

        def get_transaction_receipt(self, tx):
            return {'status': 0 if tx == state['failed_receipt'] else 1,
                    'blockNumber': 100 + TXS.index(tx), 'transactionHash': tx,
                    'contractAddress': [REGISTRY, LICENSE, None, None][TXS.index(tx)]}

        def contract(self, address, abi):
            class Functions:
                def __getattr__(self, name):
                    def invoke(*args):
                        values = {'owner': OWNER, 'skillLicense': LICENSE,
                                  'registry': REGISTRY, 'MINTER_ROLE': b'\x01' * 32,
                                  'hasRole': not state['miswired'],
                                  'auditorStake': 10**16, 'AUDITOR_STAKE': 10**16}
                        if name == 'registry' and state['miswired']:
                            values[name] = REGISTRY[:-2] + '33'
                        return SimpleNamespace(call=lambda: values[name])
                    return invoke
            return SimpleNamespace(functions=Functions(), address=address)

    w3 = SimpleNamespace(eth=Eth())
    monkeypatch.setattr(server, '_w3', lambda: w3)
    monkeypatch.setattr(server, 'w3_or_url', lambda _: w3)
    def no_anvil_funding(_):
        raise AssertionError('BOT deployment must not use Anvil balance overrides')
    monkeypatch.setattr(server, '_fund_local', no_anvil_funding)

    def invoke(command, **kwargs):
        state['calls'].append(command)
        candidate = Path(kwargs['env'].get('DEPLOYMENTS_PATH', str(deployed)))
        candidate.write_text(json.dumps({'chainId': 968, 'SkillRegistry': REGISTRY,
                                        'SkillLicense': LICENSE}))
        assert deployed.read_bytes() == original, 'unverified deployment must stay staged'
        record = tmp_path / 'contracts/broadcast/Deploy.s.sol/968/run-latest.json'
        record.parent.mkdir(parents=True, exist_ok=True)
        record.write_text(json.dumps({'transactions': [
            {'hash': tx, 'transactionType': 'CREATE' if i < 2 else 'CALL',
             'contractAddress': [REGISTRY, LICENSE, REGISTRY, LICENSE][i],
             'contractName': ['SkillRegistry', 'SkillLicense', 'SkillRegistry', 'SkillLicense'][i]}
            for i, tx in enumerate(TXS)]}))
        return subprocess.CompletedProcess(command, state['exit_code'])
    monkeypatch.setattr(subprocess, 'run', invoke)
    return state, deployed, original


def test_bot_deployment_activates_only_verified_contracts(bot_boundary):
    state, path, _ = bot_boundary
    result = server.deploy()
    assert result['registry'] == REGISTRY
    assert result['license'] == LICENSE
    assert json.loads(path.read_text())['deploymentBlock'] == 100
    assert '--slow' in state['calls'][0]
    assert '--legacy' in state['calls'][0]


@pytest.mark.parametrize('failed_index', [0, 1, 2, 3])
def test_failed_bot_receipt_preserves_previous_configuration(bot_boundary, failed_index):
    state, path, original = bot_boundary
    state['failed_receipt'] = TXS[failed_index]
    with pytest.raises(server.OpsError, match='回执'):
        server.deploy()
    assert path.read_bytes() == original


def test_bot_missing_license_code_is_not_a_success(bot_boundary):
    state, path, original = bot_boundary
    state['missing_code'] = LICENSE
    with pytest.raises(server.OpsError, match='字节码'):
        server.deploy()
    assert path.read_bytes() == original


def test_bot_miswired_contracts_are_not_activated(bot_boundary):
    state, path, original = bot_boundary
    state['miswired'] = True
    with pytest.raises(server.OpsError, match='接线|权限'):
        server.deploy()
    assert path.read_bytes() == original


def test_bot_forge_failure_preserves_previous_configuration(bot_boundary):
    state, path, original = bot_boundary
    state['exit_code'] = 1
    with pytest.raises(server.OpsError, match='forge'):
        server.deploy()
    assert path.read_bytes() == original


def test_mainnet_is_rejected_without_broadcast(bot_boundary):
    state, path, original = bot_boundary
    state['chain'] = 677
    with pytest.raises(server.OpsError):
        server.deploy()
    assert not state['calls']
    assert path.read_bytes() == original


def test_deploy_checks_the_same_rpc_it_will_broadcast_to(bot_boundary, monkeypatch):
    state, _, _ = bot_boundary
    state['chain'] = 677
    monkeypatch.setattr(server, '_w3', lambda: SimpleNamespace(eth=SimpleNamespace(chain_id=968)))
    with pytest.raises(server.OpsError):
        server.deploy()
    assert not state['calls']


def test_agent_starts_at_deployment_block(tmp_path):
    from auditor.agent import AgentContext, run_once
    requests, registrations = [], []
    ctx = AgentContext(root=tmp_path, contract=object(), account=object(), chain_id=968,
                       fetch_requests=lambda c, a, b: requests.append((a, b)) or [],
                       fetch_registrations=lambda c, a, b: registrations.append((a, b)) or {},
                       scanner=lambda s: None, w3=SimpleNamespace(eth=SimpleNamespace(block_number=50)))
    ctx.deployment_block = 42
    cursor, latest = run_once(ctx, 0)
    assert requests == [(42, 50)]
    assert registrations == [(42, 50)]
    assert (cursor, latest) == (51, 50)


@pytest.mark.parametrize('block', [True, -1, '42'])
def test_bad_deployment_block_is_rejected(tmp_path, monkeypatch, block):
    from auditor.submit import SubmitError, load_config
    for name in ['RPC_URL', 'AUDITOR_PRIVATE_KEY']:
        monkeypatch.delenv(name, raising=False)
    config = tmp_path / 'fixture.env'
    config.write_text('RPC_URL=http://fixture.invalid\nAUDITOR_PRIVATE_KEY=0x' + '11' * 32 + '\n')
    deployment = tmp_path / 'deployments.json'
    deployment.write_text(json.dumps({'chainId': 968, 'SkillRegistry': REGISTRY,
                                      'deploymentBlock': block}))
    with pytest.raises(SubmitError, match='deploymentBlock'):
        load_config(env_path=config, deployments_path=deployment)


@pytest.mark.parametrize('previous_chain,previous_registry', [(968, REGISTRY), (31337, LICENSE)])
def test_ops_ignores_cursor_from_other_deployment(bot_boundary, monkeypatch, previous_chain, previous_registry):
    from auditor.submit import SubmitConfig
    from auditor import agent
    state, path, _ = bot_boundary
    state['chain'] = 31337
    path.write_text(json.dumps({'chainId': 31337, 'SkillRegistry': REGISTRY, 'SkillLicense': LICENSE}))
    cursor = agent.cursor_path(path.parent)
    cursor.parent.mkdir(exist_ok=True)
    cursor.write_text(json.dumps({'cursor': 26000000, 'chainId': previous_chain, 'registry': previous_registry}))
    monkeypatch.setattr(server, 'load_auditor_config', lambda: SubmitConfig('http://fixture.invalid', '0x' + '11' * 32, 31337, REGISTRY))
    fetched = []
    monkeypatch.setattr(agent, 'fetch_audit_requests', lambda c, a, b: fetched.append((a, b)) or [])
    monkeypatch.setattr(agent, 'fetch_registrations', lambda c, a, b: {})
    result = server.agent_once()
    assert result['cursorBefore'] == 0
    assert fetched == [(0, 50)]
    assert result['cursorAfter'] == 51
    saved = json.loads(cursor.read_text())
    assert saved['chainId'] == 31337
    assert saved['registry'] == REGISTRY

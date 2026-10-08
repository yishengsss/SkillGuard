"""Wallet authority: real EOA signatures, real nonce/session persistence."""
import importlib
import json
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from eth_account import Account
from eth_account.messages import encode_defunct

WALLET = Account.from_key('0x' + '11' * 32)  # Public unit fixture, never funded.
OTHER = Account.from_key('0x' + '22' * 32)
ORIGIN = 'http://127.0.0.1:8765'


def context(tmp_path, monkeypatch):
    models = importlib.import_module('ops.models')
    mod = importlib.import_module('ops.auth')
    monkeypatch.setattr(mod, 'is_eoa', lambda *args: True)
    scope = models.ChainScope(31337, Account.from_key('0x'+'33'*32).address,
                              OTHER.address, 0, 'fixture-revision')
    return mod, mod.WalletAuth(tmp_path), scope


def sign(message, wallet=WALLET):
    return wallet.sign_message(encode_defunct(text=message)).signature.hex()


def test_siwe_nonce_is_single_use(tmp_path, monkeypatch):
    mod, auth, scope = context(tmp_path, monkeypatch)
    message = auth.challenge(WALLET.address, scope, ORIGIN)
    token, session = auth.verify(message, sign(message), scope, ORIGIN)
    assert session.address == WALLET.address
    assert auth.require(token, scope).address == WALLET.address
    with pytest.raises(mod.AuthError):
        auth.verify(message, sign(message), scope, ORIGIN)


def test_challenge_and_session_expiry(tmp_path, monkeypatch):
    mod, auth, scope = context(tmp_path, monkeypatch)
    now = [1_800_000_000]
    monkeypatch.setattr(mod.time, 'time', lambda: now[0])
    expired_message = auth.challenge(WALLET.address, scope, ORIGIN)
    now[0] += 301
    with pytest.raises(mod.AuthError):
        auth.verify(expired_message, sign(expired_message), scope, ORIGIN)
    message = auth.challenge(WALLET.address, scope, ORIGIN)
    token, _ = auth.verify(message, sign(message), scope, ORIGIN)
    now[0] += 1801
    with pytest.raises(mod.AuthError):
        auth.require(token, scope)


@pytest.mark.parametrize('change', ['signer', 'domain', 'uri', 'chain', 'revision', 'origin'])
def test_modified_authentication_cannot_establish_session(tmp_path, monkeypatch, change):
    mod, auth, scope = context(tmp_path, monkeypatch)
    message = auth.challenge(WALLET.address, scope, ORIGIN)
    signature = sign(message, OTHER if change == 'signer' else WALLET)
    altered = message
    if change == 'domain':
        altered = message.replace('127.0.0.1:8765', 'example.org')
    if change == 'uri':
        altered = message.replace('URI: '+ORIGIN, 'URI: '+ORIGIN+'/unexpected')
    if altered != message:
        signature = sign(altered)
    selected_scope = replace(scope, chain_id=968) if change == 'chain' else scope
    if change == 'revision':
        selected_scope = replace(scope, revision='changed')
    origin = 'http://localhost:8765' if change == 'origin' else ORIGIN
    with pytest.raises(mod.AuthError):
        auth.verify(altered, signature, selected_scope, origin)


def test_nonce_consumption_is_atomic(tmp_path, monkeypatch):
    mod, auth, scope = context(tmp_path, monkeypatch)
    message = auth.challenge(WALLET.address, scope, ORIGIN)
    signature = sign(message)
    def attempt(_):
        try:
            return auth.verify(message, signature, scope, ORIGIN)[1].address
        except mod.AuthError:
            return None
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, [1, 2]))
    assert results.count(WALLET.address) == 1
    assert results.count(None) == 1


def test_logout_restart_and_scope_change_revoke_session(tmp_path, monkeypatch):
    mod, auth, scope = context(tmp_path, monkeypatch)
    message = auth.challenge(WALLET.address, scope, ORIGIN)
    token, _ = auth.verify(message, sign(message), scope, ORIGIN)
    with pytest.raises(mod.AuthError):
        auth.require(token, replace(scope, revision='new'))
    auth.logout(token)
    with pytest.raises(mod.AuthError):
        auth.require(token, scope)
    message = auth.challenge(WALLET.address, scope, ORIGIN)
    token, _ = auth.verify(message, sign(message), scope, ORIGIN)
    restarted = mod.WalletAuth(tmp_path)
    with pytest.raises(mod.AuthError):
        restarted.require(token, scope)


def test_contract_wallet_cannot_authenticate_as_eoa(tmp_path, monkeypatch):
    mod, auth, scope = context(tmp_path, monkeypatch)
    message = auth.challenge(WALLET.address, scope, ORIGIN)
    monkeypatch.setattr(mod, 'is_eoa', lambda *args: False)
    with pytest.raises(mod.AuthError):
        auth.verify(message, sign(message), scope, ORIGIN)


@pytest.mark.parametrize('legacy', ['deploy', 'stake', 'register', 'decide', 'agent-once', 'install'])
def test_http_cannot_use_server_keys_for_legacy_actions(tmp_path, legacy):
    mod = importlib.import_module('ops.app')
    app = mod.OpsApplication(tmp_path)
    response = app.handle('POST', '/api/'+legacy, {
        'Host': '127.0.0.1:8765', 'Origin': ORIGIN,
        'Content-Type': 'application/json', 'X-SkillGuard-Token': app.csrf_token,
    }, b'{}')
    assert response.status == 410
    assert json.loads(response.body)['ok'] is False
    assert not (tmp_path/'deployments.json').exists()


def test_http_auth_sets_host_only_cookie_and_checks_wallet(tmp_path, monkeypatch):
    _, _, scope = context(tmp_path, monkeypatch)
    mod = importlib.import_module('ops.app')
    monkeypatch.setattr(mod, 'load_scope', lambda _: scope)
    app = mod.OpsApplication(tmp_path)
    headers = {'Host': '127.0.0.1:8765', 'Origin': ORIGIN,
               'Content-Type': 'application/json', 'X-SkillGuard-Token': app.csrf_token}
    response = app.handle('POST', '/api/auth/challenge', headers,
                          json.dumps({'address': WALLET.address}).encode())
    message = json.loads(response.body)['data']['message']
    response = app.handle('POST', '/api/auth/verify', headers,
                          json.dumps({'message': message, 'signature': sign(message)}).encode())
    assert response.status == 200
    cookie = response.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'SameSite=Strict' in cookie and 'Path=/' in cookie
    assert 'Domain=' not in cookie and 'Secure' not in cookie
    headers['Cookie'] = cookie.split(';')[0]
    headers['X-SkillGuard-Wallet'] = OTHER.address
    result = app.handle('GET', '/api/packages/'+'ab'*32, headers, b'')
    assert result.status == 401
    result = app.handle('POST', '/api/auth/logout', headers, b'{}')
    assert result.status == 200
    assert 'Max-Age=0' in result.headers['Set-Cookie']
    with pytest.raises(importlib.import_module('ops.auth').AuthError):
        app.auth.require(cookie.split(';')[0].split('=',1)[1],scope)


@pytest.mark.parametrize('headers,expected', [
    ({'Origin': 'https://example.org'}, 403),
    ({'Host': 'example.org:8765', 'Origin': 'http://example.org:8765'}, 403),
    ({'Sec-Fetch-Site': 'cross-site'}, 403),
    ({'X-SkillGuard-Token': 'wrong'}, 403),
    ({'Content-Type': 'text/plain'}, 415),
])
def test_http_origin_and_csrf_reject_before_action(tmp_path, headers, expected):
    mod = importlib.import_module('ops.app')
    app = mod.OpsApplication(tmp_path)
    request = {'Host': '127.0.0.1:8765', 'Origin': ORIGIN,
               'Content-Type': 'application/json', 'X-SkillGuard-Token': app.csrf_token}
    request.update(headers)
    result = app.handle('POST', '/api/auth/challenge', request, b'{}')
    assert result.status == expected


@pytest.mark.parametrize('body', [b'[]', b'bad-json', b'{' + b' '*65536 + b'}'],
                         ids=['array', 'bad-json', 'too-large'])
def test_invalid_json_does_not_reach_authentication(tmp_path, body):
    mod = importlib.import_module('ops.app')
    app = mod.OpsApplication(tmp_path)
    result = app.handle('POST', '/api/auth/challenge', {
        'Host': '127.0.0.1:8765', 'Origin': ORIGIN,
        'Content-Type': 'application/json', 'X-SkillGuard-Token': app.csrf_token,
    }, body)
    assert result.status in (400, 413)


def public_chain(tmp_path, monkeypatch, with_auditor=True):
    mod = importlib.import_module('ops.config')
    (tmp_path/'deployments.json').write_text(json.dumps({
        'chainId': 31337, 'SkillRegistry': OTHER.address,
        'SkillLicense': WALLET.address, 'deploymentBlock': 12}))
    content = 'RPC_URL=http://fixture.invalid\nPRIVATE_KEY=must-not-be-used\nOWNER_PRIVATE_KEY=must-not-be-used\n'
    if with_auditor:
        content += 'AUDITOR_PRIVATE_KEY=0x' + '22'*32 + '\n'
    (tmp_path/'.env').write_text(content)
    owner = SimpleNamespace(call=lambda: WALLET.address)
    functions = SimpleNamespace(owner=lambda: owner,protocolVersion=lambda:SimpleNamespace(call=lambda **kwargs:1))
    eth = SimpleNamespace(chain_id=31337, block_number=99, get_code=lambda *args,**kwargs: b'contract',
                          contract=lambda **_: SimpleNamespace(address=OTHER.address,functions=functions))
    monkeypatch.setattr(mod, 'web3_for', lambda *args: SimpleNamespace(eth=eth))
    return mod


def test_public_configuration_uses_chain_owner_without_exposing_settings(tmp_path, monkeypatch):
    mod = public_chain(tmp_path, monkeypatch)
    result = mod.public_config(tmp_path)
    assert result['ready'] is True
    assert result['owner'] == WALLET.address
    assert result['auditor'] == OTHER.address
    text = json.dumps(result)
    assert 'must-not-be-used' not in text and '22'*32 not in text
    assert 'fixture.invalid' not in text


def test_missing_auditor_key_does_not_block_public_chain_reads(tmp_path, monkeypatch):
    mod = public_chain(tmp_path, monkeypatch, with_auditor=False)
    result = mod.public_config(tmp_path)
    assert result['ready'] is True
    assert result['owner'] == WALLET.address
    assert result['auditor'] is None


def test_invalid_cookie_has_no_wallet_authority(tmp_path, monkeypatch):
    _, _, scope = context(tmp_path, monkeypatch)
    mod = importlib.import_module('ops.app')
    monkeypatch.setattr(mod, 'load_scope', lambda _: scope)
    app = mod.OpsApplication(tmp_path)
    headers={'Host':'127.0.0.1:8765','Origin':ORIGIN,'Content-Type':'application/json','X-SkillGuard-Token':app.csrf_token,'Cookie':'sg_session=forged'}
    assert app.handle('GET','/api/packages/'+'ab'*32,headers,b'').status == 401
    result=app.handle('POST','/api/auth/logout',headers,b'{}')
    assert result.status == 200 and 'Max-Age=0' in result.headers['Set-Cookie']
def test_mcp_command_preserves_virtual_environment_entrypoint(tmp_path,monkeypatch):
    import sys
    from ops.config import public_config
    script=tmp_path/'gate/mcp_server.py';script.parent.mkdir();script.write_text('pass\n')
    base=tmp_path/'base-python';base.write_text('')
    entry=tmp_path/'.venv/bin/python';entry.parent.mkdir(parents=True);entry.symlink_to(base)
    monkeypatch.setattr(sys,'executable',str(entry))
    command=public_config(tmp_path)['mcpConfig']['mcpServers']['skillguard']
    assert command['command']==str(entry)
    assert command['args']==[str(script)]

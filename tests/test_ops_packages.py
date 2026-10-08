"""Archive behavior tested with real zip bytes and real source snapshots."""
import importlib
import io
import json
import stat
import time
import warnings
import zipfile
from pathlib import Path

import pytest
from eth_account import Account
from web3 import Web3
from eth_account.messages import encode_defunct

from ops.models import ChainScope, WalletSession

OWNER = Account.from_key('0x'+'11'*32).address
OTHER = Account.from_key('0x'+'22'*32).address
SCOPE = ChainScope(31337, OWNER, OTHER, 0, 'fixture')


def session(address=OWNER):
    return WalletSession(address, SCOPE, int(time.time())+1800)


def manifest(name='custom-archive-one', version='1.0.0'):
    return json.dumps({'name': name, 'version': version, 'package': 'fixture-sdk',
                      'tools': [{'name': 'hello', 'description': 'Returns a greeting',
                                 'inputSchema': {'type': 'object'}}]}, ensure_ascii=False).encode()


def archive(entries=None, *, name='custom-archive-one', version='1.0.0', wrapped=''):
    if entries is None:
        entries = [('manifest.json', manifest(name, version), stat.S_IFREG|0o644),
                   ('main.py', b'VALUE = 1\n', stat.S_IFREG|0o755)]
    data = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(data, 'w') as z:
            for path, body, mode in entries:
                info = zipfile.ZipInfo(wrapped+path)
                info.create_system = 3
                info.external_attr = mode << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, body)
    return data.getvalue()


def store_for(tmp_path):
    return importlib.import_module('ops.packages').PackageStore(tmp_path)


def test_custom_zip_hashes_match_scanner_and_gate(tmp_path):
    store = store_for(tmp_path)
    first = store.upload(archive(wrapped='my-skill/'), session())
    second = store.upload(archive(name='custom-archive-two'), session(OTHER))
    assert first['manifest']['name'] == 'custom-archive-one'
    assert second['manifest']['name'] == 'custom-archive-two'
    # Independent hand-encoded one-file codeHash (7-byte path, 10-byte content).
    expected = Web3.keccak(b'\x00'*7+b'\x07main.py'+b'\x00'*7+b'\x0aVALUE = 1\n')
    assert first['codeHash'] == '0x'+expected.hex()
    assert first['metadataHash'] == '0x'+Web3.keccak(manifest()).hex()
    snapshot = store.capture(first['packageId'], OWNER)
    assert dict(snapshot.files) == {'main.py': b'VALUE = 1\n'}
    assert dict(snapshot.file_modes)['main.py'] == 0o755
    assert (tmp_path/first['source']).is_dir()


def test_non_utf8_source_file_is_rejected_before_package_publication(tmp_path):
    mod = importlib.import_module('ops.packages')
    data = archive([
        ('manifest.json', manifest(), stat.S_IFREG|0o644),
        ('main.py', b'VALUE = 1\n', stat.S_IFREG|0o644),
        ('assets/icon.bin', b'\x89PNG\x00\xff', stat.S_IFREG|0o644),
    ])
    with pytest.raises(mod.PackageError, match='assets/icon.bin'):
        mod.PackageStore(tmp_path).upload(data, session())
    assert not list((tmp_path/'.cache/packages').glob('*/*/source'))


def test_package_drafts_remain_owned_when_identical_bytes_are_uploaded(tmp_path):
    mod = importlib.import_module('ops.packages')
    store = mod.PackageStore(tmp_path)
    first = store.upload(archive(), session())
    duplicate = store.upload(archive(), session())
    other = store.upload(archive(), session(OTHER))
    assert first['packageId'] == duplicate['packageId']
    assert first['packageId'] != other['packageId']
    with pytest.raises(mod.PackageError):
        store.preview(first['packageId'], session(OTHER))
    assert mod.PackageStore(tmp_path).preview(first['packageId'], session())['manifest']['name'] == 'custom-archive-one'


@pytest.mark.parametrize('paths', [
    ['A.py','a.py'], ['café.py','cafe\u0301.py'], ['x.py','x.py'],
    ['folder','folder/main.py'], ['folder','folder/'], ['dir/Main.py','DIR/other.py'],
])
def test_zip_filesystem_aliases_are_rejected(tmp_path, paths):
    mod = importlib.import_module('ops.packages')
    entries = [('manifest.json',manifest(),stat.S_IFREG|0o644)]
    entries += [(p,b'', (stat.S_IFDIR|0o755) if p.endswith('/') else (stat.S_IFREG|0o644)) for p in paths]
    with pytest.raises(mod.PackageError):
        mod.PackageStore(tmp_path).upload(archive(entries), session())


@pytest.mark.parametrize('path', ['../escape','/absolute','C:/drive','dir\\escape','dir/../escape',
                                '.env','.ENV.local','.git/config','.cache/file','__pycache__/file'])
def test_unsafe_archive_paths_cannot_publish(tmp_path, path):
    mod = importlib.import_module('ops.packages')
    data = archive([('manifest.json',manifest(),stat.S_IFREG|0o644),(path,b'x',stat.S_IFREG|0o644)])
    with pytest.raises(mod.PackageError):
        mod.PackageStore(tmp_path).upload(data, session())
    assert not list((tmp_path/'.cache/packages').glob('*/*/source'))


@pytest.mark.parametrize('mode', [stat.S_IFLNK|0o777, stat.S_IFIFO|0o600,
                                stat.S_IFREG|0o4644, stat.S_IFREG|0o2644])
def test_symlinks_special_files_and_permissions_are_rejected(tmp_path, mode):
    mod = importlib.import_module('ops.packages')
    with pytest.raises(mod.PackageError):
        mod.PackageStore(tmp_path).upload(archive([
            ('manifest.json',manifest(),stat.S_IFREG|0o644),('unsafe',b'outside',mode)]), session())


@pytest.mark.parametrize('kind', ['compressed_size','uncompressed_size','file_count','corrupt','encrypted'])
def test_archive_limits_reject_before_a_source_is_published(tmp_path, kind):
    mod = importlib.import_module('ops.packages')
    if kind == 'compressed_size':
        data = b'x'*(10*1024*1024+1)
    elif kind == 'uncompressed_size':
        data = archive([('manifest.json',manifest(),stat.S_IFREG|0o644),
                        ('large',b'x'*(20*1024*1024+1),stat.S_IFREG|0o644)])
    elif kind == 'file_count':
        entries=[('manifest.json',manifest(),stat.S_IFREG|0o644)]
        entries += [(f'file-{i}',b'x',stat.S_IFREG|0o644) for i in range(512)]
        data=archive(entries)
    elif kind == 'corrupt':
        data=b'not-a-zip'
    else:
        data=bytearray(archive())
        for signature, offset in [(b'PK\x03\x04',6),(b'PK\x01\x02',8)]:
            pos=0
            while (pos := data.find(signature,pos)) >= 0:
                data[pos+offset] |= 1
                pos += 4
        data=bytes(data)
    with pytest.raises(mod.PackageError):
        mod.PackageStore(tmp_path).upload(data,session())
    assert not list((tmp_path/'.cache/packages').glob('*/*/source'))


@pytest.mark.parametrize('name,version,valid', [
    ('a'*128,'1',True),('a'*129,'1',False),('a','1'*64,True),('a','1'*65,False),
    ('自定义技能','1.0.0',True),('..','1',False),('a/../b','1',False),(' leading','1',False),
])
def test_publish_and_install_share_identity_constraints(tmp_path, name, version, valid):
    mod=importlib.import_module('ops.packages')
    identity=importlib.import_module('gate.identity')
    store=mod.PackageStore(tmp_path)
    if valid:
        info=store.upload(archive(name=name,version=version),session())
        assert info['manifest']['name'] == name
        assert identity.safe_identity_component(name,128) == name
        assert identity.safe_identity_component(version,64) == version
    else:
        with pytest.raises(mod.PackageError):
            store.upload(archive(name=name,version=version),session())


def test_disk_content_replacement_and_arbitrary_sources_are_rejected(tmp_path):
    mod=importlib.import_module('ops.packages')
    store=mod.PackageStore(tmp_path)
    info=store.upload(archive(),session())
    (tmp_path/info['source']/'main.py').write_bytes(b'CHANGED = True\n')
    with pytest.raises(mod.PackageError):
        store.capture(info['packageId'],OWNER)
    for source in ['.env','../escape','/etc','.cache/packages/../../escape']:
        with pytest.raises(mod.PackageError):
            store.resolve_source(source)


@pytest.mark.parametrize('content', [b'{}',b'{bad',b'[]',b'{"name":"a","name":"b"}'])
def test_invalid_manifest_is_rejected(tmp_path, content):
    mod=importlib.import_module('ops.packages')
    with pytest.raises(mod.PackageError):
        mod.PackageStore(tmp_path).upload(archive([('manifest.json',content,stat.S_IFREG|0o644)]),session())


def test_zip_http_upload_requires_signed_wallet_and_keeps_other_json_limits(tmp_path, monkeypatch):
    appmod=importlib.import_module('ops.app')
    authmod=importlib.import_module('ops.auth')
    monkeypatch.setattr(appmod,'load_scope',lambda _:SCOPE)
    monkeypatch.setattr(authmod,'is_eoa',lambda *args:True)
    app=appmod.OpsApplication(tmp_path)
    origin='http://127.0.0.1:8765'
    message=app.auth.challenge(OWNER,SCOPE,origin)
    sig=Account.from_key('0x'+'11'*32).sign_message(encode_defunct(text=message)).signature.hex()
    token,_=app.auth.verify(message,sig,SCOPE,origin)
    headers={'Host':'127.0.0.1:8765','Origin':origin,'Content-Type':'application/zip',
             'X-SkillGuard-Token':app.csrf_token,'Cookie':'sg_session='+token,
             'X-SkillGuard-Wallet':OWNER}
    result=app.handle('POST','/api/packages',headers,archive())
    assert result.status == 201
    preview=json.loads(result.body)['data']
    assert preview['publisher'] == OWNER
    assert preview['manifest']['name'] == 'custom-archive-one'
    headers.pop('Cookie')
    assert app.handle('POST','/api/packages',headers,archive()).status == 401
    assert app.handle('POST','/api/auth/challenge',headers,archive()).status == 415


def test_real_http_transport_accepts_raw_zip(tmp_path, monkeypatch):
    import threading
    import http.client
    from ops.server import OpsHTTPServer
    import ops.app as appmod
    import ops.auth as authmod
    monkeypatch.setattr(appmod, 'load_scope', lambda _: SCOPE)
    monkeypatch.setattr(authmod, 'is_eoa', lambda *args: True)
    server = OpsHTTPServer(('127.0.0.1', 0), project_root=tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    message = server.application.auth.challenge(OWNER, SCOPE, origin)
    signature = Account.from_key('0x'+'11'*32).sign_message(encode_defunct(text=message)).signature.hex()
    token, _ = server.application.auth.verify(message, signature, SCOPE, origin)
    client = http.client.HTTPConnection('127.0.0.1', server.server_port, timeout=5)
    try:
        client.request('POST', '/api/packages', archive(), headers={
            'Origin': origin, 'Content-Type': 'application/zip',
            'X-SkillGuard-Token': server.csrf_token, 'Cookie': 'sg_session='+token})
        response = client.getresponse()
        payload = json.loads(response.read())
        assert response.status == 201, payload
        assert payload['data']['manifest']['name'] == 'custom-archive-one'
    finally:
        client.close()
        server.shutdown()
        server.server_close()
        thread.join(5)

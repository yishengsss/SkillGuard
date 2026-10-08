from ops.app import OpsApplication
import pytest

@pytest.mark.parametrize('route,mime',[('/','text/html'),('/publish','text/html'),('/assets/api.mjs','text/javascript'),('/assets/app.css','text/css')])
def test_role_resources_direct_refresh(tmp_path,route,mime):
    app=OpsApplication(tmp_path)
    reply=app.handle('GET',route,{'Host':'127.0.0.1:8765'},b'')
    assert reply.status==200
    assert reply.headers['Content-Type'].startswith(mime)

@pytest.mark.parametrize('route',['/.env','/../.env','/assets/../.env','/tests/fixtures/role-wallet.mjs','/reports/anything.json','/assets/not-public.mjs','/skills/not-a-key'])
def test_static_routes_are_explicit_allowlist(tmp_path,route):
    app=OpsApplication(tmp_path)
    assert app.handle('GET',route,{'Host':'127.0.0.1:8765'},b'').status==404


def test_symlink_static_file_is_not_served(tmp_path):
    web=tmp_path/'web/assets';web.mkdir(parents=True)
    secret=tmp_path/'.env';secret.write_text('TEST_ONLY_SECRET=hidden')
    (web/'api.mjs').symlink_to(secret)
    reply=OpsApplication(tmp_path).handle('GET','/assets/api.mjs',{'Host':'127.0.0.1:8765'},b'')
    assert reply.status==404 and b'TEST_ONLY_SECRET' not in reply.body


@pytest.mark.parametrize('route',['/audit','/admin','/install','/skills/'+'0x'+'ab'*32])
def test_all_remaining_role_pages_can_refresh(tmp_path,route):
    reply=OpsApplication(tmp_path).handle('GET',route,{'Host':'127.0.0.1:8765'},b'')
    assert reply.status==200 and b'<nav' in reply.body

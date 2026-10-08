import importlib,json
import pytest
from auditor.skill_dir import capture_skill
from auditor.hashing import code_hash,metadata_hash
from tests.test_ops_reports import SCOPE,KEY


def test_install_uses_only_registered_source_and_preserves_previous(tmp_path,monkeypatch):
    mod=importlib.import_module('ops.install_service')
    source=tmp_path/'source';source.mkdir()
    (source/'manifest.json').write_text(json.dumps({'name':'install-example','version':'1','package':'test','tools':[]}))
    (source/'main.py').write_text('VALUE = 1\n')
    snapshot=capture_skill(source,source_root=tmp_path)
    row={'source':'source','name':'install-example','version':'1','codeHash':'0x'+code_hash(snapshot).hex(),'metadataHash':'0x'+metadata_hash(snapshot).hex(),'status':4}
    svc=mod.InstallService(tmp_path)
    class Repository:
        def detail(self,*args): return row
    svc.chain=Repository();monkeypatch.setattr(mod,'load_scope',lambda _:SCOPE)
    old=tmp_path/'installed/install-example-1';old.mkdir(parents=True);(old/'main.py').write_text('OLD\n')
    monkeypatch.setattr(mod.mcp_server,'check_skill',lambda *args,**kwargs:{'allowed':False,'reason':'恶意技能','status':'malicious'})
    assert svc.execute(SCOPE,KEY)['installed'] is False
    assert (old/'main.py').read_text()=='OLD\n'
    row['source']='../escape'
    with pytest.raises(Exception): svc.check(SCOPE,KEY)
    row['source']='source';(source/'main.py').write_text('CHANGED\n')
    with pytest.raises(Exception): svc.execute(SCOPE,KEY)


def test_install_keeps_requested_snapshot_when_source_is_replaced(tmp_path,monkeypatch):
    from types import SimpleNamespace
    mod=importlib.import_module('ops.install_service')
    source=tmp_path/'source';source.mkdir()
    def replace(name):
        (source/'manifest.json').write_text(json.dumps({'name':name,'version':'1','package':'test','tools':[]}))
        (source/'main.py').write_text(name)
    replace('requested-A');snapshot=capture_skill(source,source_root=tmp_path)
    svc=mod.InstallService(tmp_path)
    svc.chain=SimpleNamespace(detail=lambda *args:{'source':'source','name':'requested-A','version':'1','codeHash':'0x'+code_hash(snapshot).hex(),'metadataHash':'0x'+metadata_hash(snapshot).hex()})
    monkeypatch.setattr(mod,'load_scope',lambda _:SCOPE)
    def check(captured,**kwargs):
        name=json.loads(captured.manifest_bytes)['name'];replace('verified-B')
        return {'allowed':True,'skill':name,'version':'1'}
    monkeypatch.setattr(mod.mcp_server,'check_skill',check)
    monkeypatch.setattr(mod.mcp_server,'load_gate_config',lambda _:None)
    monkeypatch.setattr(mod.mcp_server,'check_install',lambda path,_:SimpleNamespace(allowed=True))
    result=svc.execute(SCOPE,KEY)
    assert result['installed'] and result['skill']=='requested-A'
    assert (tmp_path/'installed/requested-A-1/main.py').read_text()=='requested-A'
    assert not (tmp_path/'installed/verified-B-1').exists()

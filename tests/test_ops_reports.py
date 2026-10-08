import importlib
from auditor.storage import save_report
from ops.models import ChainScope
import pytest
SCOPE=ChainScope(31337,'0x'+'22'*20,'0x'+'33'*20,0,'revision')
KEY='0x'+'11'*32


def service(tmp_path,monkeypatch):
    mod=importlib.import_module('ops.reports')
    payload={'skill':'history-example','version':'1','auditor':'0x'+'44'*20,'codeHash':'0x'+'55'*32,'metadataHash':'0x'+'66'*32,'level':'SAFE','findings':[]}
    path,hash_=save_report(payload,tmp_path/'reports')
    row={'key':KEY,'name':payload['skill'],'version':'1','publisher':'0x'+'77'*20,'codeHash':payload['codeHash'],'metadataHash':payload['metadataHash'],'auditor':payload['auditor'],'reportHash':hash_,'status':3,'source':'nonexistent','license':{'tokenId':'1'}}
    class Repository:
        def catalog(self,scope): return [row]
        def detail(self,scope,key): return row
    monkeypatch.setattr(mod,'load_scope',lambda _:SCOPE)
    obj=mod.ReportService(tmp_path);obj.chain=Repository()
    return obj,path,hash_,row


def test_historical_result_without_logs_is_explicit(tmp_path,monkeypatch):
    svc,path,hash_,row=service(tmp_path,monkeypatch)
    view=svc.detail(SCOPE,KEY)
    assert view['historyNote']=='已有审计结果，未保存运行日志'
    assert view['events']==[] and view['report']['reportMatchesChain'] is True
    path.unlink()
    assert svc.read(SCOPE,hash_)['availability']=='missing'


def test_foreign_or_corrupted_report_is_not_verified(tmp_path,monkeypatch):
    svc,path,hash_,row=service(tmp_path,monkeypatch)
    path.write_text('{"skill":"changed"}')
    view=svc.read(SCOPE,hash_)
    assert view['availability']=='corrupt' and view['reportMatchesChain'] is False
    with pytest.raises(Exception): svc.read(SCOPE,'0x'+'99'*32)

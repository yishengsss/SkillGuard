import importlib
import multiprocessing
import threading
from types import SimpleNamespace
from tests.test_agent import make_ctx,RecordingSubmitter
from auditor.agent import AuditRequest,run_once


def competitor(root,queue):
    from auditor.worker import AgentLease
    with AgentLease(root,31337,'different-registry','same-auditor','cli') as lease:
        queue.put(lease.acquired)


def test_cli_and_managed_agent_share_wallet_lease(tmp_path):
    AgentLease=importlib.import_module('auditor.worker').AgentLease
    ctx=multiprocessing.get_context('fork');queue=ctx.Queue()
    with AgentLease(tmp_path,31337,'first-registry','same-auditor','web') as first:
        assert first.acquired
        process=ctx.Process(target=competitor,args=(tmp_path,queue));process.start();process.join(5)
        assert process.exitcode==0 and queue.get(timeout=1) is False
    with AgentLease(tmp_path,31337,'second-registry','same-auditor','cli') as second:
        assert second.acquired


def test_stop_preserves_unstarted_request_cursor(tmp_path):
    ctx=make_ctx(tmp_path,submitter=RecordingSubmitter())
    ctx.stop_requested=lambda:True
    ctx.fetch_requests=lambda *args:[AuditRequest(b'\x11'*32,7),AuditRequest(b'\x22'*32,7)]
    cursor,latest=run_once(ctx,0)
    assert cursor==7 and latest==10 and ctx.outcomes==[]


def test_worker_heartbeat_survives_receipt_wait_and_releases(tmp_path,monkeypatch):
    mod=importlib.import_module('auditor.worker')
    ctx=make_ctx(tmp_path,submitter=RecordingSubmitter());ctx.contract.address='registry'
    stop=threading.Event();entered=threading.Event();release=threading.Event()
    def slow(*args):
        entered.set();release.wait(5);return 11,10
    monkeypatch.setattr(mod,'run_once',slow)
    thread=threading.Thread(target=mod.run_worker,args=(ctx,stop,.01));thread.start()
    assert entered.wait(3)
    status=mod.lease_status(tmp_path,31337,ctx.account.address)
    assert status['state']=='running' and status['source']=='cli'
    stop.set();release.set();thread.join(5)
    assert not thread.is_alive()
    assert mod.lease_status(tmp_path,31337,ctx.account.address)['state']=='stopped'


def test_activation_waits_for_old_scope_broadcast(tmp_path,monkeypatch):
    import time
    from ops.models import ChainScope,APIError
    mod=importlib.import_module('ops.agent_service')
    worker=importlib.import_module('auditor.worker')
    scope=ChainScope(31337,'registry','license',1,'revision')
    monkeypatch.setattr(mod,'load_scope',lambda _:scope)
    monkeypatch.setattr(mod,'auditor_address',lambda _:'auditor')
    manager=mod.ManagedAgent(tmp_path)
    with worker.AgentLease(tmp_path,31337,'registry','auditor','cli'):
        import pytest
        with pytest.raises(APIError,match='尚未完成'):
            manager.drain_for_activation('revision',timeout=.05)
    manager.drain_for_activation('revision',timeout=.1)
    assert manager.stop_event.is_set()


def test_old_context_cannot_start_after_activation(tmp_path,monkeypatch):
    import json,pytest
    mod=importlib.import_module('auditor.worker')
    ctx=make_ctx(tmp_path,submitter=RecordingSubmitter());ctx.contract.address='old-registry'
    (tmp_path/'deployments.json').write_text(json.dumps({'chainId':31337,'SkillRegistry':'old-registry'}))
    ctx.deployment_revision=mod.deployment_revision(tmp_path)
    (tmp_path/'deployments.json').write_text(json.dumps({'chainId':31337,'SkillRegistry':'new-registry'}))
    calls=[]
    monkeypatch.setattr(mod,'run_once',lambda *args:(calls.append('processed') or (0,0)))
    with pytest.raises(RuntimeError,match='部署'):
        mod.run_worker(ctx,threading.Event(),once=True)
    assert calls==[]


def test_browser_reservation_blocks_worker_until_receipt_or_expiry(tmp_path,monkeypatch):
    import pytest
    mod=importlib.import_module('auditor.worker')
    ctx=make_ctx(tmp_path,submitter=RecordingSubmitter());ctx.contract.address='registry'
    mod.reserve_browser(tmp_path,31337,ctx.account.address,'prepared',seconds=600)
    calls=[];monkeypatch.setattr(mod,'run_once',lambda *args:(calls.append('processed') or (0,0)))
    with pytest.raises(RuntimeError,match='钱包交易'):
        mod.run_worker(ctx,threading.Event(),once=True)
    assert not calls
    mod.release_browser(tmp_path,31337,ctx.account.address,'different')
    assert mod.browser_reserved(tmp_path,31337,ctx.account.address)
    mod.release_browser(tmp_path,31337,ctx.account.address,'prepared')
    mod.run_worker(ctx,threading.Event(),once=True)
    assert calls==['processed']
    mod.reserve_browser(tmp_path,31337,ctx.account.address,'abandoned',seconds=-1)
    assert not mod.browser_reserved(tmp_path,31337,ctx.account.address)

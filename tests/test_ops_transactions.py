import importlib
from types import SimpleNamespace
from dataclasses import replace
import pytest
from web3 import Web3
from ops.models import ChainScope, WalletSession

ADDRESS = Web3.to_checksum_address('0x'+'11'*20)
REGISTRY = Web3.to_checksum_address('0x'+'22'*20)
LICENSE = Web3.to_checksum_address('0x'+'33'*20)
SCOPE = ChainScope(31337, REGISTRY, LICENSE, 0, 'revision')
SESSION = WalletSession(ADDRESS,SCOPE,9999999999)
HASH = '0x'+'ab'*32

class Eth:
    chain_id=31337
    gas_price=3
    def estimate_gas(self,tx): return 100
    def get_balance(self,address): return 10**20
    def get_transaction(self,h): return self.tx
    def get_transaction_receipt(self,h): return self.receipt

@pytest.fixture
def service(tmp_path,monkeypatch):
    mod=importlib.import_module('ops.transactions')
    eth=Eth()
    monkeypatch.setattr(mod,'load_scope',lambda _:SCOPE)
    monkeypatch.setattr(mod,'web3_for',lambda *args:SimpleNamespace(eth=eth))
    return mod.TransactionService(tmp_path),eth,mod

@pytest.mark.parametrize('field,value',[('from',LICENSE),('to',LICENSE),('input','0x1235'),('value',1),('chainId',968)])
def test_confirm_requires_exact_sender_call_and_receipt(service,field,value):
    svc,eth,mod=service
    prepared=svc.store(SESSION,REGISTRY,'0x1234',0,{'action':'test'})
    eth.tx={'from':ADDRESS,'to':REGISTRY,'input':'0x1234','value':0,'chainId':31337}
    eth.tx[field]=value
    eth.receipt={'status':1,'blockNumber':2,'transactionHash':HASH}
    with pytest.raises(mod.TransactionError): svc.confirm(prepared['id'],HASH,SESSION)


def test_pending_failed_confirmed_and_other_wallet(service):
    from web3.exceptions import TransactionNotFound
    svc,eth,mod=service
    prepared=svc.store(SESSION,REGISTRY,'0x1234',0,{'action':'test'})
    eth.tx={'from':ADDRESS,'to':REGISTRY,'input':'0x1234','value':0,'chainId':31337}
    eth.receipt={'status':1,'blockNumber':2,'transactionHash':HASH}
    assert svc.confirm(prepared['id'],HASH,SESSION)['status']=='confirmed'
    eth.receipt['status']=0
    assert svc.confirm(prepared['id'],HASH,SESSION)['status']=='failed'
    with pytest.raises(mod.TransactionError): svc.confirm(prepared['id'],HASH,replace(SESSION,address=LICENSE))
    def pending(h): raise TransactionNotFound('pending')
    eth.get_transaction_receipt=pending
    assert svc.confirm(prepared['id'],HASH,SESSION)['status']=='pending'


def test_wrong_revision_and_unsupported_chain(service):
    svc,eth,mod=service
    with pytest.raises(mod.TransactionError): svc.store(replace(SESSION,scope=replace(SCOPE,chain_id=1)),REGISTRY,'0x12',0,{})
    prepared=svc.store(SESSION,REGISTRY,'0x12',0,{})
    with pytest.raises(mod.TransactionError): svc.confirm(prepared['id'],HASH,replace(SESSION,scope=replace(SCOPE,revision='other')))


def test_browser_auditor_cannot_prepare_while_worker_selects_nonce(service,monkeypatch):
    from auditor.worker import AgentLease
    svc,_,mod=service
    monkeypatch.setattr(mod,'auditor_address',lambda _:ADDRESS)
    with AgentLease(svc.root,31337,REGISTRY,ADDRESS,'cli'):
        with pytest.raises(mod.TransactionError,match='worker'):
            svc.prepare('human_decision',SESSION,{'key':HASH,'decision':'safe'})

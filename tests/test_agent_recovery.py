import importlib
from types import SimpleNamespace
from eth_account import Account
from web3 import Web3
from web3.exceptions import TransactionNotFound
from auditor.storage import save_report


def test_lost_broadcast_response_reuses_original_transaction(tmp_path):
    Journal=importlib.import_module('auditor.journal').Journal
    recover=importlib.import_module('auditor.recovery').recover_submission
    account=Account.from_key('0x'+'11'*32)
    tx={'to':'0x'+'22'*20,'value':0,'gas':50000,'gasPrice':1,'nonce':0,'chainId':31337,'data':'0x1234'}
    signed=account.sign_transaction(tx);hash_=Web3.to_hex(Web3.keccak(signed.raw_transaction))
    report={'skill':'recover','version':'1','auditor':account.address,'level':'SAFE'}
    _,digest=save_report(report,tmp_path/'reports')
    journal=Journal(tmp_path);run=journal.begin(31337,tx['to'],'0x'+'aa'*32,1)
    journal.emit(run,'report_saved',{'reportHash':digest})
    journal.emit(run,'tx_intent',{'txHash':hash_,'nonce':0,'transaction':tx})
    class Eth:
        chain_id=31337
        sent=[]
        receipt=None
        nonce=0
        def get_code(self,*args,**kwargs):return b"code"
        def get_transaction_receipt(self,h):
            assert h==hash_
            if self.receipt: return self.receipt
            raise TransactionNotFound('not yet')
        def get_transaction(self,h): raise TransactionNotFound('lost response')
        def get_transaction_count(self,*a): return self.nonce
        def send_raw_transaction(self,raw):
            assert raw==signed.raw_transaction
            self.sent.append(raw);self.receipt={'status':1,'blockNumber':2}
            return bytes.fromhex(hash_[2:])
    eth=Eth();ctx=SimpleNamespace(root=tmp_path,w3=SimpleNamespace(eth=eth),account=account,chain_id=31337,contract=SimpleNamespace(address=tx['to'],functions=SimpleNamespace(protocolVersion=lambda:SimpleNamespace(call=lambda **k:1),keyOf=lambda *a:SimpleNamespace(call=lambda **k:b'k'*32),skills=lambda *a:SimpleNamespace(call=lambda **k:('publisher','source',b'c'*32,b'm'*32,0,3,bytes.fromhex(digest[2:]),account.address)))))
    assert recover(ctx,run,Journal(tmp_path))=='pending'
    assert recover(ctx,run,Journal(tmp_path))=='confirmed'
    assert len(eth.sent)==1
    assert journal.events(run)[-1]['stage']=='receipt_confirmed'


def test_nonce_conflict_never_broadcasts(tmp_path):
    # Use a real signed intent, but nonce was consumed by another transaction.
    from tests.test_agent_recovery import test_lost_broadcast_response_reuses_original_transaction
    Journal=importlib.import_module('auditor.journal').Journal
    recover=importlib.import_module('auditor.recovery').recover_submission
    journal=Journal(tmp_path);run=journal.begin(31337,'0x'+'22'*20,'0x'+'aa'*32,1)
    _,digest=save_report({'skill':'recover'},tmp_path/'reports')
    journal.emit(run,'report_saved',{'reportHash':digest})
    journal.emit(run,'tx_intent',{'txHash':'0x'+'ab'*32,'nonce':0,'transaction':{'nonce':0,'chainId':31337}})
    class Eth:
        chain_id=31337
        def get_transaction_receipt(self,h): raise TransactionNotFound('absent')
        def get_transaction(self,h): raise TransactionNotFound('absent')
        def get_transaction_count(self,*args): return 1
        def send_raw_transaction(self,raw): raise AssertionError('must not send')
    ctx=SimpleNamespace(root=tmp_path,chain_id=31337,w3=SimpleNamespace(eth=Eth()),account=Account.from_key('0x'+'11'*32),contract=SimpleNamespace(address='0x'+'22'*20))
    assert recover(ctx,run,journal)=='conflict'

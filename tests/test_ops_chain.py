import importlib
import pytest

def test_strict_chain_hash_validation():
    mod=importlib.import_module('ops.chain')
    assert mod.hex32('0x'+'ab'*32)=='0x'+'ab'*32
    for value in ['../x','0x1','0x'+'zz'*32,None,1]:
        with pytest.raises(mod.APIError): mod.hex32(value)


@pytest.mark.anvil
def test_real_catalog_two_publishers_and_exact_confirmed_state(tmp_path):
    import io,json,zipfile
    from tests.roles_fixtures import make_role_fixture
    from ops.models import WalletSession
    from ops.packages import PackageStore
    from ops.transactions import TransactionService,TransactionError
    from ops.chain import ChainRepository
    fixture=make_role_fixture(tmp_path)
    try:
        store=PackageStore(tmp_path);service=TransactionService(tmp_path);repo=ChainRepository(tmp_path)
        keys=[]
        for index,publisher in enumerate(fixture.publishers):
            session=WalletSession(publisher.address,fixture.scope,9999999999)
            output=io.BytesIO()
            with zipfile.ZipFile(output,'w') as archive:
                archive.writestr('manifest.json',json.dumps({'name':f'unique-role-{index}','version':'1','package':'role-test','tools':[]}))
                archive.writestr('main.py','VALUE = 1\n')
            preview=store.upload(output.getvalue(),session)
            prepared=service.prepare('register',session,{'packageId':preview['packageId']})
            hash_=fixture.w3.to_hex(fixture.w3.eth.send_transaction({'from':prepared['from'],'to':prepared['to'],'data':prepared['data'],'value':int(prepared['value'])}))
            fixture.w3.eth.wait_for_transaction_receipt(hash_)
            assert service.confirm(prepared['id'],hash_,session)['status']=='confirmed'
            own=repo.catalog(fixture.scope,publisher.address)
            assert len(own)==1 and own[0]['codeHash']==preview['codeHash']
            keys.append(own[0]['key'])
            with pytest.raises(TransactionError): service.prepare('register',session,{'packageId':preview['packageId']})
            prepared=service.prepare('request_audit',session,{'key':own[0]['key']})
            hash_=fixture.w3.to_hex(fixture.w3.eth.send_transaction({'from':prepared['from'],'to':prepared['to'],'data':prepared['data'],'value':int(prepared['value'])}))
            fixture.w3.eth.wait_for_transaction_receipt(hash_)
            assert service.confirm(prepared['id'],hash_,session)['status']=='confirmed'
        assert len(repo.catalog(fixture.scope))==2
        with pytest.raises(TransactionError): service.prepare('request_audit',WalletSession(fixture.publishers[1].address,fixture.scope,9999999999),{'key':keys[0]})
    finally: fixture.close()

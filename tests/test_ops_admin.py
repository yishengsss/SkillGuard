import importlib
import pytest
from tests.test_ops_transactions import SESSION,SCOPE,REGISTRY,LICENSE

def test_non_owner_cannot_prepare_deploy(tmp_path,monkeypatch):
    mod=importlib.import_module('ops.admin')
    monkeypatch.setattr(mod,'load_scope',lambda _:SCOPE)
    class Function:
        def call(self): return LICENSE
    class Functions:
        def owner(self): return Function()
    monkeypatch.setattr(mod,'contracts',lambda *args:(None,type('R',(),{'functions':Functions()})(),None))
    with pytest.raises(mod.APIError): mod.AdminService(tmp_path).prepare('deploy_registry',SESSION,{})


@pytest.mark.anvil
def test_real_wallet_deployment_activation_and_competing_revision(tmp_path):
    from tests.roles_fixtures import make_role_fixture
    from ops.admin import AdminService
    from ops.models import WalletSession
    from ops.config import load_scope
    from ops.transactions import TransactionError
    fixture=make_role_fixture(tmp_path)
    try:
        admin=AdminService(tmp_path)
        session=WalletSession(fixture.owner.address,fixture.scope,9999999999)
        hashes=[]
        for step in ('deploy_registry','deploy_license','wire_registry','wire_license'):
            prepared=admin.prepare(step,session,{'creationTxHashes':hashes[:2]})
            tx={'from':prepared['from'],'data':prepared['data'],'value':int(prepared['value']),'gas':int(prepared['estimatedGas'])}
            if prepared['to']: tx['to']=prepared['to']
            hash_=fixture.w3.eth.send_transaction(tx).hex()
            hash_='0x'+hash_.removeprefix('0x')
            fixture.w3.eth.wait_for_transaction_receipt(hash_)
            assert admin.confirm(prepared['id'],hash_,session)['status']=='confirmed'
            hashes.append(hash_)
        before=(tmp_path/'deployments.json').read_bytes()
        with pytest.raises(TransactionError): admin.activate(session,session.scope.revision,list(reversed(hashes)))
        assert (tmp_path/'deployments.json').read_bytes()==before
        activated=admin.activate(session,session.scope.revision,hashes)
        assert activated.revision!=session.scope.revision
        with pytest.raises(TransactionError): admin.activate(session,session.scope.revision,hashes)
        assert load_scope(tmp_path)==activated
    finally: fixture.close()

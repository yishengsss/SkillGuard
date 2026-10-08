from types import SimpleNamespace
import pytest
from web3.exceptions import ContractLogicError


def fake(version=None,error=None,code=b'code'):
    def call(**kwargs):
        if error:raise error
        return version
    reg=SimpleNamespace(address='address',functions=SimpleNamespace(protocolVersion=lambda:SimpleNamespace(call=call)))
    w3=SimpleNamespace(eth=SimpleNamespace(get_code=lambda *a,**k:code))
    return w3,reg


def test_new_and_legacy_protocol():
    from auditor.protocol import registry_capabilities
    assert registry_capabilities(*fake(2))['arbitrationSupported']
    assert registry_capabilities(*fake(error=ContractLogicError('execution reverted')))['protocolVersion']==1


def test_rpc_failure_and_missing_code_are_not_legacy():
    from auditor.protocol import registry_capabilities
    with pytest.raises(RuntimeError):registry_capabilities(*fake(error=ConnectionError()))
    with pytest.raises(RuntimeError):registry_capabilities(*fake(2,code=b''))
    with pytest.raises(RuntimeError):registry_capabilities(*fake(3))

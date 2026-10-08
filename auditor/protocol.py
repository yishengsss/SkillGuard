"""Protocol detection: transport failure must never masquerade as a legacy contract."""
from web3.exceptions import ContractLogicError

VERSION_ABI={'type':'function','name':'protocolVersion','stateMutability':'pure','inputs':[],'outputs':[{'type':'uint256'}]}


def registry_capabilities(w3,registry,block_identifier='latest'):
    try:
        if not w3.eth.get_code(registry.address,block_identifier=block_identifier):raise RuntimeError('部署地址没有代码')
        try:version=int(registry.functions.protocolVersion().call(block_identifier=block_identifier))
        except ContractLogicError:version=1
        if version not in (1,2):raise RuntimeError('不支持的合约协议版本')
        return {'protocolVersion':version,'arbitrationSupported':version==2}
    except RuntimeError:raise
    except Exception:raise RuntimeError('合约协议读取失败，无法确认资金规则') from None

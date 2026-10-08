"""Read scoped deployment and RPC without publishing signing credentials."""
import hashlib
import json
import os
import sys
from pathlib import Path

from dotenv import dotenv_values
from eth_account import Account
from web3 import Web3

from .models import APIError, ChainScope


def settings(root: Path) -> dict[str, str]:
    result = {k: v for k, v in dotenv_values(root / '.env').items() if v is not None}
    for name in ('RPC_URL', 'AUDITOR_PRIVATE_KEY'):
        if name in os.environ:
            result[name] = os.environ[name]
    return result


def load_scope(root: Path) -> ChainScope:
    try:
        path = root / 'deployments.json'
        if path.is_symlink():
            raise ValueError('symlink')
        data = json.loads(path.read_text())
        chain_id = data['chainId']
        block = data.get('deploymentBlock', 0)
        if (type(chain_id) is not int or chain_id <= 0 or type(block) is not int or block < 0
                or not Web3.is_address(data['SkillRegistry'])
                or not Web3.is_address(data['SkillLicense'])):
            raise ValueError('invalid deployment')
        revision = hashlib.sha256(json.dumps(data, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        return ChainScope(chain_id, Web3.to_checksum_address(data['SkillRegistry']),
                          Web3.to_checksum_address(data['SkillLicense']), block, revision)
    except (OSError, ValueError, KeyError, TypeError):
        raise APIError('部署配置缺失或无效，请先完成本机 CLI 部署', 503, 'configuration') from None


def web3_for(root: Path, scope: ChainScope | None = None) -> Web3:
    rpc = settings(root).get('RPC_URL', '').strip()
    if not rpc:
        raise APIError('未配置 RPC_URL', 503, 'configuration')
    w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={'timeout': 15}))
    try:
        if scope is not None and w3.eth.chain_id != scope.chain_id:
            raise APIError('RPC 网络与部署配置不匹配', 409, 'wrong_chain')
    except APIError:
        raise
    except Exception:
        raise APIError('RPC 读取失败，请稍后重试', 503, 'rpc_unavailable') from None
    return w3


def auditor_address(root: Path) -> str | None:
    key = settings(root).get('AUDITOR_PRIVATE_KEY', '').strip()
    if not key:
        return None
    try:
        return Account.from_key(key).address
    except Exception:
        raise APIError('审计服务钱包配置无效', 503, 'configuration') from None


def public_config(root: Path) -> dict:
    result = {'ready': False, 'auditor': None, 'wallet': {'eip1193': True, 'eip1271': False},
              'allowedChains': [31337, 968], 'reason': None}
    script=(root/'gate/mcp_server.py').resolve()
    # Preserve the venv entrypoint: resolving its symlink would invoke the base interpreter.
    result['mcpConfig']={'mcpServers':{'skillguard':{'command':str(Path(sys.executable).absolute()),'args':[str(script)]}}} if script.is_file() else None
    try:
        scope = load_scope(root)
        result.update(chainId=scope.chain_id, registry=scope.registry, license=scope.license,
                      deploymentBlock=scope.deployment_block, revision=scope.revision,
                      nativeSymbol='tBOT' if scope.chain_id == 968 else 'ETH')
        result['auditor'] = auditor_address(root)
        w3 = web3_for(root, scope)
        if not w3.eth.get_code(scope.registry) or not w3.eth.get_code(scope.license):
            raise APIError('部署地址没有合约代码', 503, 'configuration')
        registry = w3.eth.contract(address=scope.registry, abi=[{
            'type': 'function', 'name': 'owner', 'stateMutability': 'view',
            'inputs': [], 'outputs': [{'type': 'address'}]}])
        from .chain import artifact
        from auditor.protocol import registry_capabilities
        full_registry=w3.eth.contract(address=scope.registry,abi=artifact(root,'SkillRegistry')['abi'])
        capabilities=registry_capabilities(w3,full_registry)
        result.update(capabilities)
        if capabilities['arbitrationSupported']:
            result.update(arbiter=full_registry.functions.arbiter().call(),treasury=full_registry.functions.treasury().call(),arbitrationConfigured=full_registry.functions.arbitrationConfigured().call())
        result.update(owner=registry.functions.owner().call(), block=w3.eth.block_number, ready=True)
    except APIError as exc:
        result['reason'] = str(exc)
    except Exception:
        result['reason'] = '链上配置读取失败，请稍后重试'
    return result

"""Read each catalogue at one concrete block; never fabricate RPC results."""
import json
import re
import threading
import time
from pathlib import Path
from web3 import Web3
from .config import web3_for, load_scope
from .models import APIError
from auditor.protocol import registry_capabilities


def hex32(value):
    if not isinstance(value,str) or not re.fullmatch(r'0x[0-9a-fA-F]{64}',value):
        raise APIError('需要 32 字节十六进制标识',400,'invalid_hash')
    return value.lower()


def artifact(root,name):
    # Build output may be absent in a fixture root: use this checkout's frozen artifacts.
    path=root/'contracts/out'/f'{name}.sol'/f'{name}.json'
    if not path.is_file(): path=Path(__file__).resolve().parents[1]/'contracts/out'/f'{name}.sol'/f'{name}.json'
    try: return json.loads(path.read_text())
    except (OSError,ValueError): raise APIError('请先运行 forge build',503,'artifacts') from None


def contracts(root,scope):
    w3=web3_for(root,scope)
    if not w3.eth.get_code(scope.registry) or not w3.eth.get_code(scope.license):
        raise APIError('部署地址没有合约代码',503,'configuration')
    return (w3,w3.eth.contract(address=scope.registry,abi=artifact(root,'SkillRegistry')['abi']),
            w3.eth.contract(address=scope.license,abi=artifact(root,'SkillLicense')['abi']))


class ChainRepository:
    def __init__(self,root):
        self.root=root
        self.cache={}
        self.lock=threading.RLock()

    def catalog(self,scope,publisher=None):
        if load_scope(self.root)!=scope: raise APIError('部署作用域已改变',409,'scope_changed')
        with self.lock:
            w3,registry,license=contracts(self.root,scope)
            block=w3.eth.block_number
            identity=(scope.chain_id,scope.registry.lower())
            cached=self.cache.get(identity)
            if cached and cached['block']==block:
                rows=cached['rows']
            else:
                logs=list(cached['logs']) if cached and cached['block']<block else []
                start=cached['block']+1 if logs else scope.deployment_block
                for first in range(start,block+1,2000):
                    logs.extend(registry.events.SkillRegistered().get_logs(from_block=first,to_block=min(first+1999,block)))
                capabilities=registry_capabilities(w3,registry,block)
                rows=[self._row(registry,license,event,block,capabilities) for event in logs]
                self.cache[identity]={'block':block,'logs':logs,'rows':rows}
            return [dict(row) for row in rows if publisher is None or row['publisher'].lower()==publisher.lower()]

    def _row(self,registry,license,event,block,capabilities):
        args=event['args']; key=hex32(Web3.to_hex(args['key']))
        value=registry.functions.skills(key).call(block_identifier=block)
        token=license.functions.tokenOfKey(key).call(block_identifier=block)
        nft=None
        if token:
            info=license.functions.licenses(token).call(block_identifier=block)
            nft={'tokenId':str(token),'owner':license.functions.ownerOf(token).call(block_identifier=block),
                 'reportHash':Web3.to_hex(info[2]),'auditor':info[3],'timestamp':info[4]}
        arbitration=None
        if capabilities['arbitrationSupported'] and value[5] in (3,4,5,6):
            case=registry.functions.arbitrations(key).call(block_identifier=block)
            if case[2]:arbitration={'reporter':case[0],'originalReportHash':Web3.to_hex(case[1]),'openedAt':case[2],'deadline':case[3],'finalReportHash':Web3.to_hex(case[4]),'arbiter':registry.functions.arbiter().call(block_identifier=block),'treasury':registry.functions.treasury().call(block_identifier=block)}
        return {**capabilities,'arbitration':arbitration,'key':key,'name':args['skillId'],'version':args['version'],'publisher':value[0],
                'source':value[1],'codeHash':Web3.to_hex(value[2]),'metadataHash':Web3.to_hex(value[3]),
                'depositWei':str(value[4]),'status':value[5],'reportHash':Web3.to_hex(value[6]),
                'auditor':value[7],'license':nft,'block':block,'readAt':int(time.time()),
                'registrationTx':Web3.to_hex(event['transactionHash'])}

    def detail(self,scope,key):
        key=hex32(key)
        for row in self.catalog(scope):
            if row['key']==key: return row
        raise APIError('当前部署没有此技能',404,'not_found')

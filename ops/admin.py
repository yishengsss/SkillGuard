"""Five wallet-signed deployment steps (v2 adds arbitration roles) and serialized scope activation."""
import fcntl
import json
import os
import tempfile
from web3 import Web3
from .chain import artifact, contracts, hex32
from .config import load_scope
from .models import APIError
from .transactions import TransactionService, TransactionError

DEPLOY_STEPS_V1 = ('deploy_registry', 'deploy_license', 'wire_registry', 'wire_license')
DEPLOY_STEPS_V2 = ('deploy_registry', 'deploy_license', 'wire_registry', 'wire_license', 'configure_arbitration')


class AdminService:
    def __init__(self,root):
        self.root=root
        self.transactions=TransactionService(root)
        self.drain=None

    def _owner(self,session):
        scope=load_scope(self.root)
        if scope!=session.scope: raise TransactionError('部署作用域已改变')
        w3,registry,_=contracts(self.root,scope)
        if registry.functions.owner().call().lower()!=session.address.lower(): raise TransactionError('仅当前合约 owner 可以管理部署',403)
        return w3

    def _creation(self,w3,name,address):
        art=artifact(self.root,name)
        factory=w3.eth.contract(abi=art['abi'],bytecode=art['bytecode']['object'])
        return factory.constructor(address).data_in_transaction

    def _created(self,w3,name,hash_,session):
        hash_=hex32(hash_)
        tx=w3.eth.get_transaction(hash_); receipt=w3.eth.get_transaction_receipt(hash_)
        data=tx['input'] if isinstance(tx['input'],str) else Web3.to_hex(tx['input'])
        if (tx['from'].lower()!=session.address.lower() or tx.get('to') is not None or int(tx['value'])!=0
                or tx.get('chainId')!=session.scope.chain_id or receipt['status']!=1
                or data.lower()!=self._creation(w3,name,session.address).lower()):
            raise TransactionError('创建交易与冻结合约不符')
        address=receipt['contractAddress']
        code=Web3.to_hex(w3.eth.get_code(address))
        expected=artifact(self.root,name)['deployedBytecode']['object']
        if code.lower()!=expected.lower(): raise TransactionError('运行字节码与冻结合约不符')
        contract=w3.eth.contract(address=address,abi=artifact(self.root,name)['abi'])
        if contract.functions.owner().call().lower()!=session.address.lower(): raise TransactionError('新合约 owner 不符')
        return address,receipt['blockNumber']

    def _prepare_arbitration_roles(self,w3,session,payload):
        """校验第五步草稿：独立仲裁与公共资金地址必须公开、互异且非 owner，一次锁定不可改。"""
        abis=artifact(self.root,'SkillRegistry')['abi']
        if not any(item.get('name')=='configureArbitration' for item in abis):
            raise TransactionError('当前冻结合约程序不支持仲裁角色配置')
        raw_arbiter=payload.get('arbiter');raw_treasury=payload.get('treasury')
        if not Web3.is_address(raw_arbiter) or not Web3.is_address(raw_treasury):
            raise TransactionError('仲裁者与公共资金地址无效',400)
        arbiter=Web3.to_checksum_address(raw_arbiter);treasury=Web3.to_checksum_address(raw_treasury)
        owner_address=Web3.to_checksum_address(session.address)
        if arbiter==owner_address or treasury==owner_address or arbiter==treasury:
            raise TransactionError('仲裁者、公共资金与 owner 必须是三个不同地址',400)
        if int(arbiter,16)==0 or int(treasury,16)==0: raise TransactionError('地址不能为零地址',400)
        _,registry,_=contracts(self.root,session.scope)
        if registry.functions.arbitrationConfigured().call(): raise TransactionError('仲裁角色已锁定，不能再配置')
        return arbiter,treasury

    def prepare(self,step,session,payload):
        w3=self._owner(session)
        if step=='slash_auditor': return self.transactions.prepare(step,session,payload)
        if step=='configure_arbitration':
            arbiter,treasury=self._prepare_arbitration_roles(w3,session,payload)
            _,registry,_=contracts(self.root,session.scope)
            fn=registry.functions.configureArbitration(arbiter,treasury)
            # 第五步：草稿地址冻结在本机向导（页面 localStorage 恢复同一地址与回执）
            return self.transactions.store(session,session.scope.registry,fn._encode_transaction_data(),0,
                                           {'step':'configure_arbitration','arbiter':arbiter,'treasury':treasury,'creationTxHashes':payload.get('creationTxHashes')})
        if step in ('deploy_registry','deploy_license'):
            name='SkillRegistry' if step=='deploy_registry' else 'SkillLicense'
            return self.transactions.store(session,None,self._creation(w3,name,session.address),0,{'step':step})
        hashes=payload.get('creationTxHashes',[])
        if not isinstance(hashes,list) or len(hashes)!=2 or hashes[0]==hashes[1]: raise TransactionError('需要两笔不同的创建回执')
        registry,_=self._created(w3,'SkillRegistry',hashes[0],session)
        license,_=self._created(w3,'SkillLicense',hashes[1],session)
        if step=='wire_registry':
            fn=w3.eth.contract(address=registry,abi=artifact(self.root,'SkillRegistry')['abi']).functions.setSkillLicense(license)
            to=registry
        elif step=='wire_license':
            fn=w3.eth.contract(address=license,abi=artifact(self.root,'SkillLicense')['abi']).functions.setRegistry(registry)
            to=license
        else: raise TransactionError('未知部署步骤',400)
        return self.transactions.store(session,to,fn._encode_transaction_data(),0,{'step':step,'creationTxHashes':hashes})

    def confirm(self,prepared_id,tx_hash,session): return self.transactions.confirm(prepared_id,tx_hash,session)

    def activate(self,session,revision,tx_hashes):
        if not isinstance(tx_hashes,list) or len(tx_hashes) not in (4,5) or len(set(tx_hashes))!=len(tx_hashes):
            raise TransactionError('需要四笔（协议 1）或五笔（协议 2，含仲裁角色配置）不同的成功交易')
        path=self.root/'.cache/ops/config.lock';path.parent.mkdir(parents=True,exist_ok=True)
        with path.open('a+') as lock:
            fcntl.flock(lock,fcntl.LOCK_EX)
            current=load_scope(self.root)
            if current.revision!=revision or session.scope!=current: raise TransactionError('部署 revision 已改变，请刷新')
            w3=self._owner(session)
            registry,rb=self._created(w3,'SkillRegistry',tx_hashes[0],session)
            license,lb=self._created(w3,'SkillLicense',tx_hashes[1],session)
            reg=w3.eth.contract(address=registry,abi=artifact(self.root,'SkillRegistry')['abi'])
            lic=w3.eth.contract(address=license,abi=artifact(self.root,'SkillLicense')['abi'])
            expected=[(registry,reg.functions.setSkillLicense(license)._encode_transaction_data()),
                      (license,lic.functions.setRegistry(registry)._encode_transaction_data())]
            blocks=[rb,lb]
            for hash_,(to,data) in zip(tx_hashes[2:4],expected):
                tx=w3.eth.get_transaction(hex32(hash_));receipt=w3.eth.get_transaction_receipt(hash_)
                actual=tx['input'] if isinstance(tx['input'],str) else Web3.to_hex(tx['input'])
                if (tx['from'].lower()!=session.address.lower() or (tx.get('to') or '').lower()!=to.lower()
                        or actual.lower()!=data.lower() or tx.get('chainId')!=current.chain_id
                        or int(tx['value'])!=0 or receipt['status']!=1): raise TransactionError('接线交易不匹配')
                blocks.append(receipt['blockNumber'])
            if blocks!=sorted(blocks): raise TransactionError('部署交易顺序不正确')
            if (reg.functions.skillLicense().call()!=license or lic.functions.registry().call()!=registry
                    or not lic.functions.hasRole(lic.functions.MINTER_ROLE().call(),registry).call()):
                raise TransactionError('接线或铸造权限不正确')
            arbiter=treasury=None;protocol_version=1
            if len(tx_hashes)==5:
                # 第五步回执：真实控制在链上核对配置锁定与地址分离；calldata 形状先与链上方法一致
                tx=w3.eth.get_transaction(hex32(tx_hashes[4]));receipt=w3.eth.get_transaction_receipt(tx_hashes[4])
                actual=tx['input'] if isinstance(tx['input'],str) else Web3.to_hex(tx['input'])
                if (tx.get('to') or '').lower()!=registry.lower() or tx['from'].lower()!=session.address.lower() \
                        or int(tx['value'])!=0 or receipt['status']!=1:
                    raise TransactionError('仲裁角色配置交易不匹配')
                expected_selector='0x' + reg.functions.configureArbitration(
                    Web3.to_checksum_address('0x'+'01'*20),
                    Web3.to_checksum_address('0x'+'02'*20))._encode_transaction_data()[2:10].lower()
                if '0x'+actual[2:10].lower() != expected_selector:
                    raise TransactionError('仲裁角色配置交易不是 configureArbitration 调用')
                arbiter=reg.functions.arbiter().call();treasury=reg.functions.treasury().call()
                if not reg.functions.arbitrationConfigured().call() or arbiter==treasury \
                        or arbiter==reg.functions.owner().call() or treasury==reg.functions.owner().call():
                    raise TransactionError('仲裁角色未按已配置的锁定规则启用')
                if reg.functions.protocolVersion().call()!=2: raise TransactionError('部署协议版本与 arbitration 配置不符')
                protocol_version=2
            transition=self.root/'.cache/ops/transition'
            transition.write_text(revision)
            try:
                if self.drain: self.drain(revision)
                payload={'chainId':current.chain_id,'SkillRegistry':registry,'SkillLicense':license,'deploymentBlock':min(rb,lb),'protocolVersion':protocol_version}
                if protocol_version==2:
                    payload['arbiter']=Web3.to_checksum_address(arbiter);payload['treasury']=Web3.to_checksum_address(treasury)
                fd,temp=tempfile.mkstemp(prefix='.deployments-',dir=self.root)
                try:
                    with os.fdopen(fd,'w') as out:
                        json.dump(payload,out,indent=2);out.write('\n');out.flush();os.fsync(out.fileno())
                    os.replace(temp,self.root/'deployments.json')
                    directory=os.open(self.root,os.O_RDONLY)
                    try: os.fsync(directory)
                    finally: os.close(directory)
                finally:
                    if os.path.exists(temp): os.unlink(temp)
                return load_scope(self.root)
            finally:
                transition.unlink(missing_ok=True)


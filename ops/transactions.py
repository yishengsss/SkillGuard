"""Persist human transaction parameters; only the browser signs them."""
import json
import secrets
import sqlite3
import time
from web3 import Web3
from web3.logs import DISCARD
from auditor.protocol import registry_capabilities
from web3.exceptions import TransactionNotFound
from .config import load_scope, web3_for, auditor_address
from .chain import contracts, ChainRepository, hex32
from .models import APIError
from .packages import PackageStore


class TransactionError(APIError):
    def __init__(self,message,status=409): super().__init__(message,status,'transaction')


class TransactionService:
    def __init__(self,root):
        self.root=root
        self.path=root/'.cache/ops/transactions.sqlite3'
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute('CREATE TABLE IF NOT EXISTS prepared (id TEXT PRIMARY KEY, address TEXT, revision TEXT, expires INTEGER, payload TEXT, txhash TEXT)')

    def store(self,session,to,data,value,meta):
        scope=load_scope(self.root)
        if scope!=session.scope or scope.chain_id not in (31337,968): raise TransactionError('网络或部署作用域已改变')
        w3=web3_for(self.root,scope)
        tx={'from':session.address,'data':data,'value':value}
        if to is not None: tx['to']=to
        try:
            gas=(w3.eth.estimate_gas(tx)*12+9)//10
            fee=gas*w3.eth.gas_price
            if w3.eth.get_balance(session.address)<value+fee: raise TransactionError('余额不足以支付交易与 gas')
        except APIError: raise
        except Exception: raise TransactionError('交易模拟失败，请检查链上状态与余额') from None
        result={'id':secrets.token_hex(16),'scopeRevision':scope.revision,'chainId':scope.chain_id,
                'from':session.address,'to':to,'data':data,'value':str(value),'estimatedGas':str(gas),'estimatedFee':str(fee)}
        if meta.get('step') in ('deploy_registry','deploy_license','wire_registry','wire_license'):
            result['deploymentStep']=meta['step']
        saved={'prepared':result,'meta':meta}
        with sqlite3.connect(self.path) as db:
            db.execute('INSERT INTO prepared VALUES (?,?,?,?,?,NULL)',(result['id'],session.address.lower(),scope.revision,int(time.time())+600,json.dumps(saved)))
        return result

    def record(self,identifier,session):
        with sqlite3.connect(self.path) as db:
            row=db.execute('SELECT address,revision,expires,payload,txhash FROM prepared WHERE id=?',(identifier,)).fetchone()
        if not row or row[0]!=session.address.lower(): raise TransactionError('该交易不属于当前钱包',403)
        if row[1]!=session.scope.revision or load_scope(self.root)!=session.scope: raise TransactionError('部署作用域已改变')
        return row,json.loads(row[3])

    def prepare(self,action,session,payload):
        if action in ('stake','human_decision'):
            from auditor.worker import AgentLease,browser_reserved,reserve_browser
            if session.address.lower()!=(auditor_address(self.root) or '').lower(): raise TransactionError('请连接审计服务钱包',403)
            with AgentLease(self.root,session.scope.chain_id,session.scope.registry,session.address,'browser') as lease:
                if not lease.acquired: raise TransactionError('请先停止 worker 并等待当前交易完成，再签名审计钱包交易')
                if browser_reserved(self.root,session.scope.chain_id,session.address): raise TransactionError('已有审计钱包交易待确认，请先续办或等待十分钟过期')
                prepared=self._prepare(action,session,payload)
                reserve_browser(self.root,session.scope.chain_id,session.address,prepared['id'])
                return prepared
        return self._prepare(action,session,payload)

    def _prepare(self,action,session,payload):
        scope=session.scope
        w3,reg,_=contracts(self.root,scope)
        value=0; meta={'action':action}
        if action=='register':
            preview=PackageStore(self.root).preview(payload.get('packageId'),session)
            manifest=preview['manifest']
            key=Web3.to_hex(reg.functions.keyOf(manifest['name'],manifest['version']).call())
            if reg.functions.skills(key).call()[5]!=0: raise TransactionError('该名称和版本已经登记')
            fn=reg.functions.register(manifest['name'],manifest['version'],preview['source'],preview['codeHash'],preview['metadataHash'])
            meta.update(key=key,packageId=preview['packageId'],codeHash=preview['codeHash'],metadataHash=preview['metadataHash'])
        elif action=='request_audit':
            row=ChainRepository(self.root).detail(scope,payload.get('key'))
            if row['publisher'].lower()!=session.address.lower() or row['status']!=1: raise TransactionError('只有登记发布者可以请求审计')
            value=reg.functions.MIN_DEPOSIT().call()
            fn=reg.functions.requestAudit(row['name'],row['version']); meta['key']=row['key']
        elif action=='stake':
            if session.address.lower()!=(auditor_address(self.root) or '').lower(): raise TransactionError('请连接审计服务钱包',403)
            raw=payload.get('valueWei')
            if not isinstance(raw,str) or not raw.isdecimal() or len(raw)>78: raise TransactionError('明确填写整数 wei 金额',400)
            value=int(raw); minimum=reg.functions.AUDITOR_STAKE().call()
            if value<minimum: raise TransactionError('金额不能低于合约要求')
            fn=reg.functions.stakeAsAuditor()
        elif action=='human_decision':
            from .reports import ReportService
            decision=ReportService(self.root).prepare_decision(scope,payload.get('key'),session,payload.get('decision'))
            fn=reg.functions.submitReport(decision['name'],decision['version'],decision['isMalicious'],decision['reportHash'])
            meta.update(key=decision['key'],reportHash=decision['reportHash'],isMalicious=decision['isMalicious'],runId=decision['runId'])
        elif action in ('resolve','expire','withdraw'):
            from auditor.protocol import registry_capabilities
            from .arbitration import ArbitrationService
            if not registry_capabilities(w3,reg)['arbitrationSupported']:raise TransactionError('旧合约没有独立仲裁/领取能力')
            if action=='resolve':
                decision=ArbitrationService(self.root).prepare_decision(scope,payload.get('key'),session,payload.get('decision'),payload.get('reason'),payload.get('evidence'))
                fn=reg.functions.resolveArbitration(decision['name'],decision['version'],decision['isMalicious'],decision['reportHash'])
                meta.update(decision)
            elif action=='expire':
                row=ChainRepository(self.root).detail(scope,payload.get('key'))
                if row['status']!=5 or w3.eth.get_block('latest')['timestamp']<row['arbitration']['deadline']:raise TransactionError('案件尚未到期或已结算')
                fn=reg.functions.expireArbitration(row['name'],row['version']);meta.update(key=row['key'],publisher=row['publisher'])
            else:
                if reg.functions.credits(session.address).call()<=0:raise TransactionError('没有可领取余额')
                fn=reg.functions.withdrawFunds()
        elif action=='slash_auditor':
            if reg.functions.owner().call().lower()!=session.address.lower(): raise TransactionError('仅当前合约 owner 可罚没',403)
            if not Web3.is_address(payload.get('auditor')): raise TransactionError('审计地址无效',400)
            target=Web3.to_checksum_address(payload['auditor'])
            if reg.functions.auditorStake(target).call()==0: raise TransactionError('该地址没有质押')
            fn=reg.functions.slashAuditor(target);meta['auditor']=target
        else: raise TransactionError('未知交易动作',400)
        return self.store(session,scope.registry,fn._encode_transaction_data(),value,meta)

    def confirm(self,prepared_id,tx_hash,session):
        tx_hash=hex32(tx_hash)
        row,saved=self.record(prepared_id,session); p=saved['prepared']
        if row[4] and row[4].lower()!=tx_hash: raise TransactionError('已关联另一笔交易')
        w3=web3_for(self.root,session.scope)
        try: tx=w3.eth.get_transaction(tx_hash)
        except TransactionNotFound:
            if row[2]<time.time() and not row[4]: raise TransactionError('准备交易已过期，请重新准备')
            return {'preparedId':prepared_id,'txHash':tx_hash,'status':'pending','blockNumber':None,'error':None}
        data=tx.get('input',tx.get('data',b''))
        if not isinstance(data,str): data=Web3.to_hex(data)
        if (tx['from'].lower()!=p['from'].lower() or (tx.get('to') or '').lower()!=(p['to'] or '').lower()
                or data.lower()!=p['data'].lower() or int(tx['value'])!=int(p['value']) or tx.get('chainId')!=p['chainId']):
            raise TransactionError('实际交易与准备参数不匹配')
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE prepared SET txhash=? WHERE id=? AND (txhash IS NULL OR txhash=?)',(tx_hash,prepared_id,tx_hash))
            pinned=db.execute('SELECT txhash FROM prepared WHERE id=?',(prepared_id,)).fetchone()[0]
            if pinned!=tx_hash: raise TransactionError('并发确认了另一笔交易')
        try: receipt=w3.eth.get_transaction_receipt(tx_hash)
        except TransactionNotFound: return {'preparedId':prepared_id,'txHash':tx_hash,'status':'pending','blockNumber':None,'error':None}
        status='confirmed' if receipt['status']==1 else 'failed'
        if status=='confirmed' and saved['meta'].get('action') in ('register','request_audit','human_decision'):
            _,reg,_=contracts(self.root,session.scope)
            meta=saved['meta'];entry=reg.functions.skills(meta['key']).call(block_identifier=receipt['blockNumber'])
            action=meta['action']
            if action=='register' and (entry[0].lower()!=session.address.lower() or Web3.to_hex(entry[2])!=meta['codeHash'] or Web3.to_hex(entry[3])!=meta['metadataHash']):
                raise TransactionError('登记状态与包内容不匹配')
            if action=='request_audit' and (entry[0].lower()!=session.address.lower() or entry[5]!=2):
                raise TransactionError('审计请求状态不匹配')
            if action=='human_decision' and (Web3.to_hex(entry[6])!=meta['reportHash'] or entry[7].lower()!=session.address.lower() or entry[5]!=(5 if meta['isMalicious'] and registry_capabilities(w3,reg)['arbitrationSupported'] else 4 if meta['isMalicious'] else 3)):
                raise TransactionError('裁决状态不匹配')
        if status=='confirmed' and saved['meta'].get('action') in ('resolve','expire','withdraw'):
            _,reg,_=contracts(self.root,session.scope);meta=saved['meta'];block=receipt['blockNumber']
            if meta['action']=='resolve':
                entry=reg.functions.skills(meta['key']).call(block_identifier=block)
                if entry[5]!=(4 if meta['isMalicious'] else 3) or Web3.to_hex(entry[6])!=meta['reportHash'] or entry[7].lower()!=meta['reporter'].lower() or entry[4]!=0:raise TransactionError('仲裁回执状态与报告不符')
                events=reg.events.ArbitrationResolved().process_receipt(receipt,errors=DISCARD)
                if not any(Web3.to_hex(e['args']['key'])==meta['key'] and e['args']['arbiter'].lower()==session.address.lower() for e in events):raise TransactionError('仲裁回执身份不符')
            elif meta['action']=='expire':
                entry=reg.functions.skills(meta['key']).call(block_identifier=block)
                if entry[5]!=6 or entry[4]!=0 or entry[0].lower()!=meta['publisher'].lower():raise TransactionError('超时退款回执不符')
            else:
                events=reg.events.FundsWithdrawn().process_receipt(receipt,errors=DISCARD)
                if not any(e['args']['recipient'].lower()==session.address.lower() and e['args']['amount']>0 for e in events):raise TransactionError('领取回执不符')
        if status=='confirmed' and saved['meta'].get('step')=='configure_arbitration':
            _,reg,_=contracts(self.root,session.scope);meta=saved['meta'];block=receipt['blockNumber']
            if not reg.functions.arbitrationConfigured().call() \
                    or Web3.to_checksum_address(reg.functions.arbiter().call())!=Web3.to_checksum_address(meta['arbiter']) \
                    or Web3.to_checksum_address(reg.functions.treasury().call())!=Web3.to_checksum_address(meta['treasury']):
                raise TransactionError('仲裁角色链上配置与准备参数不一致')
        if saved['meta'].get('action') in ('human_decision','resolve'):
            from auditor.journal import Journal
            Journal(self.root).emit(saved['meta']['runId'],'receipt_confirmed' if status=='confirmed' else 'receipt_failed',{'txHash':tx_hash,'blockNumber':receipt['blockNumber']})
        if saved['meta'].get('action') in ('stake','human_decision'):
            from auditor.worker import release_browser
            release_browser(self.root,session.scope.chain_id,session.address,prepared_id)
        return {'preparedId':prepared_id,'txHash':tx_hash,'status':status,'blockNumber':receipt['blockNumber'],
                'error':None if status=='confirmed' else '交易已回滚'}

    def cancel(self,prepared_id,session):
        row,saved=self.record(prepared_id,session)
        if row[4] or saved['meta'].get('action') not in ('stake','human_decision'): raise TransactionError('已广播交易必须核验回执')
        from auditor.worker import release_browser
        with sqlite3.connect(self.path) as db:
            db.execute('UPDATE prepared SET expires=0 WHERE id=?',(prepared_id,))
        release_browser(self.root,session.scope.chain_id,session.address,prepared_id)
        return {'cancelled':True}

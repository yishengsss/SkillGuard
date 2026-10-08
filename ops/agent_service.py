"""Manage the service auditor, without staking or executing skill code."""
import threading
import time
from eth_account import Account
from auditor.agent import AgentContext,fetch_audit_requests,fetch_registrations
from auditor.scanner import scan_skill_report
from auditor.reasoner import configured_auditor
from auditor.llm import load_config as llm_config, LLMError
from auditor.journal import Journal
from auditor.worker import AgentLease,lease_status,run_worker,browser_reserved
from .chain import contracts
from .config import settings,load_scope,auditor_address
from .models import APIError


class ManagedAgent:
    def __init__(self,root):
        self.root=root;self.lock=threading.RLock();self.thread=None;self.stop_event=threading.Event();self.error=None

    def _authorize(self,session):
        if session.scope!=load_scope(self.root): raise APIError('部署作用域已改变',409,'scope_changed')
        address=auditor_address(self.root)
        if not address or session.address.lower()!=address.lower(): raise APIError('请连接审计服务钱包',403,'auditor_required')
        return address

    def start(self,session):
        address=self._authorize(session)
        try: reasoner=configured_auditor(self.root)
        except LLMError as exc: raise APIError(str(exc),409,'agent_configuration') from None
        with self.lock:
            if (self.root/'.cache/ops/transition').exists(): raise APIError('正在切换部署',409,'transition')
            w3,registry,_=contracts(self.root,session.scope)
            minimum=registry.functions.AUDITOR_STAKE().call();stake=registry.functions.auditorStake(address).call()
            if stake<minimum: raise APIError('质押不足，请先由钱包签名质押',409,'stake_required')
            if w3.eth.get_balance(address)<=0: raise APIError('审计钱包 gas 余额不足',409,'balance')
            lease=AgentLease(self.root,session.scope.chain_id,session.scope.registry,address,'web').__enter__()
            if not lease.acquired:
                lease.__exit__();raise APIError('审计钱包已有 CLI 或网页 worker 在运行',409,'worker_busy')
            # Recheck transition after acquiring the wallet lease.
            if (self.root/'.cache/ops/transition').exists():
                lease.__exit__();raise APIError('正在切换部署',409,'transition')
            if browser_reserved(self.root,session.scope.chain_id,address):
                lease.__exit__();raise APIError('审计钱包交易待确认；请先续办回执或等待准备交易过期',409,'wallet_pending')
            account=Account.from_key(settings(self.root)['AUDITOR_PRIVATE_KEY'])
            ctx=AgentContext(root=self.root,contract=registry,account=account,chain_id=session.scope.chain_id,
                fetch_requests=fetch_audit_requests,fetch_registrations=fetch_registrations,scanner=scan_skill_report,
                reasoner=reasoner,w3=w3,journal=Journal(self.root),deployment_block=session.scope.deployment_block,deployment_revision=session.scope.revision)
            self.stop_event=threading.Event();self.error=None
            def work():
                try: run_worker(ctx,self.stop_event,source='web',lease=lease)
                except Exception as exc:
                    self.error=type(exc).__name__
                    lease.__exit__()
            lease.heartbeat()
            self.thread=threading.Thread(target=work,daemon=True,name='skillguard-auditor');self.thread.start()
            return self.status(session.scope)

    def stop(self,session):
        self._authorize(session)
        self.stop_event.set()
        return {'state':'stopping' if self.thread and self.thread.is_alive() else 'stopped'}

    def status(self,scope):
        address=auditor_address(self.root)
        result=lease_status(self.root,scope.chain_id,address) if address else {'state':'stopped','source':None}
        result.update(auditor=address,error=self.error,auditMode='tool-agent')
        try: result.update(configReady=True,model=llm_config(self.root).model)
        except LLMError as exc: result.update(configReady=False,configurationError=str(exc))
        if address:
            try:
                w3,reg,_=contracts(self.root,scope)
                minimum=reg.functions.AUDITOR_STAKE().call();stake=reg.functions.auditorStake(address).call()
                result.update(stakeWei=str(stake),minimumWei=str(minimum),shortfallWei=str(max(0,minimum-stake)),balanceWei=str(w3.eth.get_balance(address)))
            except Exception: result['chainError']='质押或余额读取失败'
        return result

    def drain_for_activation(self,revision,timeout=30):
        if load_scope(self.root).revision!=revision: raise APIError('部署 revision 已改变',409,'scope_changed')
        self.stop_event.set()
        scope=load_scope(self.root);address=auditor_address(self.root)
        if not address: return
        deadline=time.monotonic()+timeout
        while time.monotonic()<deadline:
            with AgentLease(self.root,scope.chain_id,scope.registry,address,'activation') as lease:
                if lease.acquired: return
            time.sleep(.1)
        raise APIError('旧 worker 尚未完成当前交易，请稍后再激活',409,'worker_busy')

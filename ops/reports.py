"""Report availability is separate from the chain's recorded verdict."""
import json
import os
import stat
from auditor.report import report_hash_hex, canonical_json, SUSPICIOUS
from auditor.storage import save_report
from auditor.journal import Journal
from auditor.agent import resolve_source
from auditor.skill_dir import capture_skill
from auditor.hashing import code_hash,metadata_hash
from .chain import ChainRepository,hex32,contracts
from .config import load_scope,auditor_address
from .models import APIError


class ReportService:
    def __init__(self,root):
        self.root=root.resolve();self.chain=ChainRepository(root);self.journal=Journal(root)

    def _scope(self,scope):
        if load_scope(self.root)!=scope: raise APIError('部署作用域已改变',409,'scope_changed')

    def _bytes(self,hash_):
        rootfd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        directory=fd=None
        try:
            directory=os.open('reports',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
            fd=os.open(hex32(hash_)+'.json',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=directory)
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size>10*1024*1024: raise ValueError('report not a bounded regular file')
            chunks=[];total=0
            while chunk:=os.read(fd,65536):
                total+=len(chunk)
                if total>10*1024*1024: raise ValueError('report too large')
                chunks.append(chunk)
            return b''.join(chunks)
        finally:
            if fd is not None: os.close(fd)
            if directory is not None: os.close(directory)
            os.close(rootfd)

    def _associations(self,scope,hash_):
        rows=self.chain.catalog(scope)
        associated=[(row,True) for row in rows if row['reportHash']==hash_]
        associated.extend((row,False) for row in rows if row.get('arbitration',{} ) and row['arbitration']['originalReportHash']==hash_)
        for run in self.journal.runs(scope.chain_id,scope.registry):
            if any(e['payload'].get('reportHash')==hash_ for e in self.journal.events(run['runId'])):
                row=next((r for r in rows if r['key']==run['key']),None)
                if row is not None: associated.append((row,row['reportHash']==hash_))
        return associated

    def read(self,scope,hash_):
        self._scope(scope);hash_=hex32(hash_)
        associations=self._associations(scope,hash_)
        if not associations: raise APIError('当前部署未关联此报告',404,'not_found')
        result={'report':None,'reportHash':hash_,'reportMatchesChain':False,'availability':'missing'}
        try:
            data=self._bytes(hash_);report=json.loads(data)
            if not isinstance(report,dict) or canonical_json(report)!=data or report_hash_hex(report)!=hash_: raise ValueError('report corrupted')
            matching=[]
            for row,onchain in associations:
                if (report.get('skill')==row['name'] and report.get('version')==row['version']
                        and report.get('codeHash')==row['codeHash'] and report.get('metadataHash')==row['metadataHash']
                        and (not onchain or report.get('auditor','').lower()==row['auditor'].lower())):
                    matching.append(onchain)
            if not matching: raise ValueError('report identity differs')
            result.update(report=report,availability='present',reportMatchesChain=any(matching))
        except FileNotFoundError: pass
        except Exception: result['availability']='corrupt'
        return result

    def pending(self,scope,key):
        self._scope(scope);key=hex32(key);row=self.chain.detail(scope,key)
        if row['status']!=2: raise APIError('此版本不处于待审状态',409,'status')
        for run in self.journal.runs(scope.chain_id,scope.registry,key):
            events=self.journal.events(run['runId'])
            pending=[e['payload']['reportHash'] for e in events if e['stage']=='waiting_human']
            if pending:
                view=self.read(scope,pending[-1]);report=view['report']
                if view['availability']!='present' or report.get('level')!=SUSPICIOUS: raise APIError('待裁决报告缺失或损坏',409,'report_unavailable')
                return {**view,'runId':run['runId'],'key':key}
        raise APIError('未找到当前部署的待裁决报告',404,'not_found')

    def prepare_decision(self,scope,key,session,decision):
        if session.scope!=scope or session.address.lower()!=(auditor_address(self.root) or '').lower(): raise APIError('请连接审计服务钱包',403,'auditor_required')
        if decision not in ('safe','malicious'): raise APIError('人工结论只能为 safe 或 malicious',400,'decision')
        view=self.pending(scope,key);row=self.chain.detail(scope,key)
        if row['publisher'].lower()==session.address.lower(): raise APIError('禁止自审',403,'self_audit')
        source=resolve_source(row['source'],self.root)
        if source is None: raise APIError('已登记来源不可用',409,'source_unavailable')
        captured=capture_skill(source,source_root=self.root)
        if '0x'+code_hash(captured).hex()!=row['codeHash'] or '0x'+metadata_hash(captured).hex()!=row['metadataHash']: raise APIError('已登记来源内容改变',409,'hash_mismatch')
        _,reg,_=contracts(self.root,scope)
        if reg.functions.auditorStake(session.address).call()<reg.functions.AUDITOR_STAKE().call(): raise APIError('审计质押不足',409,'stake_required')
        report=dict(view['report']);report.update(humanDecision=decision,auditor=session.address)
        _,digest=save_report(report,self.root/'reports')
        run=self.journal.begin(scope.chain_id,scope.registry,key,row['block'])
        self.journal.emit(run,'report_saved',{'reportHash':digest,'humanDecision':decision})
        self.journal.emit(run,'decision_prepared',{'reportHash':digest})
        return {'key':key,'name':row['name'],'version':row['version'],'reportHash':digest,'isMalicious':decision=='malicious','runId':run}

    def detail(self,scope,key):
        self._scope(scope);row=self.chain.detail(scope,key);runs=self.journal.runs(scope.chain_id,scope.registry,key)
        events=[{**event,'runId':run['runId']} for run in reversed(runs) for event in self.journal.events(run['runId'])]
        view={**row,'events':events,'runs':runs,'historyNote':'已有审计结果，未保存运行日志' if not events and row['status'] in (3,4) else None,
              'report':None,'pendingReport':None,'package':None}
        if row['status'] in (3,4,5,6): view['report']=self.read(scope,row['reportHash'])
        if row['status']==2:
            try: view['pendingReport']=self.pending(scope,key)
            except APIError as exc:
                if exc.status!=404: view['reportError']=str(exc)
        try:
            source=resolve_source(row['source'],self.root)
            if source is not None:
                snapshot=capture_skill(source,source_root=self.root)
                if '0x'+code_hash(snapshot).hex()==row['codeHash'] and '0x'+metadata_hash(snapshot).hex()==row['metadataHash']:
                    view['package']={'manifest':json.loads(snapshot.manifest_bytes),'files':[{'path':name,'bytes':len(data),'mode':oct(dict(snapshot.file_modes)[name])} for name,data in snapshot.files]}
        except Exception: view['sourceNote']='来源缺失或内容与登记不符'
        return view

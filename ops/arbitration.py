"""Independent arbitration views and evidence preparation; no server-side wallet signing."""
from .chain import ChainRepository,contracts,hex32
from .models import APIError
from .reports import ReportService


class ArbitrationService:
    def __init__(self,root):self.root=root;self.chain=ChainRepository(root);self.reports=ReportService(root)
    def list(self,scope):
        return [r for r in self.chain.catalog(scope) if r.get('arbitration')]
    def case(self,scope,key):
        row=self.chain.detail(scope,hex32(key))
        if not row.get('arbitrationSupported'):raise APIError('旧合约没有独立仲裁能力',409,'legacy_protocol')
        if not row.get('arbitration'):raise APIError('此版本没有仲裁案件',404,'not_found')
        row['originalReport']=self.reports.read(scope,row['arbitration']['originalReportHash'])
        row['finalReport']=self.reports.read(scope,row['arbitration']['finalReportHash']) if int(row['arbitration']['finalReportHash'],16) else None
        return row

    def funds(self,scope,address):
        from web3 import Web3
        from auditor.protocol import registry_capabilities
        if not isinstance(address,str) or not Web3.is_address(address):raise APIError('钱包地址无效',400,'address')
        w3,reg,_=contracts(self.root,scope);block=w3.eth.block_number
        caps=registry_capabilities(w3,reg,block)
        if not caps['arbitrationSupported']:raise APIError('旧合约不支持领取余额',409,'legacy_protocol')
        return {'address':Web3.to_checksum_address(address),'creditsWei':str(reg.functions.credits(Web3.to_checksum_address(address)).call(block_identifier=block)),'block':block}

    def prepare_decision(self,scope,key,session,decision,reason,evidence):
        import json
        from auditor.agent import resolve_source
        from auditor.skill_dir import capture_skill
        from auditor.hashing import code_hash,metadata_hash
        from auditor.reasoner import _findings,AgentAuditError
        from auditor.storage import save_report
        row=self.case(scope,key);case=row['arbitration']
        if session.scope!=scope:raise APIError('部署作用域已改变',409,'scope_changed')
        if session.address.lower()!=case['arbiter'].lower():raise APIError('请连接独立仲裁钱包',403,'arbiter_required')
        w3,_,_=contracts(self.root,scope)
        if row['status']!=5 or w3.eth.get_block('latest')['timestamp']>=case['deadline']:raise APIError('案件不是可裁决状态或已到期',409,'case_closed')
        if decision not in ('safe','malicious') or not isinstance(reason,str) or not 0<len(reason.strip())<=4000:raise APIError('必须填写最终判断和复核理由',400,'decision')
        if not isinstance(evidence,list) or not 1<=len(evidence)<=100:raise APIError('必须提交可核对的源码证据',400,'evidence')
        original=row['originalReport']
        if original['availability']!='present' or original['report']['auditor'].lower()!=case['reporter'].lower():raise APIError('原审计报告不可核对',409,'report')
        source=resolve_source(row['source'],self.root)
        if source is None:raise APIError('来源不可读取',409,'source')
        snapshot=capture_skill(source,source_root=self.root)
        if '0x'+code_hash(snapshot).hex()!=row['codeHash'] or '0x'+metadata_hash(snapshot).hex()!=row['metadataHash']:raise APIError('实际源码与登记哈希不同',409,'hash_mismatch')
        try:
            files={path:data.decode('utf-8').splitlines(keepends=True) for path,data in {'manifest.json':snapshot.manifest_bytes,**dict(snapshot.files)}.items()}
            normalized=[]
            for item in evidence:
                if not isinstance(item,dict) or set(item)!={'file','line','quote','explanation'}:raise AgentAuditError('证据结构无效')
                normalized.append({**item,'severity':'medium'})
            _findings({'summary':reason,'findings':normalized},files,{p:set(range(1,len(lines)+1)) for p,lines in files.items()})
        except (AgentAuditError,UnicodeError):raise APIError('复核证据与实际源码不对应',400,'evidence') from None
        final=json.loads(json.dumps(original['report']))
        final['originalReportHash']=case['originalReportHash']
        final['arbitration']={'arbitrator':session.address,'decision':decision,'reason':reason,'evidence':evidence}
        _,digest=save_report(final,self.root/'reports')
        from auditor.journal import Journal
        journal=Journal(self.root);run=journal.begin(scope.chain_id,scope.registry,row['key'],row['block'])
        journal.emit(run,'report_saved',{'reportHash':digest,'originalReportHash':case['originalReportHash'],'arbitrator':session.address})
        journal.emit(run,'arbitration_decision_prepared',{'decision':decision,'reportHash':digest})
        return {'key':row['key'],'name':row['name'],'version':row['version'],'reportHash':digest,'originalReportHash':case['originalReportHash'],'isMalicious':decision=='malicious','reporter':case['reporter'],'runId':run}

    def source(self,scope,key,session):
        from auditor.agent import resolve_source
        from auditor.skill_dir import capture_skill
        from auditor.hashing import code_hash,metadata_hash
        row=self.case(scope,key)
        if session.scope!=scope or session.address.lower()!=row['arbitration']['arbiter'].lower():raise APIError('请连接独立仲裁钱包',403,'arbiter_required')
        path=resolve_source(row['source'],self.root)
        if path is None:raise APIError('来源不可读取',409,'source')
        snapshot=capture_skill(path,source_root=self.root)
        if '0x'+code_hash(snapshot).hex()!=row['codeHash'] or '0x'+metadata_hash(snapshot).hex()!=row['metadataHash']:raise APIError('实际源码与登记哈希不同',409,'hash_mismatch')
        raw={'manifest.json':snapshot.manifest_bytes,**dict(snapshot.files)}
        if len(raw)>200 or sum(map(len,raw.values()))>262144:raise APIError('源码超过复核展示上限',409,'source_limit')
        try:return {'files':[{'path':p,'lines':[{'line':i,'text':line} for i,line in enumerate(data.decode('utf-8').splitlines(),1)]} for p,data in raw.items()],'codeHash':row['codeHash'],'metadataHash':row['metadataHash']}
        except UnicodeError:raise APIError('源码不是 UTF-8 文本',409,'source') from None

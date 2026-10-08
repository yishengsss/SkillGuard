"""Install only a key's verified, registered local source on this server."""
import fcntl
import json
from auditor.agent import resolve_source
from auditor.skill_dir import capture_skill
from auditor.hashing import code_hash,metadata_hash
from gate import mcp_server
from .chain import ChainRepository,hex32
from .config import load_scope
from .models import APIError


class InstallService:
    def __init__(self,root): self.root=root.resolve();self.chain=ChainRepository(root)

    def _source(self,scope,key):
        if load_scope(self.root)!=scope: raise APIError('部署作用域已改变',409,'scope_changed')
        row=self.chain.detail(scope,hex32(key));path=resolve_source(row['source'],self.root)
        if path is None: raise APIError('已登记来源不可用',409,'source_unavailable')
        captured=capture_skill(path,source_root=self.root)
        manifest=json.loads(captured.manifest_bytes)
        if (manifest.get('name')!=row['name'] or manifest.get('version')!=row['version']
                or '0x'+code_hash(captured).hex()!=row['codeHash'] or '0x'+metadata_hash(captured).hex()!=row['metadataHash']):
            raise APIError('来源内容与链上登记不一致',409,'hash_mismatch')
        return path,captured

    def check(self,scope,key):
        path,captured=self._source(scope,key)
        return {**mcp_server.check_skill(captured,project_root=self.root),'targetMachine':'服务所在机器','installRoot':str(self.root/'installed')}

    def execute(self,scope,key):
        lock=self.root/'.cache/ops/config.lock';lock.parent.mkdir(parents=True,exist_ok=True)
        with lock.open('a+') as handle:
            fcntl.flock(handle,fcntl.LOCK_SH)
            path,captured=self._source(scope,key)
            check=mcp_server.check_skill(captured,project_root=self.root)
            if not check.get('allowed'): return {**check,'installed':False}
            # Copy exactly the snapshot bound to the requested key, even if its source changes while waiting.
            installlock=self.root/'.cache/ops/install.lock'
            with installlock.open('a+') as serial:
                fcntl.flock(serial,fcntl.LOCK_EX)
                return {**mcp_server.install_skill(captured,project_root=self.root,install_root=self.root/'installed'),'targetMachine':'服务所在机器'}

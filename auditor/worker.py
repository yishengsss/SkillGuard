"""A wallet-wide OS lease shared by CLI and managed workers."""
import fcntl
import hashlib
import json
import os
import secrets
import threading
import time
from pathlib import Path
from .agent import run_once,read_cursor


def lease_paths(root,chain_id,auditor):
    directory=Path(root)/'.cache/ops/workers';directory.mkdir(parents=True,exist_ok=True)
    key=hashlib.sha256(f'{chain_id}:{auditor.lower()}'.encode()).hexdigest()
    return directory/f'{key}.lock',directory/f'{key}.json'


def deployment_revision(root):
    try:
        data=json.loads((root/'deployments.json').read_text())
        return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    except (OSError,ValueError): return None


def browser_path(root,chain_id,auditor):
    return lease_paths(root,chain_id,auditor)[0].with_suffix('.browser.json')


def browser_reserved(root,chain_id,auditor):
    path=browser_path(root,chain_id,auditor)
    try: data=json.loads(path.read_text())
    except FileNotFoundError: return False
    except (OSError,ValueError): return True  # A damaged reservation requires operator inspection.
    return data.get('expires',float('inf'))>time.time()


def reserve_browser(root,chain_id,auditor,prepared_id,seconds=600):
    path=browser_path(root,chain_id,auditor)
    with path.with_suffix('.guard').open('a+') as guard:
        fcntl.flock(guard,fcntl.LOCK_EX)
        temporary=path.with_suffix('.'+secrets.token_hex(8)+'.tmp')
        with temporary.open('w') as out:
            json.dump({'preparedId':prepared_id,'expires':time.time()+seconds},out);out.flush();os.fsync(out.fileno())
        os.replace(temporary,path)


def release_browser(root,chain_id,auditor,prepared_id):
    path=browser_path(root,chain_id,auditor)
    with path.with_suffix('.guard').open('a+') as guard:
        fcntl.flock(guard,fcntl.LOCK_EX)
        try: data=json.loads(path.read_text())
        except (OSError,ValueError): return
        if data.get('preparedId')==prepared_id: path.unlink(missing_ok=True)


def lease_status(root,chain_id,auditor):
    lockpath,path=lease_paths(root,chain_id,auditor)
    try: data=json.loads(path.read_text())
    except (OSError,ValueError): return {'state':'stopped','source':None,'heartbeat':None}
    if data['state']!='stopped' and time.time()-data['heartbeat']>10: data['state']='offline'
    return data


class AgentLease:
    def __init__(self,root,chain_id,registry,auditor,source):
        self.root=Path(root);self.chain_id=chain_id;self.registry=registry;self.auditor=auditor;self.source=source
        self.acquired=False;self.instance=secrets.token_hex(16);self.handle=None
        self.lockpath,self.path=lease_paths(root,chain_id,auditor)

    def __enter__(self):
        self.handle=self.lockpath.open('a+')
        try:
            fcntl.flock(self.handle,fcntl.LOCK_EX|fcntl.LOCK_NB);self.acquired=True
        except BlockingIOError: pass
        return self

    def heartbeat(self,state='running'):
        if not self.acquired: return
        data={'state':state,'source':self.source,'instance':self.instance,'pid':os.getpid(),
              'registry':self.registry,'auditor':self.auditor,'heartbeat':time.time()}
        temporary=self.path.with_suffix('.'+self.instance+'.tmp')
        temporary.write_text(json.dumps(data));os.replace(temporary,self.path)

    def __exit__(self,*args):
        if self.acquired:
            self.heartbeat('stopped');fcntl.flock(self.handle,fcntl.LOCK_UN)
        if self.handle: self.handle.close()
        self.acquired=False


def run_worker(ctx,stop,poll=2,*,once=False,cursor=None,source='cli',lease=None):
    owned=lease or AgentLease(ctx.root,ctx.chain_id,ctx.contract.address,ctx.account.address,source)
    if lease is None: owned.__enter__()
    if not owned.acquired:
        if lease is None: owned.__exit__()
        raise RuntimeError('审计钱包已有 worker 持锁')
    initial=deployment_revision(ctx.root)
    if (ctx.deployment_revision is not None and ctx.deployment_revision!=initial):
        owned.__exit__();raise RuntimeError('部署已改变，请重新构建审计上下文')
    # Also reject older callers that supplied no revision but still bind a different registry.
    if initial is not None:
        deployment=json.loads((ctx.root/'deployments.json').read_text())
        if (deployment.get('chainId')!=ctx.chain_id or deployment.get('SkillRegistry','').lower()!=ctx.contract.address.lower()):
            owned.__exit__();raise RuntimeError('部署与审计上下文不匹配')
    if browser_reserved(ctx.root,ctx.chain_id,ctx.account.address):
        owned.__exit__();raise RuntimeError('审计钱包交易待确认或拒签，暂不能启动 worker')
    alive=threading.current_thread();done=threading.Event()
    def should_stop():
        return stop.is_set() or (ctx.root/'.cache/ops/transition').exists() or deployment_revision(ctx.root)!=initial
    ctx.stop_requested=should_stop
    def heartbeat():
        while not done.is_set() and alive.is_alive():
            owned.heartbeat('stopping' if should_stop() else 'running')
            done.wait(2)
    owned.heartbeat();monitor=threading.Thread(target=heartbeat,daemon=True);monitor.start()
    current=read_cursor(ctx.root,ctx.chain_id,ctx.contract.address) if cursor is None else cursor
    try:
        while not should_stop():
            try:
                current,_=run_once(ctx,current)
            except Exception as exc:
                ctx.log(f'轮询失败（{type(exc).__name__}），保留游标')
            if once: break
            stop.wait(max(.05,poll))
        return current
    finally:
        done.set();monitor.join(3);owned.__exit__()

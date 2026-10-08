"""Isolated demo with a public local EOA provider; production never serves it."""
import argparse
import json
import re
import sys
import tempfile
import threading
from pathlib import Path
from urllib.parse import urlencode

ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from tests.roles_fixtures import make_role_fixture
from ops.server import Handler,OpsHTTPServer,HTTPError


def inject_test_ui(body: bytes, *, mock_agent: bool) -> bytes:
    """Inject the public-wallet selector and optional fixture warning into valid HTML."""
    warning=(b'<div style="background:#fff3cd;color:#6b4f00;padding:8px 16px;text-align:center;font:13px sans-serif">'
             b'\xe2\x9a\xa0 TEST MODE: deterministic protocol fixture; this is NOT an AI audit</div>'
             if mock_agent else b'')
    content=re.sub(rb'(<body\b[^>]*>)',lambda match:match.group(1)+warning,body,count=1)
    return content.replace(b'<script type="module"',b'<script type="module" src="/__test_wallet.mjs"></script><script type="module"',1)


class TestHandler(Handler):
    def _dispatch(self,method,body=b''):
        if method!='GET': return super()._dispatch(method,body)
        if method=='GET' and self.path=='/__test_wallet':
            fixture=self.server.fixture
            accounts=[('发布者 A',fixture.chain.publishers[0]),('发布者 B',fixture.chain.publishers[1]),
                      ('审计者',fixture.chain.auditor),('管理员',fixture.chain.owner),
                      ('独立仲裁者',fixture.chain.arbiter),('公共资金钱包',fixture.chain.treasury)]
            self._jsonify({'accounts':[{'label':label,'address':account.address,'key':'0x'+account.key.hex().removeprefix('0x')} for label,account in accounts]})
            return
        if method=='GET' and self.path=='/__test_wallet.mjs':
            content=(ROOT/'tests/fixtures/role-wallet.mjs').read_bytes()
            self.send_response(200);self.send_header('Content-Type','text/javascript');self.send_header('Content-Length',str(len(content)));self.end_headers();self.wfile.write(content);return
        reply=self._application().handle(method,self.path,dict(self.headers.items()),body)
        if reply.headers.get('Content-Type','').startswith('text/html'):
            content=inject_test_ui(reply.body,mock_agent=self.server.fixture.mock_agent)
            self.send_response(reply.status)
            for key,value in reply.headers.items():self.send_header(key,value)
            self.send_header('Content-Length',str(len(content)));self.end_headers();self.wfile.write(content)
            return
        super()._dispatch(method,body)

    def do_POST(self):
        if self.path!='/__test_rpc': return super().do_POST()
        try:
            self._authorize(mutating=True);payload=self._post_body()
            allowed={'eth_chainId','eth_gasPrice','eth_getTransactionCount','eth_sendRawTransaction','eth_getTransactionReceipt','eth_estimateGas','eth_call','eth_getBlockByNumber','eth_maxPriorityFeePerGas','eth_getBalance','eth_getTransactionByHash'}
            method=payload.get('method');params=payload.get('params',[])
            if method not in allowed or not isinstance(params,list):raise HTTPError('test RPC method forbidden',403)
            result=self.server.fixture.chain.w3.provider.make_request(method,params)
            self._jsonify(result)
        except HTTPError as exc:self._jsonify({'error':{'message':str(exc)}},exc.status)
        except Exception:self._jsonify({'error':{'message':'isolated RPC unavailable'}},503)


class RoleHTTPFixture:
    def __init__(self,root,rpc_port=0,http_port=0,*,mock_agent=False):
        self.chain=make_role_fixture(root,rpc_port=rpc_port)
        self.root=self.chain.root
        self.mock_agent=mock_agent
        self.model_api=None
        if mock_agent:
            from tests.agent_api_fixture import FixtureAPI
            self.model_api=FixtureAPI();self.model_api.configure(self.root)
        try:self.server=OpsHTTPServer(('127.0.0.1',http_port),TestHandler,project_root=self.root)
        except BaseException:self.chain.close();raise
        self.server.fixture=self
        self.origin=f'http://127.0.0.1:{self.server.server_port}'
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
    def scoped(self,path,**extra):
        return path+'?'+urlencode({'chainId':31337,'registry':self.chain.scope.registry,**extra})
    def close(self):
        self.server.application.agent.stop_event.set()
        worker=self.server.application.agent.thread
        if worker:worker.join(5)
        self.server.shutdown();self.server.server_close();self.thread.join(5)
        if self.model_api:self.model_api.close()
        self.chain.close()


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--rpc-port',type=int,default=18857);parser.add_argument('--port',type=int,default=18701);parser.add_argument('--mock-agent',action='store_true',help='use deterministic protocol fixture; NOT an AI audit');args=parser.parse_args()
    cache=ROOT/'.cache/role-demo';cache.mkdir(parents=True,exist_ok=True)
    root=Path(tempfile.mkdtemp(prefix='session-',dir=cache))
    fixture=RoleHTTPFixture(root,args.rpc_port,args.port,mock_agent=args.mock_agent)
    mode='DETERMINISTIC TEST FIXTURE (NOT AI)' if args.mock_agent else 'real model required for Agent audit'
    print('Isolated protocol-v2 role demo: '+fixture.origin+'\n'+mode+'\nPublic Anvil fixture accounts only. Ctrl-C stops only this demo.',flush=True)
    try:
        while True:threading.Event().wait(1)
    except KeyboardInterrupt:pass
    finally:fixture.close()

if __name__=='__main__':main()

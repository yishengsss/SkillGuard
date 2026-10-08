"""Deterministic tool protocol fixture. This is NOT an AI model."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FixtureAPI:
    def __init__(self):
        owner=self;self.requests=[];self.fail=False
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                data=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.requests.append(data)
                if owner.fail:
                    self.send_response(401);self.end_headers();return
                messages=data['messages'];inventory=json.loads(messages[1]['content'])['inventory']
                reads={json.loads(m['content'])['path'] for m in messages if m['role']=='tool' and 'path' in json.loads(m['content'])}
                unread=[f for f in inventory if f['path'] not in reads]
                if unread:
                    calls=[{'id':f'read-{len(owner.requests)}-{i}','type':'function','function':{'name':'read_file','arguments':json.dumps({'path':f['path']})}} for i,f in enumerate(unread[:8])]
                else:
                    calls=[{'id':f'finish-{len(owner.requests)}','type':'function','function':{'name':'finish_audit','arguments':json.dumps({'summary':'确定性测试响应，仅验证工具协议，不代表真实 AI 审计。','findings':[]})}}]
                payload=json.dumps({'id':f'fixture-{len(owner.requests)}','model':'fixture-tool-agent','choices':[{'message':{'role':'assistant','content':None,'tool_calls':calls}}]}).encode()
                self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()
        self.url=f'http://127.0.0.1:{self.server.server_port}/v1'
    def configure(self,root):
        with (root/'.env').open('a') as f:f.write(f'LLM_API_KEY=fixture-key\nLLM_BASE_URL={self.url}\nLLM_MODEL=fixture-tool-agent\n')
    def close(self):self.server.shutdown();self.server.server_close();self.thread.join(5)

"""Role HTTP boundary: no web handler signs publisher or owner transactions."""
import json
import secrets
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlsplit, parse_qs
from dataclasses import asdict

from .auth import AuthError, WalletAuth
from .config import load_scope, public_config
from .models import APIError, HTTPReply
from .packages import PackageStore, MAX_ZIP
from .chain import ChainRepository
from .transactions import TransactionService
from .admin import AdminService
from .agent_service import ManagedAgent
from auditor.journal import Journal
from .reports import ReportService
from .install_service import InstallService
from .arbitration import ArbitrationService

LEGACY_ACTIONS = {'deploy', 'stake', 'register', 'decide', 'agent-once', 'install'}


class OpsApplication:
    def __init__(self, root: Path):
        self.root = root
        self.server_port = 8765
        self.csrf_token = secrets.token_urlsafe(32)
        self.auth = WalletAuth(root)
        self.packages = PackageStore(root)
        self.chain = ChainRepository(root)
        self.transactions = TransactionService(root)
        self.admin = AdminService(root)
        self.agent = ManagedAgent(root)
        self.journal = Journal(root)
        self.reports = ReportService(root)
        self.installs = InstallService(root)
        self.admin.drain = self.agent.drain_for_activation

    def _reply(self, data, status=200, headers=None):
        body = json.dumps({'ok': True, 'data': data}, ensure_ascii=False).encode()
        return HTTPReply(status, {'Content-Type': 'application/json; charset=utf-8',
                                 'Cache-Control': 'no-store', **(headers or {})}, body)

    def _authorize(self, method, headers, path):
        host = headers.get('host', '')
        if host not in (f'127.0.0.1:{self.server_port}', f'localhost:{self.server_port}'):
            raise APIError('请求来源不被允许', 403, 'origin')
        origin = headers.get('origin')
        if ((origin is not None and origin != f'http://{host}')
                or headers.get('sec-fetch-site') not in (None, 'none', 'same-origin')):
            raise APIError('请求来源不被允许', 403, 'origin')
        if method == 'POST':
            if origin != f'http://{host}':
                raise APIError('请求来源不被允许', 403, 'origin')
            expected_type = 'application/zip' if path == '/api/packages' else 'application/json'
            if headers.get('content-type', '').split(';')[0].strip().lower() != expected_type:
                raise APIError('请求格式必须为 JSON', 415, 'content_type')
            if not secrets.compare_digest(headers.get('x-skillguard-token', ''), self.csrf_token):
                raise APIError('操作会话已失效，请刷新页面重试', 403, 'csrf')

    def _session(self, headers):
        cookie = SimpleCookie()
        try:
            cookie.load(headers.get('cookie', ''))
            token = cookie['sg_session'].value if 'sg_session' in cookie else ''
        except Exception:
            raise AuthError() from None
        session = self.auth.require(token, load_scope(self.root))
        expected = headers.get('x-skillguard-wallet')
        if expected is not None and expected.lower() != session.address.lower():
            raise AuthError('当前钱包与登录会话不匹配')
        return token, session

    def handle(self, method: str, path: str, headers: dict, body: bytes) -> HTTPReply:
        try:
            headers = {k.lower(): v for k, v in headers.items()}
            route = urlsplit(path).path
            self._authorize(method, headers, route)
            if method == 'GET':
                pages={'/':'catalog','/publish':'publish','/audit':'audit','/admin':'admin','/arbitration':'arbitration','/install':'install','/ops.html':'catalog'}
                if route.startswith('/skills/'):
                    from .chain import hex32
                    try: hex32(route.rsplit('/',1)[-1])
                    except APIError: raise APIError('not found',404,'not_found') from None
                    pages[route]='detail'
                resource=None
                if route in pages: resource=('pages/'+pages[route]+'.html','text/html; charset=utf-8')
                assets={'api','wallet','shell','transactions'}
                page_modules={'catalog','publish','audit','admin','detail','install','arbitration'}
                if route=='/assets/app.css': resource=('assets/app.css','text/css; charset=utf-8')
                for name in assets:
                    if route==f'/assets/{name}.mjs': resource=(f'assets/{name}.mjs','text/javascript; charset=utf-8')
                for name in page_modules:
                    if route==f'/pages/{name}.mjs': resource=(f'pages/{name}.mjs','text/javascript; charset=utf-8')
                if resource:
                    web=self.root/'web'
                    if not web.exists(): web=Path(__file__).resolve().parents[1]/'web'
                    relative,mime=resource;file=web/relative
                    if web.is_symlink() or any(parent.is_symlink() for parent in [file,*file.parents] if parent!=self.root.parent):
                        raise APIError('not found',404,'not_found')
                    if not file.is_file(): raise APIError('not found',404,'not_found')
                    return HTTPReply(200,{'Content-Type':mime,'Cache-Control':'no-store'},file.read_bytes())
            payload = {}
            if method == 'POST':
                limit = MAX_ZIP if route == '/api/packages' else 65536
                if len(body) > limit:
                    raise APIError('请求内容过大', 413, 'body_size')
                if route != '/api/packages':
                    try:
                        payload = json.loads(body or b'{}')
                        if not isinstance(payload, dict):
                            raise ValueError('object required')
                    except (ValueError, UnicodeError):
                        raise APIError('请求必须是合法 JSON 对象', 400, 'invalid_json') from None
            if method=='GET' and (route.startswith('/api/arbitration/cases') or route=='/api/funds'):
                scope=load_scope(self.root);query=parse_qs(urlsplit(path).query)
                if query.get('chainId')!=[str(scope.chain_id)] or query.get('registry',[''])[0].lower()!=scope.registry.lower():raise APIError('部署作用域不匹配',409,'scope_changed')
                service=ArbitrationService(self.root)
                if route=='/api/funds':return self._reply(service.funds(scope,query.get('address',[''])[0]))
                if route=='/api/arbitration/cases':return self._reply(service.list(scope))
                if route.endswith('/source'):
                    _,session=self._session(headers)
                    return self._reply(service.source(scope,route.split('/')[-2],session))
                return self._reply(service.case(scope,route.rsplit('/',1)[-1]))
            if method=='POST' and route in ('/api/arbitration/prepare','/api/funds/prepare'):
                _,session=self._session(headers)
                allowed={'resolve'} if '/arbitration/' in route else {'expire','withdraw'}
                if payload.get('action') not in allowed:raise APIError('此角色不支持该操作',400,'action')
                return self._reply(self.transactions.prepare(payload['action'],session,payload))
            if method=='POST' and route in ('/api/arbitration/confirm','/api/funds/confirm'):
                _,session=self._session(headers)
                return self._reply(self.transactions.confirm(payload.get('preparedId'),payload.get('txHash'),session))
            if method == 'GET' and route.startswith('/api/reports/'):
                scope=load_scope(self.root);query=parse_qs(urlsplit(path).query)
                if query.get('chainId') != [str(scope.chain_id)] or query.get('registry',[''])[0].lower() != scope.registry.lower():
                    raise APIError('部署作用域不匹配',409,'scope_changed')
                return self._reply(self.reports.read(scope,route.rsplit('/',1)[-1]))
            if method == 'POST' and route in ('/api/install/check','/api/install/execute'):
                scope=load_scope(self.root)
                return self._reply(self.installs.check(scope,payload.get('key')) if route.endswith('/check') else self.installs.execute(scope,payload.get('key')))
            if method == 'GET' and route in ('/api/agent/status','/api/agent/runs','/api/agent/events'):
                scope = load_scope(self.root)
                query = parse_qs(urlsplit(path).query)
                if query.get('chainId') != [str(scope.chain_id)] or query.get('registry',[''])[0].lower() != scope.registry.lower():
                    raise APIError('部署作用域不匹配',409,'scope_changed')
                if route.endswith('/status'): return self._reply(self.agent.status(scope))
                runs = self.journal.runs(scope.chain_id,scope.registry,query.get('key',[None])[0])
                if route.endswith('/runs'): return self._reply(runs)
                run_id = query.get('runId',[''])[0]
                if run_id not in {run['runId'] for run in runs}: raise APIError('未找到当前作用域运行记录',404,'not_found')
                try: after = int(query.get('after',['0'])[0])
                except ValueError: raise APIError('事件游标无效',400,'cursor') from None
                return self._reply(self.journal.events(run_id,after))
            if method == 'POST' and route in ('/api/agent/start','/api/agent/stop'):
                _,session = self._session(headers)
                return self._reply(self.agent.start(session) if route.endswith('/start') else self.agent.stop(session))
            if method == 'GET' and (route == '/api/skills' or route.startswith('/api/skills/')):
                scope = load_scope(self.root)
                query = parse_qs(urlsplit(path).query)
                if query.get('chainId') != [str(scope.chain_id)] or query.get('registry', [''])[0].lower() != scope.registry.lower():
                    raise APIError('部署作用域不匹配',409,'scope_changed')
                if route == '/api/skills':
                    return self._reply(self.chain.catalog(scope,query.get('publisher',[None])[0]))
                return self._reply(self.reports.detail(scope,route.rsplit('/',1)[-1]))
            if method == 'POST' and route in ('/api/publisher/prepare','/api/auditor/prepare','/api/admin/prepare'):
                _,session = self._session(headers)
                if route == '/api/admin/prepare':
                    return self._reply(self.admin.prepare(payload.get('step'),session,payload))
                allowed = {'register','request_audit'} if '/publisher/' in route else {'stake','human_decision'}
                if payload.get('action') not in allowed:
                    raise APIError('此角色不支持该操作',400,'action')
                return self._reply(self.transactions.prepare(payload['action'],session,payload))
            if method == 'POST' and route == '/api/auditor/cancel':
                _,session=self._session(headers)
                return self._reply(self.transactions.cancel(payload.get('preparedId'),session))
            if method == 'POST' and route in ('/api/publisher/confirm','/api/auditor/confirm','/api/admin/confirm'):
                _,session = self._session(headers)
                return self._reply(self.transactions.confirm(payload.get('preparedId'),payload.get('txHash'),session))
            if method == 'POST' and route == '/api/admin/activate':
                _,session = self._session(headers)
                scope = self.admin.activate(session,payload.get('revision'),payload.get('txHashes'))
                return self._reply(asdict(scope))
            if method == 'POST' and route == '/api/packages':
                _,session = self._session(headers)
                return self._reply(self.packages.upload(body,session),201)
            if method == 'GET' and route.startswith('/api/packages/'):
                _,session = self._session(headers)
                return self._reply(self.packages.preview(route.rsplit('/',1)[-1],session))
            if method == 'GET' and route == '/api/session':
                return self._reply({'csrfToken': self.csrf_token})
            if method == 'GET' and route == '/api/config':
                return self._reply(public_config(self.root))
            if method == 'POST' and route.removeprefix('/api/') in LEGACY_ACTIONS:
                raise APIError('此代签接口已停用，请使用独立角色页面连接自己的钱包', 410, 'legacy_action')
            if method == 'POST' and route == '/api/auth/challenge':
                message = self.auth.challenge(payload.get('address', ''), load_scope(self.root), headers['origin'])
                return self._reply({'message': message})
            if method == 'POST' and route == '/api/auth/verify':
                token, session = self.auth.verify(payload.get('message'), payload.get('signature'),
                                                  load_scope(self.root), headers['origin'])
                return self._reply({'address': session.address, 'expiresAt': session.expires_at}, headers={
                    'Set-Cookie': f'sg_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800'})
            if method == 'POST' and route == '/api/auth/logout':
                cookie = SimpleCookie()
                try:
                    cookie.load(headers.get('cookie',''))
                    token = cookie['sg_session'].value if 'sg_session' in cookie else ''
                except Exception:
                    token = ''
                self.auth.logout(token)
                return self._reply({}, headers={
                    'Set-Cookie': 'sg_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0'})
            raise APIError('not found', 404, 'not_found')
        except APIError as exc:
            return HTTPReply(exc.status, {'Content-Type': 'application/json; charset=utf-8',
                                         'Cache-Control': 'no-store'},
                             json.dumps({'ok': False, 'error': str(exc), 'code': exc.code},
                                        ensure_ascii=False).encode())
        except Exception:
            return HTTPReply(500, {'Content-Type': 'application/json; charset=utf-8'},
                             b'{"ok":false,"error":"Internal operation failed","code":"internal"}')

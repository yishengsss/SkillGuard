"""One-time SIWE challenges and revocable scoped EOA sessions."""
import hashlib
import json
import secrets
import sqlite3
import time
from dataclasses import asdict
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from eth_account import Account
from eth_account.messages import encode_defunct
from web3 import Web3

from .config import web3_for
from .models import APIError, ChainScope, WalletSession


class AuthError(APIError):
    def __init__(self, message='钱包会话无效，请重新连接并签名'):
        super().__init__(message, 401, 'wallet_authentication')


def is_eoa(root: Path, address: str, scope: ChainScope) -> bool:
    w3 = web3_for(root, scope)
    try:
        return bool(w3.eth.get_code(scope.registry)) and not bool(w3.eth.get_code(address))
    except Exception:
        raise AuthError('钱包验证所需的链上读取失败') from None


def _scope(scope: ChainScope) -> str:
    return json.dumps(asdict(scope), sort_keys=True, separators=(',', ':'))


def _utc(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace('+00:00', 'Z')


class WalletAuth:
    def __init__(self, root: Path):
        self.root = root
        folder = root / '.cache' / 'ops'
        folder.mkdir(parents=True, exist_ok=True)
        self.path = folder / 'sessions.sqlite3'
        with self._db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS challenges (
                    message TEXT PRIMARY KEY, address TEXT, scope TEXT, origin TEXT, expires INTEGER);
                CREATE TABLE IF NOT EXISTS sessions (
                    digest TEXT PRIMARY KEY, address TEXT, scope TEXT, expires INTEGER);
                DELETE FROM challenges;
                DELETE FROM sessions;
            ''')

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA journal_mode=WAL')
            with db:
                yield db
        finally:
            db.close()

    def challenge(self, address: str, scope: ChainScope, origin: str) -> str:
        try:
            address = Web3.to_checksum_address(address)
            parsed = urlsplit(origin)
            if (parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost')
                    or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
                    or not parsed.port):
                raise ValueError('origin')
        except Exception:
            raise AuthError('钱包地址或登录来源无效') from None
        now = int(time.time())
        message = (f'{parsed.netloc} wants you to sign in with your Ethereum account:\n'
                   f'{address}\n\n登录 SkillGuard 本机角色页面。此签名不发起交易。\n\n'
                   f'URI: {origin}\nVersion: 1\nChain ID: {scope.chain_id}\n'
                   f'Nonce: {secrets.token_hex(16)}\nIssued At: {_utc(now)}\n'
                   f'Expiration Time: {_utc(now + 300)}')
        with self._db() as db:
            db.execute('DELETE FROM challenges WHERE expires <= ?', (now,))
            db.execute('INSERT INTO challenges VALUES (?,?,?,?,?)',
                       (message, address, _scope(scope), origin, now + 300))
        return message

    def verify(self, message: str, signature: str, scope: ChainScope, origin: str):
        if not isinstance(message, str) or not isinstance(signature, str):
            raise AuthError()
        with self._db() as db:
            row = db.execute('SELECT * FROM challenges WHERE message=?', (message,)).fetchone()
        if (row is None or row['scope'] != _scope(scope) or row['origin'] != origin
                or row['expires'] <= time.time()):
            raise AuthError('登录挑战已失效或作用域不匹配')
        try:
            recovered = Account.recover_message(encode_defunct(text=message), signature=signature)
        except Exception:
            raise AuthError('钱包签名无效') from None
        if recovered.lower() != row['address'].lower() or not is_eoa(self.root, recovered, scope):
            raise AuthError('签名账户不匹配，或该钱包不支持 EOA 登录')
        token = secrets.token_urlsafe(32)
        expires = int(time.time()) + 1800
        with self._db() as db:
            db.execute('BEGIN IMMEDIATE')
            consumed = db.execute('DELETE FROM challenges WHERE message=? AND expires>?',
                                  (message, time.time())).rowcount
            if consumed != 1:
                raise AuthError('登录挑战已使用或过期')
            db.execute('INSERT INTO sessions VALUES (?,?,?,?)',
                       (hashlib.sha256(token.encode()).hexdigest(), recovered, _scope(scope), expires))
        return token, WalletSession(recovered, scope, expires)

    def require(self, token: str, scope: ChainScope) -> WalletSession:
        if not token:
            raise AuthError()
        with self._db() as db:
            row = db.execute('SELECT * FROM sessions WHERE digest=?',
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        if row is None or row['expires'] <= time.time() or row['scope'] != _scope(scope):
            raise AuthError()
        return WalletSession(row['address'], scope, row['expires'])

    def logout(self, token: str):
        with self._db() as db:
            db.execute('DELETE FROM sessions WHERE digest=?',
                       (hashlib.sha256(token.encode()).hexdigest(),))

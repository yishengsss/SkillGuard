"""Durable, scoped action records, independent of browser services."""
import json
import secrets
import sqlite3
import time
from contextlib import contextmanager


class Journal:
    def __init__(self,root):
        self.path=root/'.cache/agent-journal.sqlite3'
        self.path.parent.mkdir(parents=True,exist_ok=True)
        with self.db() as db:
            db.execute('PRAGMA journal_mode=WAL')
            db.execute('CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, chain INTEGER, registry TEXT, key TEXT, block INTEGER, created REAL)')
            db.execute('CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY AUTOINCREMENT, run TEXT, stage TEXT, time REAL, payload TEXT)')
            db.execute('CREATE INDEX IF NOT EXISTS scope_key ON runs(chain,registry,key)')

    @contextmanager
    def db(self):
        db=sqlite3.connect(self.path,timeout=15)
        try:
            db.execute('PRAGMA synchronous=FULL')
            with db: yield db
        finally: db.close()

    def begin(self,chain_id,registry,key,request_block):
        run=secrets.token_hex(16)
        with self.db() as db:
            db.execute('INSERT INTO runs VALUES (?,?,?,?,?,?)',(run,chain_id,registry.lower(),key.lower(),request_block,time.time()))
        return run

    def emit(self,run_id,stage,payload):
        if not isinstance(payload,dict): raise ValueError('event payload must be an object')
        with self.db() as db:
            if not db.execute('SELECT 1 FROM runs WHERE id=?',(run_id,)).fetchone(): raise ValueError('unknown run')
            cursor=db.execute('INSERT INTO events(run,stage,time,payload) VALUES (?,?,?,?)',(run_id,stage,time.time(),json.dumps(payload,ensure_ascii=False)))
            return cursor.lastrowid

    def runs(self,chain_id,registry,key=None):
        with self.db() as db:
            query='SELECT id,key,block,created FROM runs WHERE chain=? AND registry=?';params=[chain_id,registry.lower()]
            if key is not None: query+=' AND key=?';params.append(key.lower())
            rows=db.execute(query+' ORDER BY created DESC',params).fetchall()
            result=[]
            for run,key,block,created in rows:
                last=db.execute('SELECT stage FROM events WHERE run=? ORDER BY id DESC LIMIT 1',(run,)).fetchone()
                result.append({'runId':run,'key':key,'requestBlock':block,'createdAt':created,'stage':last[0] if last else 'created'})
            return result

    def events(self,run_id,after=0):
        with self.db() as db:
            rows=db.execute('SELECT id,stage,time,payload FROM events WHERE run=? AND id>? ORDER BY id',(run_id,after)).fetchall()
        return [{'eventId':i,'stage':stage,'time':timestamp,'payload':json.loads(payload)} for i,stage,timestamp,payload in rows]

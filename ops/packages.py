"""Owned immutable archives, validated before any package source is published."""
import hashlib
import io
import json
import os
import re
import sqlite3
import stat
import tempfile
import unicodedata
import zipfile
from contextlib import contextmanager
from pathlib import Path

from auditor.hashing import code_hash, metadata_hash
from auditor.skill_dir import capture_skill
from gate.identity import safe_identity_component
from .models import APIError, WalletSession

MAX_ZIP = 10*1024*1024
MAX_BYTES = 20*1024*1024
MAX_FILES = 512


class PackageError(APIError):
    def __init__(self, message='技能包校验失败', status=400):
        super().__init__(message, status, 'invalid_package')


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PackageError('manifest 不允许重复字段')
        result[key] = value
    return result


def _manifest(raw):
    try:
        data=json.loads(raw.decode('utf-8'),object_pairs_hook=_object)
        if (not isinstance(data,dict)
                or safe_identity_component(data.get('name'),128) is None
                or safe_identity_component(data.get('version'),64) is None
                or not isinstance(data.get('package'),str) or not data['package'].strip()
                or not isinstance(data.get('tools'),list)):
            raise ValueError('manifest fields')
        for tool in data['tools']:
            if (not isinstance(tool,dict) or not isinstance(tool.get('name'),str) or not tool['name']
                    or not isinstance(tool.get('description'),str)
                    or not isinstance(tool.get('inputSchema'),dict)):
                raise ValueError('tool fields')
        return data
    except PackageError:
        raise
    except (ValueError,UnicodeError,KeyError,TypeError):
        raise PackageError('manifest 格式或 name/version/tools 无效') from None


def _members(bundle):
    entries=[]
    seen={}
    count=0
    total=0
    for info in bundle.infolist():
        original=info.orig_filename
        if (original != info.filename or not original or original.startswith('/')
                or '\\' in original or re.match(r'^[A-Za-z]:',original)
                or any(unicodedata.category(c).startswith('C') for c in original)):
            raise PackageError('ZIP 包含不安全路径')
        text=original[:-1] if info.is_dir() else original
        parts=text.split('/')
        if any(p in ('','.','..') for p in parts):
            raise PackageError('ZIP 包含不安全路径')
        if any(p.casefold() in ('.git','.cache','__pycache__') or p.casefold().startswith('.env') for p in parts):
            raise PackageError('ZIP 不允许包含秘密文件或未参与审计的目录')
        mode=info.external_attr >> 16
        kind=stat.S_IFMT(mode)
        if (info.flag_bits & 1 or mode & 0o7000
                or kind not in ((0,stat.S_IFDIR) if info.is_dir() else (0,stat.S_IFREG))):
            raise PackageError('ZIP 不允许加密、链接、特殊文件或特殊权限')
        for i in range(1,len(parts)+1):
            raw='/'.join(parts[:i])
            folded=unicodedata.normalize('NFC',raw).casefold()
            is_dir=i<len(parts) or info.is_dir()
            explicit=i==len(parts)
            previous=seen.get(folded)
            if previous:
                if previous['raw'] != raw or previous['dir'] != is_dir or (explicit and previous['explicit']):
                    raise PackageError('ZIP 路径重复、大小写/Unicode 冲突或文件目录冲突')
                previous['explicit'] |= explicit
            else:
                seen[folded]={'raw':raw,'dir':is_dir,'explicit':explicit}
        if not info.is_dir():
            count+=1
            total+=info.file_size
            if count>MAX_FILES or total>MAX_BYTES:
                raise PackageError('ZIP 文件数量或解压大小超限',413)
        entries.append((info,parts,0o755 if mode & 0o111 else 0o644))
    manifests=[parts for info,parts,_ in entries if not info.is_dir() and parts[-1]=='manifest.json']
    if len(manifests)!=1 or len(manifests[0]) not in (1,2):
        raise PackageError('ZIP 需要唯一的根 manifest.json 或单层包装目录')
    prefix=manifests[0][:-1]
    if prefix and any(parts[:len(prefix)]!=prefix for _,parts,_ in entries):
        raise PackageError('ZIP 包装目录之外存在其他内容')
    return entries,prefix


class PackageStore:
    def __init__(self,root:Path):
        self.root=root.resolve()
        self.folder=self.root/'.cache/packages'
        self.folder.mkdir(parents=True,exist_ok=True)
        if self.root not in self.folder.resolve().parents:
            raise PackageError('包存储目录无效')
        self.path=self.folder/'index.sqlite3'
        with self._db() as db:
            db.execute('CREATE TABLE IF NOT EXISTS packages (id TEXT PRIMARY KEY,publisher TEXT,metadata TEXT)')

    @contextmanager
    def _db(self):
        db=sqlite3.connect(self.path,timeout=10)
        db.row_factory=sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def upload(self,data:bytes,session:WalletSession):
        if len(data)>MAX_ZIP:
            raise PackageError('ZIP 压缩大小超过 10 MiB',413)
        publisher=session.address
        owner_folder=self.folder/publisher
        owner_folder.mkdir(exist_ok=True)
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as bundle:
                entries,prefix=_members(bundle)
                with tempfile.TemporaryDirectory(prefix='.upload-',dir=owner_folder) as temporary:
                    source=Path(temporary)/'source'
                    source.mkdir()
                    actual=0
                    for info,parts,mode in entries:
                        relative=parts[len(prefix):]
                        if not relative:
                            continue
                        target=source.joinpath(*relative)
                        if info.is_dir():
                            target.mkdir(parents=True,exist_ok=True)
                            continue
                        target.parent.mkdir(parents=True,exist_ok=True)
                        with bundle.open(info) as incoming, target.open('xb') as output:
                            while chunk:=incoming.read(65536):
                                actual+=len(chunk)
                                if actual>MAX_BYTES:
                                    raise PackageError('ZIP 实际解压大小超限',413)
                                output.write(chunk)
                            output.flush()
                            os.fsync(output.fileno())
                        target.chmod(mode)
                    captured=capture_skill(source,source_root=self.root)
                    manifest=_manifest(captured.manifest_bytes)
                    code='0x'+code_hash(captured).hex()
                    metadata='0x'+metadata_hash(captured).hex()
                    identity={'publisher':publisher.lower(),'codeHash':code,'metadataHash':metadata,
                              'modes':list(captured.file_modes),'manifestMode':captured.manifest_mode}
                    package_id=hashlib.sha256(json.dumps(identity,sort_keys=True).encode()).hexdigest()
                    destination=owner_folder/package_id
                    relative_source=(destination/'source').relative_to(self.root).as_posix()
                    files=[{'path':'manifest.json','size':len(captured.manifest_bytes),'mode':captured.manifest_mode}]
                    files += [{'path':p,'size':len(b),'mode':dict(captured.file_modes)[p]} for p,b in captured.files]
                    preview={'packageId':package_id,'publisher':publisher,'manifest':manifest,'files':files,
                             'codeHash':code,'metadataHash':metadata,'source':relative_source}
                    if not destination.exists():
                        try:
                            os.rename(temporary,destination)
                        except FileExistsError:
                            pass  # Another upload of the same owned content completed first.
                    with self._db() as db:
                        db.execute('INSERT OR IGNORE INTO packages VALUES (?,?,?)',
                                   (package_id,publisher.lower(),json.dumps(preview,ensure_ascii=False)))
                    self.capture(package_id,publisher)
                    return preview
        except PackageError:
            raise
        except Exception:
            raise PackageError('ZIP 损坏、来源不可安全读取或存储失败') from None

    def _record(self,package_id:str,publisher:str|None=None):
        if not isinstance(package_id,str) or not re.fullmatch('[0-9a-f]{64}',package_id):
            raise PackageError('包 ID 无效',404)
        with self._db() as db:
            row=db.execute('SELECT * FROM packages WHERE id=?',(package_id,)).fetchone()
        if row is None or (publisher is not None and row['publisher']!=publisher.lower()):
            raise PackageError('包不存在或不属于当前钱包',403)
        return json.loads(row['metadata'])

    def preview(self,package_id:str,session:WalletSession):
        result=self._record(package_id,session.address)
        self.capture(package_id,session.address)
        return result

    def resolve_source(self,source:str)->Path:
        if not isinstance(source,str):
            raise PackageError('来源无效')
        parts=source.split('/')
        if (len(parts)!=5 or parts[:2]!=['.cache','packages'] or parts[-1]!='source'
                or not re.fullmatch('0x[0-9a-fA-F]{40}',parts[2])
                or not re.fullmatch('[0-9a-f]{64}',parts[3])):
            raise PackageError('来源不属于技能包存储')
        target=self.root.joinpath(*parts)
        current=self.root
        for part in parts:
            current=current/part
            if current.is_symlink():
                raise PackageError('来源目录不能包含符号链接')
        return target

    def capture(self,package_id:str,publisher:str):
        record=self._record(package_id,publisher)
        try:
            captured=capture_skill(self.resolve_source(record['source']),source_root=self.root)
            expected={f['path']:f['mode'] for f in record['files']}
            if ('0x'+code_hash(captured).hex()!=record['codeHash']
                    or '0x'+metadata_hash(captured).hex()!=record['metadataHash']
                    or any(expected.get(path)!=mode for path,mode in captured.file_modes)
                    or expected.get('manifest.json')!=captured.manifest_mode):
                raise PackageError('包的代码、manifest 或权限已改变，请重新上传')
            return captured
        except PackageError:
            raise
        except Exception:
            raise PackageError('包来源无法安全读取') from None

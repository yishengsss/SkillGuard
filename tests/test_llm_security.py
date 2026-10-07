"""Independent boundary tests for the optional LLM audit stage."""
import json
import urllib.request
from pathlib import Path

import pytest
from auditor.llm import LLMConfig, LLMError, check_consistency, load_config
from auditor.scanner import scan_skill_report


@pytest.fixture
def setup(tmp_path, monkeypatch):
    root = tmp_path / 'skill'
    root.mkdir()
    manifest = {'name':'weather','package':'weather-mcp','version':'1.0.0',
                'tools':[{'name':'weather','description':'Weather only','inputSchema':{}}]}
    (root/'manifest.json').write_text(json.dumps(manifest))
    (root/'server.py').write_text("def weather():\n    return 'sunny'\n")
    cfg = LLMConfig('fixture-key', 'https://example.org/v1', 'fixture-model')
    state = {'calls':[], 'findings':[]}

    class Response:
        status = 200
        def __enter__(self):return self
        def __exit__(self,*args):return False
        def read(self,size=-1):
            raw=json.dumps({'choices':[{'message':{'content':json.dumps({'findings':state['findings']})}}]}).encode()
            return raw if size<0 else raw[:size]
    class Opener:
        def open(self,req,**kwargs):
            state['calls'].append(req)
            return Response()
    monkeypatch.setattr(urllib.request,'build_opener',lambda *args:Opener())
    return root, cfg, tmp_path/'.cache/llm', state


def call(setup):
    root,cfg,cache,state=setup
    return check_consistency(root,scan_skill_report(root),cfg,cache)


@pytest.mark.parametrize('finding', [
    {'severity':'low','file':'server.py','evidence':'mismatch'},
    {'severity':'critical','file':'../secret','evidence':'mismatch'},
    {'severity':'critical','file':'missing.py','evidence':'mismatch'},
    {'severity':'critical','file':'.env','evidence':'mismatch'},
    {'severity':'critical','file':'server.py','evidence':''},
    {'severity':'critical','file':'server.py','evidence':' '},
    {'severity':'critical','file':'server.py','evidence':'x'*2001},
    {'severity':'critical','file':'server.py','evidence':False},
    {'severity':'critical','file':'server.py'},
    {'severity':'critical','file':'server.py','evidence':'mismatch','level':'SAFE'},
    {'rule':'arbitrary','stage':'llm','severity':'critical','file':'server.py','evidence':'mismatch'},
    {'rule':'LLM-001','stage':'static','severity':'critical','file':'server.py','evidence':'mismatch'},
])
def test_invalid_model_findings_fail_closed(setup,finding):
    root,cfg,cache,state=setup
    state['findings']=[finding]
    with pytest.raises(LLMError):call(setup)
    assert not list(cache.glob('*.json'))


@pytest.mark.parametrize('raw',[None,{},'safe',False,[{}]*101])
def test_invalid_findings_collection_fails_closed(setup,raw):
    setup[3]['findings']=raw
    with pytest.raises(LLMError):call(setup)


def test_sensitive_files_and_symlinks_not_sent(setup,tmp_path):
    root,cfg,cache,state=setup
    for folder in ('.git','.cache','__pycache__'):
        (root/folder).mkdir();(root/folder/'secret.py').write_text('HIDDEN_CONTENT_MARKER')
    (root/'.env').write_text('HIDDEN_CONTENT_MARKER')
    (root/'.env.local').write_text('HIDDEN_CONTENT_MARKER')
    outside=tmp_path/'outside.py';outside.write_text('HIDDEN_CONTENT_MARKER')
    (root/'linked.py').symlink_to(outside)
    call(setup)
    assert 'HIDDEN_CONTENT_MARKER' not in state['calls'][0].data.decode()


@pytest.mark.parametrize('changed',['server.py','manifest.json'])
def test_stale_report_rejected_before_network(setup,changed):
    root,cfg,cache,state=setup
    report=scan_skill_report(root)
    p=root/changed;p.write_text(p.read_text()+'\n')
    with pytest.raises(LLMError):check_consistency(root,report,cfg,cache)
    assert state['calls']==[]


def test_oversized_input_is_rejected_not_truncated(setup):
    (setup[0]/'server.py').write_text('#'+'x'*300000)
    with pytest.raises(LLMError):call(setup)
    assert setup[3]['calls']==[]


@pytest.mark.parametrize('which',['root','parent'])
def test_cache_directory_symlink_rejected(setup,tmp_path,which):
    root,cfg,cache,state=setup
    outside=tmp_path/'outside';outside.mkdir()
    if which=='root':
        cache.parent.mkdir();cache.symlink_to(outside,target_is_directory=True)
    else:cache.parent.symlink_to(outside,target_is_directory=True)
    with pytest.raises(LLMError):call(setup)
    assert list(outside.iterdir())==[]


def test_cache_file_symlink_never_followed(setup,tmp_path):
    call(setup)
    path=next(setup[2].glob('*.json'))
    outside=tmp_path/'outside.json';outside.write_text(path.read_text())
    original=outside.read_bytes();path.unlink();path.symlink_to(outside)
    with pytest.raises(LLMError):call(setup)
    assert outside.read_bytes()==original


def test_endpoint_change_invalidates_cache(setup):
    root,cfg,cache,state=setup
    call(setup)
    cfg2=LLMConfig('fixture-key','https://example.com/v1','fixture-model')
    check_consistency(root,scan_skill_report(root),cfg2,cache)
    assert len(state['calls'])==2


@pytest.mark.parametrize('url',['http://example.org/v1','https://user:password@example.org/v1',
                               'https://example.org/v1?key=secret','https://example.org/v1#secret'])
def test_unsafe_service_urls_rejected(tmp_path,monkeypatch,url):
    monkeypatch.setenv('LLM_API_KEY','fixture-key')
    monkeypatch.setenv('LLM_BASE_URL',url)
    monkeypatch.setenv('LLM_MODEL','fixture-model')
    with pytest.raises(LLMError):load_config(tmp_path)


@pytest.mark.parametrize('mutation',['path','count','unknown_field'])
def test_corrupt_cached_findings_rejected(setup,mutation):
    root,cfg,cache,state=setup
    state['findings']=[{'severity':'high','file':'server.py','evidence':'mismatch'}]
    call(setup)
    path=next(cache.glob('*.json')); data=json.loads(path.read_text())
    if mutation=='path':data['findings'][0]['file']='../outside.py'
    elif mutation=='count':data['findings']=data['findings']*101
    else:data['findings'][0]['level']='SAFE'
    path.write_text(json.dumps(data))
    with pytest.raises(LLMError):call(setup)
    assert len(state['calls'])==1


@pytest.mark.parametrize('constant',['SYSTEM_PROMPT','PROMPT_VERSION'])
def test_prompt_change_invalidates_cache(setup,monkeypatch,constant):
    from auditor import llm
    call(setup)
    monkeypatch.setattr(llm,constant,getattr(llm,constant)+' revised')
    call(setup)
    assert len(setup[3]['calls'])==2


def test_oversized_file_not_read_into_memory(setup,monkeypatch):
    from auditor import llm
    root,cfg,cache,state=setup
    (root/'server.py').write_text('#'+'x'*300000)
    report=scan_skill_report(root)
    read=llm.safe_read_bytes; observed=[]
    def record(path):
        observed.append(Path(path).name)
        return read(path)
    monkeypatch.setattr(llm,'safe_read_bytes',record)
    with pytest.raises(LLMError):check_consistency(root,report,cfg,cache)
    assert 'server.py' not in observed

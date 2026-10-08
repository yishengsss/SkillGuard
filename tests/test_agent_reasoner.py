import json
import pytest
from auditor.skill_dir import capture_skill
from auditor.scanner import scan_skill_report
from auditor.llm import LLMConfig
from tests.test_agent import write_skill


def responses(snapshot,findings=None):
    files={'manifest.json':snapshot.manifest_bytes,**dict(snapshot.files)}
    calls=[{'id':'read-'+str(i),'type':'function','function':{'name':'read_file','arguments':json.dumps({'path':path})}} for i,path in enumerate(files)]
    return [{'id':'req-read','model':'fixture-model','choices':[{'message':{'role':'assistant','content':None,'tool_calls':calls}}]},
            {'id':'req-finish','model':'fixture-model','usage':{'total_tokens':12},'choices':[{'message':{'role':'assistant','content':None,'tool_calls':[{'id':'finish','type':'function','function':{'name':'finish_audit','arguments':json.dumps({'summary':'代码逐项检查完成。','findings':findings or []})}}]}}]}]


def run(tmp_path,monkeypatch,queue,extra=''):
    from auditor import reasoner
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气',extra_code=extra)
    snapshot=capture_skill(source);events=[];requests=[]
    def post(url,cfg,body):
        requests.append(json.loads(body));return json.dumps(queue.pop(0)).encode()
    monkeypatch.setattr(reasoner,'_post',post)
    result=reasoner.audit_snapshot(snapshot,scan_skill_report(snapshot),LLMConfig('fixture-key','https://example.org/v1','fixture-model'),emit=lambda stage,data:events.append((stage,data)))
    return result,events,requests


def test_real_tool_loop_reads_snapshot_and_records_actual_rounds(tmp_path,monkeypatch):
    from auditor import reasoner
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气')
    snapshot=capture_skill(source)
    result,events,requests=run(tmp_path,monkeypatch,responses(snapshot))
    assert result['level']=='SAFE' and result['agent']['complete']
    assert result['agent']['requestIds']==['req-read','req-finish']
    assert result['agent']['readFiles']==['manifest.json','server.py']
    assert len(requests)==2 and requests[1]['messages'][-2]['role']=='tool'
    assert events[0][0]=='agent_started' and events[-1][0]=='agent_completed'
    assert 'fixture-key' not in json.dumps(events)


def test_no_finish_without_reading_files(tmp_path,monkeypatch):
    from auditor.reasoner import AgentAuditError
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气')
    with pytest.raises(AgentAuditError,match='完整'):
        run(tmp_path,monkeypatch,[responses(capture_skill(source))[1]])


@pytest.mark.parametrize('finding',[
 {'severity':'critical','file':'../.env','line':1,'quote':'VALUE = 1','explanation':'outside'},
 {'severity':'critical','file':'server.py','line':1,'quote':'FAKE_CODE','explanation':'fabricated'},
 {'severity':'critical','file':'server.py','line':True,'quote':'VALUE = 1','explanation':'bad line'},
])
def test_findings_require_exact_read_source_evidence(tmp_path,monkeypatch,finding):
    from auditor.reasoner import AgentAuditError
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气')
    with pytest.raises(AgentAuditError):run(tmp_path,monkeypatch,responses(capture_skill(source),[finding]))


def test_agent_can_find_risk_without_a_rule_hit(tmp_path,monkeypatch):
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气')
    findings=[{'severity':'medium','file':'server.py','line':1,'quote':'VALUE = 1','explanation':'只声明常量，没有实现天气工具。'}]
    result,events,_=run(tmp_path,monkeypatch,responses(capture_skill(source),findings))
    assert result['level']=='SUSPICIOUS' and result['findings'][-1]['stage']=='agent'
    assert result['agent']['summary']=='代码逐项检查完成。'


def test_network_failure_is_not_a_safe_report(tmp_path,monkeypatch):
    from auditor import reasoner
    from auditor.llm import LLMError
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气')
    def unavailable(*args):raise LLMError('LLM 服务返回 HTTP 401')
    monkeypatch.setattr(reasoner,'_post',unavailable)
    with pytest.raises(LLMError):reasoner.audit_snapshot(capture_skill(source),scan_skill_report(source),LLMConfig('fixture-key','https://example.org/v1','fixture-model'))


def test_rule_risk_cannot_be_downgraded_by_agent(tmp_path,monkeypatch):
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气',extra_code='HOST = "https://telemetry.example.com/v1"\n')
    result,_,_=run(tmp_path,monkeypatch,responses(capture_skill(source)),extra='HOST = "https://telemetry.example.com/v1"\n')
    assert result['level']=='SUSPICIOUS' and any(f['stage']!='agent' for f in result['findings'])


def test_invalid_tool_path_shape_fails_cleanly(tmp_path,monkeypatch):
    from auditor.reasoner import AgentAuditError
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气')
    queue=responses(capture_skill(source));queue[0]['choices'][0]['message']['tool_calls'][0]['function']['arguments']='{"path": []}'
    with pytest.raises(AgentAuditError,match='路径'):run(tmp_path,monkeypatch,queue)


def test_stop_before_request_does_not_call_api(tmp_path,monkeypatch):
    from auditor import reasoner
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气')
    monkeypatch.setattr(reasoner,'_post',lambda *a:pytest.fail('stopped worker called model'))
    with pytest.raises(reasoner.AgentAuditError,match='停止'):
        reasoner.audit_snapshot(capture_skill(source),scan_skill_report(source),LLMConfig('fixture-key','https://example.org/v1','fixture-model'),stop=lambda:True)


@pytest.mark.parametrize('message_patch,finish_reason',[
 ({'refusal':'I cannot complete this audit.'},'tool_calls'),
 ({},'content_filter'),
 ({},'length'),
])
def test_refused_or_truncated_model_response_cannot_finish_safe(tmp_path,monkeypatch,message_patch,finish_reason):
    from auditor.reasoner import AgentAuditError
    source=write_skill(tmp_path/'skill',name='agent-example',description='查询天气')
    queue=responses(capture_skill(source));queue[-1]['choices'][0]['message'].update(message_patch);queue[-1]['choices'][0]['finish_reason']=finish_reason
    with pytest.raises(AgentAuditError):run(tmp_path,monkeypatch,queue)

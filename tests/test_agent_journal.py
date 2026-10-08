import importlib
import json
from tests.test_agent import make_ctx,write_skill,bind_entry,RecordingSubmitter
from auditor.agent import AuditRequest,Registration,process_request
from auditor.hashing import code_hash,metadata_hash
from auditor.skill_dir import capture_skill


def test_events_follow_actual_audit_actions(tmp_path):
    Journal=importlib.import_module('auditor.journal').Journal
    skill=write_skill(tmp_path/'dynamic',name='timeline-example',description='查询天气')
    snapshot=capture_skill(skill,source_root=tmp_path)
    registration=Registration('timeline-example','1.0.0','dynamic',code_hash(snapshot),metadata_hash(snapshot))
    submitter=RecordingSubmitter();ctx=make_ctx(tmp_path,submitter=submitter)
    bind_entry(ctx,registration);ctx.contract.address='0x'+'22'*20;ctx.journal=Journal(tmp_path)
    process_request(ctx,AuditRequest(b'\x11'*32,1),registration)
    runs=ctx.journal.runs(31337,ctx.contract.address)
    stages=[e['stage'] for e in ctx.journal.events(runs[0]['runId'])]
    assert stages[:4]==['request_received','source_resolved','hashes_verified','scan_completed']
    assert stages[-1]=='report_saved' # injected submitter has no actual receipt to invent
    assert len(submitter.calls)==1
    restarted=Journal(tmp_path)
    assert restarted.events(runs[0]['runId'])==ctx.journal.events(runs[0]['runId'])
    assert restarted.runs(968,ctx.contract.address)==[]


def test_journal_scopes_pending_reports_and_event_cursors(tmp_path):
    Journal=importlib.import_module('auditor.journal').Journal
    journal=Journal(tmp_path)
    run=journal.begin(31337,'0x'+'22'*20,'0x'+'11'*32,9)
    first=journal.emit(run,'report_saved',{'reportHash':'0x'+'ab'*32})
    last=journal.emit(run,'waiting_human',{'reportHash':'0x'+'ab'*32})
    assert [e['eventId'] for e in journal.events(run,first)]==[last]
    assert journal.runs(31337,'0x'+'22'*20)[0]['stage']=='waiting_human'


def test_suspicious_waits_for_human_without_broadcast(tmp_path):
    Journal=importlib.import_module('auditor.journal').Journal
    skill=write_skill(tmp_path/'suspicious',name='pending-example',description='查询天气',extra_code='HOST = "https://telemetry.example.com/v1"\n')
    captured=capture_skill(skill,source_root=tmp_path)
    from auditor.scanner import scan_skill_report
    from auditor.report import SUSPICIOUS
    assert scan_skill_report(captured).level == SUSPICIOUS
    registration=Registration('pending-example','1.0.0','suspicious',code_hash(captured),metadata_hash(captured))
    submitter=RecordingSubmitter();ctx=make_ctx(tmp_path,submitter=submitter)
    bind_entry(ctx,registration);ctx.contract.address='0x'+'22'*20;ctx.journal=Journal(tmp_path)
    process_request(ctx,AuditRequest(b'\x12'*32,1),registration)
    assert submitter.calls==[]
    assert ctx.journal.runs(31337,ctx.contract.address)[0]['stage']=='waiting_human'

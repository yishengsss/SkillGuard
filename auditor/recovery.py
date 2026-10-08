"""Recover only the original signed intent; never choose another nonce."""
import json
from web3 import Web3
from web3.exceptions import TransactionNotFound
from .report import report_hash_hex
from .skill_dir import safe_read_text


def recover_submission(ctx,run_id,journal):
    events=journal.events(run_id)
    intents=[e['payload'] for e in events if e['stage']=='tx_intent']
    if not intents: return 'absent'
    intent=intents[-1];hash_=intent['txHash'];tx=intent['transaction']
    saved=[e['payload'].get('reportHash') for e in events if e['stage']=='report_saved']
    try:
        directory=ctx.root/'reports'
        if directory.is_symlink() or not directory.resolve().is_relative_to(ctx.root.resolve()): raise ValueError('report directory escaped')
        report=json.loads(safe_read_text(directory/f'{saved[-1]}.json'))
        if report_hash_hex(report)!=saved[-1]: raise ValueError('report changed')
        if ctx.w3.eth.chain_id!=ctx.chain_id or tx['chainId']!=ctx.chain_id or tx.get('to','').lower()!=ctx.contract.address.lower(): raise ValueError('scope changed')
    except Exception:
        journal.emit(run_id,'recovery_conflict',{'reason':'saved report or scope does not match'})
        return 'conflict'
    try:
        receipt=ctx.w3.eth.get_transaction_receipt(hash_)
        if receipt['status']==1:
            from .protocol import registry_capabilities
            try:
                block=receipt['blockNumber']
                capabilities=registry_capabilities(ctx.w3,ctx.contract,block)
                key=ctx.contract.functions.keyOf(report['skill'],report['version']).call(block_identifier=block)
                entry=ctx.contract.functions.skills(key).call(block_identifier=block)
                malicious=report.get('humanDecision')=='malicious' or (not report.get('humanDecision') and report['level']=='MALICIOUS')
                expected=5 if malicious and capabilities['arbitrationSupported'] else 4 if malicious else 3
                if entry[5]!=expected or Web3.to_hex(entry[6])!=saved[-1] or entry[7].lower()!=ctx.account.address.lower():raise ValueError()
            except Exception:
                journal.emit(run_id,'recovery_conflict',{'reason':'receipt state or report identity does not match'})
                return 'conflict'
            journal.emit(run_id,'receipt_confirmed',{'txHash':hash_,'blockNumber':receipt['blockNumber'],'recovered':True})
            return 'confirmed'
        journal.emit(run_id,'receipt_failed',{'txHash':hash_,'blockNumber':receipt['blockNumber']})
        return 'failed'
    except TransactionNotFound: pass
    try:
        ctx.w3.eth.get_transaction(hash_)
        return 'pending'
    except TransactionNotFound: pass
    nonce=ctx.w3.eth.get_transaction_count(ctx.account.address,'pending')
    if nonce!=intent['nonce']:
        journal.emit(run_id,'recovery_conflict',{'txHash':hash_,'reason':'original nonce unavailable'})
        return 'conflict'
    signed=ctx.account.sign_transaction(tx)
    if Web3.to_hex(Web3.keccak(signed.raw_transaction))!=hash_:
        journal.emit(run_id,'recovery_conflict',{'reason':'reconstructed transaction hash differs'})
        return 'conflict'
    # The intent remains durable even if this RPC response is lost again.
    ctx.w3.eth.send_raw_transaction(signed.raw_transaction)
    journal.emit(run_id,'tx_broadcast',{'txHash':hash_,'recovered':True})
    return 'pending'

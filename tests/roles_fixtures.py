"""Isolated public Anvil accounts; never read the user's live configuration."""
import json
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from eth_account import Account
from web3 import Web3

Account.enable_unaudited_hdwallet_features()
MNEMONIC='test test test test test test test test test test test junk'

@dataclass
class RoleFixture:
    root: Path
    process: subprocess.Popen
    w3: Web3
    owner: object
    publishers: list
    auditor: object
    scope: object
    arbiter: object
    treasury: object
    def close(self):
        self.process.terminate()
        try: self.process.wait(5)
        except subprocess.TimeoutExpired:
            self.process.kill();self.process.wait(5)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def make_role_fixture(root,rpc_port=0,http_port=0):
    from ops.chain import artifact
    from ops.config import load_scope
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    port=rpc_port or free_port()
    process=subprocess.Popen(['/Users/keason/.foundry/bin/anvil','--host','127.0.0.1','--port',str(port),'--chain-id','31337','--silent'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    w3=Web3(Web3.HTTPProvider(f'http://127.0.0.1:{port}',request_kwargs={'timeout':5}))
    try:
        for _ in range(100):
            if process.poll() is not None: raise RuntimeError('isolated Anvil failed to start')
            if w3.is_connected(): break
            time.sleep(.05)
        else: raise RuntimeError('isolated Anvil unavailable')
        accounts=[Account.from_mnemonic(MNEMONIC,account_path=f"m/44'/60'/0'/0/{i}") for i in range(6)]
        owner,p1,p2,auditor=accounts[:4]
        arbiter,treasury=accounts[4:]
        def deploy(name):
            art=artifact(root,name)
            factory=w3.eth.contract(abi=art['abi'],bytecode=art['bytecode']['object'])
            receipt=w3.eth.wait_for_transaction_receipt(factory.constructor(owner.address).transact({'from':owner.address}))
            assert receipt.status==1
            return w3.eth.contract(address=receipt.contractAddress,abi=art['abi']),receipt.blockNumber
        registry,block=deploy('SkillRegistry');license,_=deploy('SkillLicense')
        for fn in (registry.functions.configureArbitration(arbiter.address,treasury.address),registry.functions.setSkillLicense(license.address),license.functions.setRegistry(registry.address)):
            assert w3.eth.wait_for_transaction_receipt(fn.transact({'from':owner.address})).status==1
        (root/'deployments.json').write_text(json.dumps({'chainId':31337,'SkillRegistry':registry.address,'SkillLicense':license.address,'deploymentBlock':block}))
        (root/'.env').write_text(f'RPC_URL=http://127.0.0.1:{port}\nAUDITOR_PRIVATE_KEY={auditor.key.hex()}\n')
        (root/'.env').chmod(0o600)
        return RoleFixture(root,process,w3,owner,[p1,p2],auditor,load_scope(root),arbiter,treasury)
    except BaseException:
        process.terminate();process.wait(5);raise

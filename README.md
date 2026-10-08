# SkillGuard

**Auditable security checks for AI-agent skills, before installation.**

SkillGuard records versioned skill hashes and audit outcomes on an EVM chain. A resident audit worker checks registered source snapshots, while an installer-facing MCP server verifies the chain status and hashes before it copies a skill. Human-controlled wallets provide deposits, stakes, deployment, and—on the new protocol—independent arbitration.

> **Local-first prototype.** The role-based web app and protocol-v2 arbitration flow are intended for isolated Anvil testing. The existing BOT Testnet deployment (chain ID `968`) is protocol v1; it has not been migrated to protocol v2. Do not assume v2 arbitration is active on BOT.

## What it does

```text
Publisher wallet                 Audit service wallet
register version + deposit  ──▶  resident worker checks source and hashes
                                      │
                     SAFE ────────────┼──▶ VERIFIED license; publisher can withdraw
                     MALICIOUS ───────┼──▶ protocol v1: legacy settlement
                                      │    protocol v2: deposit frozen for arbitration
                     SUSPICIOUS ──────┴──▶ no automatic verdict; human review

Installer agent ──▶ MCP check/install ──▶ chain status + license + content-hash check
```

### Protocol versions

| Protocol | Malicious report behavior | Where it applies |
|---|---|---|
| **v1** | Legacy contract behavior: the malicious report is final under the single-auditor model. | Existing deployments, including the current BOT Testnet deployment. |
| **v2** | Malicious report becomes `ArbitrationPending`; the deposit is frozen for up to seven days. A separately configured arbiter confirms or overturns it. Funds are credited to the public treasury or publisher and withdrawn using pull payments. | New deployments only, after the fifth deployment step configures distinct arbiter and treasury wallets. |

The UI detects the deployed contract protocol. A v1 deployment is not represented as having v2 arbitration.

## Features

- **Version-bound registration:** records source, `codeHash`, and `metadataHash`; a new version requires a new audit.
- **Audit pipeline:** metadata rules, static rules, package-name similarity checks, and an optional LLM/tool-calling audit. The resident worker does not execute uploaded code.
- **Audit evidence:** canonical JSON reports are hashed and linked to the on-chain result. Model tool calls and run events are recorded when available; historical reports without a run log are identified as such.
- **Human-controlled transactions:** browser EOA wallets sign publisher, auditor, arbiter, treasury, and owner actions. The web backend prepares and verifies transactions; it does not sign for publishers or owners.
- **MCP installation gate:** `check_skill` and `install_skill` verify chain status, license, and content hashes. Failed checks reject installation.
- **Role-based web app:** catalogue, publisher, audit operations, administrator, detail, install, and independent arbitration pages.
- **BOT Testnet read-only history:** current public deployment history can be browsed without submitting transactions.

## Quick start: isolated local demo

### Requirements

- Python 3.11+
- Foundry (`anvil`, `forge`, `cast`)
- Node.js (web UI tests only)

```bash
git clone https://github.com/yishengsss/SkillGuard.git
cd SkillGuard

python3.11 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
```

Set `RPC_URL` and three **different** local/test wallets in `.env`:

| Variable | Role |
|---|---|
| `PRIVATE_KEY` | Publisher: register skills and lock deposits. |
| `AUDITOR_PRIVATE_KEY` | Audit operator: stake and sign audit results. |
| `OWNER_PRIVATE_KEY` | Administrator: deploy and manage contracts. |
| `LLM_API_KEY`, `LLM_BASE_URL`, `LLM_MODEL` | Required by the resident web/CLI Agent; optional for offline rules-only CLI scans. |
| `ARBITER_ADDRESS`, `TREASURY_ADDRESS` | Optional v2 deployment roles. Set both to distinct wallets when using the local demo with protocol-v2 arbitration. |

For a local Anvil run, open two terminals:

```bash
# Terminal 1 — local chain
anvil
```

```bash
# Terminal 2 — complete demo (uses the RPC_URL in .env)
./demo.sh --no-pause
```

The demo deploys to a fresh local chain when needed, stakes through the human-operated command, starts the resident audit worker, registers `weather` and `mail-helper`, waits for on-chain outcomes, then calls the installer MCP tools. The resident worker requires valid `LLM_API_KEY`, `LLM_BASE_URL`, and `LLM_MODEL` settings; rule-only scans do not. To exercise protocol-v2 arbitration, also set `ARBITER_ADDRESS` and `TREASURY_ADDRESS` to distinct local wallets before deploying. It exits with a clear “already registered” message if run again without resetting Anvil.

To keep the existing `.env` unchanged while selecting local Anvil:

```bash
DEMO_RPC_URL=http://127.0.0.1:8545 ./demo.sh --no-pause
```

### Start the role-based web app

The web app binds to loopback only. It requires a valid deployment configuration and RPC:

```bash
.venv/bin/python -m ops.server --port 8765
```

Open <http://127.0.0.1:8765/>. The test-only isolated role demo uses a separate Anvil instance and public test wallets; never fund those wallets with real assets:

```bash
.venv/bin/python tests/role_demo.py --rpc-port 18857 --port 18701
```

Human transactions are signed in the browser wallet. The audit service wallet is configured separately and must be staked by its operator before starting the worker.

## Useful commands

```bash
# Contract and regression tests
(cd contracts && forge test -vv)
.venv/bin/python -m pytest -q -m 'not anvil'
node --test tests/web/*.test.mjs

# Isolated role / HTTP flows (start their own Anvil fixtures)
.venv/bin/python -m pytest tests/test_roles_e2e.py tests/test_ops_chain.py \
  tests/test_ops_transactions.py tests/test_ops_admin.py -q

# Audit and operations
.venv/bin/python -m auditor.cli samples/weather
.venv/bin/python -m auditor.cli samples/weather --submit
.venv/bin/python -m auditor.cli <skill-dir> --submit --human-decision safe
.venv/bin/python -m auditor.stake
.venv/bin/python -m auditor.agent [--once] [--from-block N] [--poll SECONDS]
.venv/bin/python gate/mcp_server.py
```

The resident Agent requires model configuration and uses read-only snapshot tools. It does not execute skill code, fetch remote Git repositories, or stake automatically. `SUSPICIOUS` reports are held for human review.

## Independent arbitration (protocol v2)

Protocol v2 adds `ArbitrationPending` and `ArbitrationExpired` states:

1. The auditor’s provisional malicious verdict freezes the publisher deposit; it does not pay the reporter and does not mint a license.
2. A distinct, one-time-configured arbiter reviews the original report and source evidence before the seven-day deadline.
3. The arbiter confirms malicious (funds credited to the treasury) or overturns it (publisher refunded and a verified license minted).
4. If the deadline expires, anyone may finalize the timeout; the publisher is credited, but the skill remains unverified.
5. The publisher or treasury withdraws its own credited balance. The contract never pushes settlement funds to a third party.

Deploying v2 requires five owner-signed steps: deploy Registry, deploy License, wire Registry to License, wire License to Registry, and configure the independent arbiter and treasury. The addresses must be distinct from each other and the owner. The fifth step is one-time and locked on-chain.

The existing BOT deployment is v1. The repository’s v2 code and UI do **not** change that deployment. No BOT migration or transaction is performed by this README’s local demo instructions.

## Security and limitations

- The demo skills are inert fixtures. They contain rule-triggering strings, but their sample code does not read real credentials, execute external commands, or connect to the network.
- Static rules can be bypassed by wording changes or string construction; `STAT-002` may also flag benign URLs. An audit is not a proof of safety.
- Single-auditor reports are not automatically proven correct. On v1, malicious verdicts use legacy settlement. On v2, arbitration adds a separate reviewer but does not make the review infallible.
- There is no audit fee, and auditor stake has no withdrawal mechanism in the current contract.
- Source retrieval supports local paths only; remote Git fetching is not implemented.
- The installer MCP gate is an integration contract, not a platform-enforced hook. An agent configured with this tool could still copy files through another mechanism.
- The role web app is a local prototype and its backend is part of the local trust boundary. Keep it bound to loopback; do not expose it publicly.
- Existing BOT deployment and history are read-only for this workflow. Verify the active `deployments.json` and network before signing any transaction.

See [the role-page acceptance record](docs/ROLE-PAGES-ACCEPTANCE.md), [the v2 arbitration plan](docs/superpowers/plans/2026-10-08-independent-arbitration.md), and [the auditor workflow](docs/tool-agent-auditing.md) for implementation and validation details.

## License

This repository currently has no root-level `LICENSE` file. Contact the maintainers for reuse terms; SPDX headers on individual Solidity files do not by themselves specify the license for the whole repository.

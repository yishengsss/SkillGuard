#!/usr/bin/env bash
# SkillGuard 一键演示(docs/PROMPTS.md 第 10 步，SPEC 第 1 节主流程)
#   注册 → 请求审计(锁押金)→ 审计报告上链 → 门禁查链
# 覆盖三条路径：
#   1. weather      SAFE      → Verified，门禁放行
#   2. mail-helper  MALICIOUS → 押金罚没给审计者，门禁拒绝
# 用法：./demo.sh          (需要 anvil 在 127.0.0.1:8545 运行，或指向任意测试网)
# 所有密钥一律来自根目录 .env，不在脚本内出现。
set -euo pipefail
# macOS 自带 bash 3.2 在 UTF-8 locale 下会把 `$var` 后紧跟的多字节字符拼进变量名，
# 导致 "unbound variable"。全局切 C locale 规避；Python 用 UTF-8 模式不受影响。
export LC_ALL=C
export PYTHONUTF8=1
cd "$(dirname "$0")"

log()  { printf '\n\033[0;1m== %s\033[0;0m\n' "$*"; }
step() { printf '\n\033[1;34m-- %s\033[0;0m\n' "$*"; }
fail() { printf '\n\033[1;31m✘ %s\033[0;0m\n' "$*" >&2; exit 1; }

# ---- 0. 依赖与环境 ----
for bin in cast forge; do
  command -v "$bin" >/dev/null 2>&1 || fail "缺 $bin(Foundry)。请先安装：curl -LsSf https://foundry.paradigm.xyz | sh"
done
[ -f .env ] || fail "根目录没有 .env。先 cp .env.example .env，填入 RPC_URL、PRIVATE_KEY、AUDITOR_PRIVATE_KEY"
set -a; # shellcheck disable=SC1091
source .env; set +a
# 可用 DEMO_RPC_URL 临时覆盖 RPC（不改 .env），本地演示时传 http://127.0.0.1:8545
: "${DEMO_RPC_URL:=}"
[ -n "$DEMO_RPC_URL" ] && RPC_URL="$DEMO_RPC_URL"
: "${RPC_URL:?请在 .env 里填 RPC_URL}"
: "${PRIVATE_KEY:?请在 .env 里填 PRIVATE_KEY(发布者/部署者)}"
: "${AUDITOR_PRIVATE_KEY:?请在 .env 里填 AUDITOR_PRIVATE_KEY(审计者)}"
PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
"$PY" -c 'import web3, yaml, rich' 2>/dev/null || fail "Python 依赖不全。先：python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"

PUBLISHER=$(cast wallet address --private-key "$PRIVATE_KEY")
AUDITOR=$(cast wallet address --private-key "$AUDITOR_PRIVATE_KEY")
[ "$PUBLISHER" != "$AUDITOR" ] || fail "PRIVATE_KEY 与 AUDITOR_PRIVATE_KEY 是同一地址，合约要求 publisher != auditor"

# 三钱包分离（SPEC 第 10 节）：缺 OWNER_PRIVATE_KEY 提示补配置
if [ -z "${OWNER_PRIVATE_KEY:-}" ]; then
  fail "缺 OWNER_PRIVATE_KEY（管理员，部署合约 & slashAuditor）。请在 .env 按角色补三个私钥（参照 .env.example）"
fi
OWNER=$(cast wallet address --private-key "$OWNER_PRIVATE_KEY")
[ "$OWNER" != "$PUBLISHER" ] || fail "OWNER_PRIVATE_KEY 与 PRIVATE_KEY 相同（第 10 节要求三钱包两两不同）"
[ "$OWNER" != "$AUDITOR" ] || fail "OWNER_PRIVATE_KEY 与 AUDITOR_PRIVATE_KEY 相同（第 10 节要求三钱包两两不同）"

log "0. 连接链并保证部署可用"
cast chain-id --rpc-url "$RPC_URL" >/dev/null 2>&1 \
  || fail "连不上 RPC_URL=$RPC_URL(本地演示请先另开终端运行 anvil)"
CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL")
REGISTRY=$(command "$PY" -c 'import json;print(json.load(open("deployments.json"))["SkillRegistry"])')
LICENSE=$(command "$PY" -c 'import json;print(json.load(open("deployments.json"))["SkillLicense"])')
DEPLOYED_CHAIN=$(command "$PY" -c 'import json;print(json.load(open("deployments.json")).get("chainId"))')
ONCHAIN_CODE=$(cast code "$REGISTRY" --rpc-url "$RPC_URL")

# 本地链：不自愈就什么都不合适——deployments.json 与当前链不符、字节码为空都允许重部署，
# 并给 .env 里的密钥兜底测试资金(anvil_setBalance，仅本地)。
# 测试网(SPEC 第 7 节)：绝不自动发部署交易，状态不对就给指引直接退出，防止误烧 gas。
case "$RPC_URL" in
  http://127.0.0.1:*) IS_LOCAL=yes ;;
  http://localhost:*) IS_LOCAL=yes ;;
  *) IS_LOCAL=no ;;
esac

if [ "$IS_LOCAL" = "yes" ]; then
  for addr in "$PUBLISHER" "$AUDITOR" "$OWNER"; do
    [ "$(cast balance "$addr" --rpc-url "$RPC_URL" 2>/dev/null || echo 0)" -gt 1000000000000000000 ] \
      || cast rpc anvil_setBalance "$addr" 0x1BC16D674EC80000 --rpc-url "$RPC_URL" >/dev/null   # 2 ETH
  done
  if [ "$DEPLOYED_CHAIN" != "$CHAIN_ID" ] || [ -z "$ONCHAIN_CODE" ] || [ "$ONCHAIN_CODE" = "0x" ]; then
    step "本地链与 deployments.json 不匹配，用管理员钱包重新部署（SPEC 第 7 节）"
    (cd contracts && PRIVATE_KEY="$OWNER_PRIVATE_KEY" forge script script/Deploy.s.sol --rpc-url "$RPC_URL" --broadcast)
    REGISTRY=$(command "$PY" -c 'import json;print(json.load(open("deployments.json"))["SkillRegistry"])')
    LICENSE=$(command "$PY" -c 'import json;print(json.load(open("deployments.json"))["SkillLicense"])')
  fi
else
  if [ "$DEPLOYED_CHAIN" != "$CHAIN_ID" ] || [ -z "$ONCHAIN_CODE" ] || [ "$ONCHAIN_CODE" = "0x" ]; then
    fail "deployments.json 与链 $CHAIN_ID 不匹配。请先用管理员钱包部署并提交地址：
  cd contracts && PRIVATE_KEY=\"\$OWNER_PRIVATE_KEY\" forge script script/Deploy.s.sol --rpc-url \"\$RPC_URL\" --broadcast"
  fi
fi
echo "chainId      : $CHAIN_ID"
echo "SkillRegistry: $REGISTRY"
echo "SkillLicense : $LICENSE"
echo "publisher    : $PUBLISHER"
echo "auditor      : $AUDITOR"
echo "owner        : $OWNER（链上读取 owner()=$(cast call "$REGISTRY" "owner()(address)" --rpc-url "$RPC_URL")）"

MIN_DEPOSIT=$(cast call "$REGISTRY" "MIN_DEPOSIT()(uint256)" --rpc-url "$RPC_URL")   # wei
MIN_DEPOSIT=${MIN_DEPOSIT%% *}   # cast 对整数也会带人类可读后缀，如 “10000000000000000 [1e16]”，只留原值
MIN_DEPOSIT_ETH=$(cast --from-wei "$MIN_DEPOSIT")

# ---- 复用的演示子流程 ----
# 流程一：注册版本 + 请求审计(发布者)
register_and_request() { # $1=技能目录 $2=repo
  local dir="$1" repo="$2" name version hashes status
  name=$(command "$PY" -c "import json;print(json.load(open('$dir/manifest.json'))['name'])")
  version=$(command "$PY" -c "import json;print(json.load(open('$dir/manifest.json'))['version'])")
  REG_NAME="$name"; REG_VERSION="$version"   # 供后续从链上读状态使用
  # 每个版本只能注册一次（防“先良性后投毒”）；重跑演示需要重启 anvil 归零状态
  status=$(cast call "$REGISTRY" "getStatus(string,string)(uint8)" "$name" "$version" --rpc-url "$RPC_URL" 2>/dev/null || echo none)
  [ "$status" = "0" ] || fail "$name@$version 已注册过（status=$status）。请重启 anvil（Ctrl-C 后重跑 anvil）得到干净链再运行 ./demo.sh"
  hashes=$(command "$PY" -c \
    "import sys;sys.path.insert(0,'.');from auditor.hashing import code_hash,metadata_hash;from pathlib import Path;d=Path('$dir');print('0x'+code_hash(d).hex(),'0x'+metadata_hash(d).hex())")
  read -r CODE_HASH META_HASH <<EOF
$hashes
EOF
  step "register $name@$version(publisher=$PUBLISHER)"
  cast send "$REGISTRY" \
    "register(string,string,string,bytes32,bytes32)" "$name" "$version" "$repo" "$CODE_HASH" "$META_HASH" \
    --private-key "$PRIVATE_KEY" --rpc-url "$RPC_URL" 2>/dev/null | awk '/transactionHash/ {hash=$2} END {print "tx: " hash}'
  step "requestAudit $name@$version，押金 $MIN_DEPOSIT_ETH ETH"
  cast send "$REGISTRY" "requestAudit(string,string)" "$name" "$version" --value "$MIN_DEPOSIT" \
    --private-key "$PRIVATE_KEY" --rpc-url "$RPC_URL" 2>/dev/null | awk '/transactionHash/ {hash=$2} END {print "tx: " hash}'
}

# 流程二：审计 + 上链提交(审计者)
audit_and_submit() { # $1=技能目录
  step "audit + submitReport(auditor=$AUDITOR)"
  command "$PY" -m auditor.cli "$1" --submit
}

# 流程三：安装门禁
gate_check() { # $1=技能目录
  set +e
  command "$PY" gate/gate.py install "$1"
  local rc=$?
  set -e
  echo "gate-exit: $rc"
}

log "1. 质押(人):python -m auditor.stake"
command "$PY" -m auditor.stake || fail "质押失败：请检查 AUDITOR_PRIVATE_KEY 与 RPC 后重跑"

log "2. SAFE 样本 weather"
register_and_request samples/weather "samples/weather"
audit_and_submit samples/weather
echo "getStatus($REG_NAME@$REG_VERSION)=$(cast call "$REGISTRY" "getStatus(string,string)(uint8)" "$REG_NAME" "$REG_VERSION" --rpc-url "$RPC_URL")"
gate_check samples/weather

log "3. 恶意样本 mail-helper"
PUB_BEFORE=$(cast balance "$PUBLISHER" --rpc-url "$RPC_URL")
AUD_BEFORE=$(cast balance "$AUDITOR" --rpc-url "$RPC_URL")
register_and_request samples/mail-helper "samples/mail-helper"
audit_and_submit samples/mail-helper
PUB_AFTER=$(cast balance "$PUBLISHER" --rpc-url "$RPC_URL")
AUD_AFTER=$(cast balance "$AUDITOR" --rpc-url "$RPC_URL")
echo "getStatus($REG_NAME@$REG_VERSION)=$(cast call "$REGISTRY" "getStatus(string,string)(uint8)" "$REG_NAME" "$REG_VERSION" --rpc-url "$RPC_URL")  isVerified=$(cast call "$LICENSE" "isVerified(string,string)(bool)" "$REG_NAME" "$REG_VERSION" --rpc-url "$RPC_URL")"
echo "publisher-balance: $PUB_BEFORE -> $PUB_AFTER wei   auditor-balance: $AUD_BEFORE -> $AUD_AFTER wei"
gate_check samples/mail-helper

log "4. 完成"
echo "报告见 reports/，看板：open web/index.html(用 viem 读取链上事件)"

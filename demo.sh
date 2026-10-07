#!/usr/bin/env bash
# SkillGuard 一键演示（Agent 版，docs/PROMPTS.md A8；SPEC 1 主流程）
#   部署（管理员）→ 人质押 → 常驻审计 Agent 后台监听
#   → 发布者注册/请求审计 → Agent 无人值守自动上链 → 安装方 Agent MCP 工具查链安装
# 用法：./demo.sh [--no-pause]      （默认本地 anvil；关键步骤暂停等回车，--no-pause 跳过）
# 所有密钥一律来自根目录 .env；判定/数值/交易号/状态全部来自真实运行或链上读取。
set -euo pipefail
# macOS 自带 bash 3.2 在 UTF-8 locale 下会把 `$var` 后紧跟的多字节字符拼进变量名，
# 导致 "unbound variable"。全局切 C locale 规避；Python 用 UTF-8 模式不受影响。
export LC_ALL=C
export PYTHONUTF8=1
cd "$(dirname "$0")"

log()  { printf '\n\033[0;1m== %s\033[0;0m\n' "$*"; }
step() { printf '\n\033[1;34m-- %s\033[0;0m\n' "$*"; }
fail() { printf '\n\033[1;31m✘ %s\033[0;0m\n' "$*" >&2; exit 1; }
pause() {
  if [ "${NO_PAUSE:-}" = "1" ]; then return; fi
  printf '\n\033[0;93m（回车继续）\033[0;0m'
  read -r || true
}

for bin in cast forge; do
  command -v "$bin" >/dev/null 2>&1 || fail "缺 $bin（Foundry）。请先安装：curl -LsSf https://foundry.paradigm.xyz | sh"
done
[ -f .env ] || fail "根目录没有 .env。先 cp .env.example .env，按角色填 RPC_URL、PRIVATE_KEY、AUDITOR_PRIVATE_KEY、OWNER_PRIVATE_KEY"
set -a  # shellcheck disable=SC1091
source .env; set +a
# 可用 DEMO_RPC_URL 临时覆盖 RPC（不改 .env），本地演示时传 http://127.0.0.1:8545
: "${DEMO_RPC_URL:=}"
[ -n "$DEMO_RPC_URL" ] && RPC_URL="$DEMO_RPC_URL"
: "${RPC_URL:?请在 .env 里填 RPC_URL}"
: "${PRIVATE_KEY:?请在 .env 里填 PRIVATE_KEY（发布者）}"
: "${AUDITOR_PRIVATE_KEY:?请在 .env 里填 AUDITOR_PRIVATE_KEY（审计者运营方）}"
PY=.venv/bin/python
[ -x "$PY" ] || PY=python3
"$PY" -c 'import web3, yaml, rich, mcp' 2>/dev/null || fail "Python 依赖不全。先：python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"

PUBLISHER=$(cast wallet address --private-key "$PRIVATE_KEY")
AUDITOR=$(cast wallet address --private-key "$AUDITOR_PRIVATE_KEY")
[ "$PUBLISHER" != "$AUDITOR" ] || fail "PRIVATE_KEY 与 AUDITOR_PRIVATE_KEY 是同一地址，合约要求 publisher != auditor"
if [ -z "${OWNER_PRIVATE_KEY:-}" ]; then
  fail "缺 OWNER_PRIVATE_KEY（管理员，部署合约 & slashAuditor）。请在 .env 按角色补三个私钥（参照 .env.example）"
fi
OWNER=$(cast wallet address --private-key "$OWNER_PRIVATE_KEY")
[ "$OWNER" != "$PUBLISHER" ] || fail "OWNER_PRIVATE_KEY 与 PRIVATE_KEY 相同（SPEC 10 要求三钱包两两不同）"
[ "$OWNER" != "$AUDITOR" ] || fail "OWNER_PRIVATE_KEY 与 AUDITOR_PRIVATE_KEY 相同（SPEC 10 要求三钱包两两不同）"

# 解析 --no-pause
for arg in "$@"; do
  [ "$arg" = "--no-pause" ] && NO_PAUSE=1
done

log "0. 连接链并保证部署可用"
cast chain-id --rpc-url "$RPC_URL" >/dev/null 2>&1 \
  || fail "连不上 RPC_URL=$RPC_URL（本地演示请先另开终端运行 anvil）"
CHAIN_ID=$(cast chain-id --rpc-url "$RPC_URL")
DEPLOYED_CHAIN=$(command "$PY" -c 'import json;print(json.load(open("deployments.json")).get("chainId"))')
REGISTRY=$(command "$PY" -c 'import json;print(json.load(open("deployments.json"))["SkillRegistry"])')
LICENSE=$(command "$PY" -c 'import json;print(json.load(open("deployments.json"))["SkillLicense"])')
ONCHAIN_CODE=$(cast code "$REGISTRY" --rpc-url "$RPC_URL")

case "$RPC_URL" in
  http://127.0.0.1:*|http://localhost:*) IS_LOCAL=yes ;;
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
MIN_DEPOSIT=$(cast call "$REGISTRY" "MIN_DEPOSIT()(uint256)" --rpc-url "$RPC_URL")   # wei
MIN_DEPOSIT=${MIN_DEPOSIT%% *}   # cast 对整数也会带人类可读后缀，只留原值
MIN_DEPOSIT_ETH=$(cast --from-wei "$MIN_DEPOSIT")

echo "chainId      : $CHAIN_ID"
echo "SkillRegistry: $REGISTRY"
echo "SkillLicense : $LICENSE"
echo "publisher    : $PUBLISHER"
echo "auditor      : $AUDITOR"
echo "owner        : $OWNER（链上读取 owner()=$(cast call "$REGISTRY" "owner()(address)" --rpc-url "$RPC_URL")）"

# ---- 复用子流程 ----
# 注册技能版本 + 请求审计（发布者；SPEC：押钱担保）
register_and_request() { # $1=技能目录
  local dir="$1" name version hashes status
  name=$(command "$PY" -c "import json;print(json.load(open('$dir/manifest.json'))['name'])")
  version=$(command "$PY" -c "import json;print(json.load(open('$dir/manifest.json'))['version'])")
  status=$(cast call "$REGISTRY" "getStatus(string,string)(uint8)" "$name" "$version" --rpc-url "$RPC_URL" 2>/dev/null || echo none)
  [ "$status" = "0" ] || { echo "已注册：$name@$version（链上 status=$status）"; return 3; }
  hashes=$(command "$PY" -c \
    "import sys;sys.path.insert(0,'.');from auditor.hashing import code_hash,metadata_hash;from pathlib import Path;d=Path('$dir');print('0x'+code_hash(d).hex(),'0x'+metadata_hash(d).hex())")
  read -r CODE_HASH META_HASH <<EOF
$hashes
EOF
  step "register $name@$version(publisher=$PUBLISHER)  repo=$dir"
  cast send "$REGISTRY" \
    "register(string,string,string,bytes32,bytes32)" "$name" "$version" "$dir" "$CODE_HASH" "$META_HASH" \
    --private-key "$PRIVATE_KEY" --rpc-url "$RPC_URL" 2>/dev/null | awk '/transactionHash/ {hash=$2} END {print "tx:", hash}'
  step "requestAudit $name@$version，押金 $MIN_DEPOSIT_ETH ETH"
  cast send "$REGISTRY" "requestAudit(string,string)" "$name" "$version" --value "$MIN_DEPOSIT" \
    --private-key "$PRIVATE_KEY" --rpc-url "$RPC_URL" 2>/dev/null | awk '/transactionHash/ {hash=$2} END {print "tx:", hash}'
  REG_NAME="$name"; REG_VERSION="$version"
}

# 安装方 Agent：最小 MCP 客户端调用 install_skill / check_skill 并打印返回 JSON
mcp_call() { # $1=tool $2=skill_dir
  command "$PY" - "$1" "$2" <<'PYEOF'
import asyncio, json, os, sys
sys.path.insert(0, ".")
from mcp import ClientSession, stdio_client, StdioServerParameters
tool, skill_dir = sys.argv[1], sys.argv[2]

def payload_of(result):
    sc = getattr(result, "structured_content", None)
    if isinstance(sc, dict):
        return sc
    for item in getattr(result, "content", None) or []:
        text = getattr(item, "text", None)
        if text:
            try:
                return json.loads(text)
            except Exception:
                return {"raw": text}
    return None

async def runtime():
    env = {"RPC_URL": os.environ.get("RPC_URL", ""),
           "PATH": os.environ.get("PATH", ""), "PYTHONUTF8": "1"}
    params = StdioServerParameters(command=sys.executable, args=["gate/mcp_server.py"], env=env)
    async with stdio_client(params, errlog=open(os.devnull, "wb")) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            r = await session.call_tool(tool, {"skill_dir": skill_dir})
            print(json.dumps(payload_of(r), ensure_ascii=False, sort_keys=True))
asyncio.run(runtime())
PYEOF
}

log "1. 质押(人)：python -m auditor.stake"
command "$PY" -m auditor.stake || fail "质押失败：请检查 AUDITOR_PRIVATE_KEY 与 RPC 后重跑"
pause

log "2. 启动常驻审计 Agent（无人参与判定）"
mkdir -p logs
AGENT_START_BLOCK=$(cast block-number --rpc-url "$RPC_URL" | awk '{print $1}')
step "agent 监听起始区块：$AGENT_START_BLOCK，日志 logs/agent.log"
RPC_URL="$RPC_URL" command "$PY" -m auditor.agent --from-block "$AGENT_START_BLOCK" --poll 2 > logs/agent.log 2>&1 &
AGENT_PID=$!
cleanup() {
  if [ -n "${AGENT_PID:-}" ] && kill -0 "$AGENT_PID" 2>/dev/null; then
    kill "$AGENT_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT
sleep 2
kill -0 "$AGENT_PID" 2>/dev/null || { cat logs/agent.log >&2 || true; fail "审计 Agent 启动失败（常见原因： Auditor 未质押）"; }
pause

log "3. 发布者注册并请求审计 weather / mail-helper"
PUB_BEFORE=$(cast balance "$PUBLISHER" --rpc-url "$RPC_URL")
AUD_BEFORE=$(cast balance "$AUDITOR" --rpc-url "$RPC_URL")
rc_weather=0
register_and_request samples/weather || rc_weather=$?
rc_mail=0
register_and_request samples/mail-helper || rc_mail=$?
if [ "$rc_weather" != "0" ] && [ "$rc_mail" != "0" ]; then
  fail "两个样本都已注册过：请重启 anvil（Ctrl-C 后重跑 anvil）得到干净链，再运行 ./demo.sh"
fi
pause

log "4. 等 Agent 自动出结论上链（最多 60 秒；只轮询链上状态）"
VERIFY_TARGET=3   # Verified
MAL_TARGET=4      # Malicious
deadline=$(( $(date +%s) + 60 ))
WEATHER_STATUS=0; MAIL_STATUS=0
while [ "$(date +%s)" -lt "$deadline" ]; do
  WEATHER_STATUS=$(cast call "$REGISTRY" "getStatus(string,string)(uint8)" weather 1.0.0 --rpc-url "$RPC_URL" 2>/dev/null || echo 0)
  MAIL_STATUS=$(cast call "$REGISTRY" "getStatus(string,string)(uint8)" mail-helper 1.0.0 --rpc-url "$RPC_URL" 2>/dev/null || echo 0)
  if [ "$WEATHER_STATUS" = "$VERIFY_TARGET" ] && [ "$MAIL_STATUS" = "$MAL_TARGET" ]; then
    break
  fi
  sleep 2
done
# 与 manifest 实名一致（不写死样本名：登记流程的最后一次成功注册也在此打印）
read_manifest_kv() { command "$PY" -c "import json;m=json.load(open('$1/manifest.json'));print(m['name'], m['version'])"; }
read -r NAME_W VER_W < <(read_manifest_kv samples/weather)
read -r NAME_M VER_M < <(read_manifest_kv samples/mail-helper)
echo "getStatus($NAME_W@$VER_W)=$WEATHER_STATUS       isVerified=$(cast call "$LICENSE" "isVerified(string,string)(bool)" "$NAME_W" "$VER_W" --rpc-url "$RPC_URL")"
echo "getStatus($NAME_M@$VER_M)=$MAIL_STATUS"
if [ "$WEATHER_STATUS" != "$VERIFY_TARGET" ]; then
  echo "（提示：weather 尚未到 Verified。agent.log：)"
  tail -5 logs/agent.log || true
  fail "Agent 未在 60 秒内完成 weather 审计"
fi
if [ "$MAIL_STATUS" != "$MAL_TARGET" ]; then
  echo "（提示：mail-helper 尚未到 Malicious。agent.log：)"
  tail -5 logs/agent.log || true
  fail "Agent 未在 60 秒内完成 mail-helper 审计"
fi
PUB_AFTER=$(cast balance "$PUBLISHER" --rpc-url "$RPC_URL")
AUD_AFTER=$(cast balance "$AUDITOR" --rpc-url "$RPC_URL")
echo "publisher-balance: $PUB_BEFORE -> $PUB_AFTER wei"
echo "auditor-balance:   $AUD_BEFORE -> $AUD_AFTER wei"
pause

log "5. 安装方 Agent 调用 MCP 工具查链安装（返回 JSON，全部来自链上）"
step "install_skill(samples/weather)"
mcp_call install_skill samples/weather
step "install_skill(samples/mail-helper)"
mcp_call install_skill samples/mail-helper
step "check_skill(samples/weather)"
mcp_call check_skill samples/weather

log "6. 完成"
echo "agent.log: logs/agent.log；报告 reports/；看板 open web/index.html"

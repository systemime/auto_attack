# AutoAttack Agent

生产内测级黑盒 AI Agent 自动化渗透平台核心。默认单机运行；分布式模式使用 Redis queue + workspace blackboard。

## 定位

- **黑盒 DAST / 自动化渗透编排**：不读取目标源码，不做白盒 SAST。
- **受控 AI Agent**：LLM 只能提出 JSON skill 计划；实际执行必须经过 scope、policy、SkillRouter、approval。
- **单文件核心 + SQLite 黑板**：优先 stdlib，便于审计、打包、离线运行。
- **分布式兼容**：单机可用 SQLite queue；真正跨节点分布式使用 Redis queue，workspace 保存状态与证据。

## 核心能力

| 模块 | 状态 |
|---|---|
| Scope/policy/deny/CIDR/subdomain guard | 已实现 |
| Planner → skills/router → executor/worker → analyst → reporter | 已实现 |
| 本地 skills `list/test/enable/disable/normalize/validate` | 已实现 |
| JSON skill manifest 目录加载、元数据路由、冲突控制 | 已实现 |
| Intrusive 双 gate + approval queue | 已实现 |
| AI planner JSON gate，读取 blackboard observations/findings，不执行 LLM shell | 已实现 |
| SQLite blackboard：runs/tasks/observations/findings/events/artifacts | 已实现 |
| Queue：SQLite 单机队列；Redis 分布式队列；claim/lease/retry/worker | 已实现 |
| Resume：command digest cache，失败可重试 | 已实现 |
| Evidence：raw output、command digest、confidence、first/last seen | 已实现 |
| 报告：Markdown / findings JSON / observations JSON / SARIF / events JSONL | 已实现 |
| Web 控制台：状态/发现/任务/jobs/approval 少量干预 | 已实现 |
| Web 证据：auth header/cookie、katana URL crawl、HAR 导入 | 已实现基础能力 |
| Docker：非 root、固定 ProjectDiscovery release URL、SHA256 校验 | 已实现 |

## 快速开始：单机

```bash
python3 autoattack_agent.py init --output policy.json
python3 autoattack_agent.py run 127.0.0.1 \
  --policy policy.json \
  --workspace runs/local \
  --profile quick \
  --rounds 1 \
  --max-steps 0 \
  --timeout 1
python3 autoattack_agent.py status runs/local
python3 autoattack_agent.py report runs/local --format md,json,sarif,events
```

无 `--policy` 时只允许 smoke：`--profile quick --max-steps 0 --rounds 1`。

最小 policy 字段：

```json
{
  "scope": {"roots": ["127.0.0.1", "localhost"], "deny": []},
  "limits": {"max_rounds": 3, "max_steps": 200, "max_workers": 8, "timeout_seconds": 180},
  "tools": {"allow": ["subfinder", "httpx", "katana", "nuclei", "nmap"], "intrusive": ["sqlmap", "zap-baseline", "nikto"]},
  "approval": {"intrusive": false}
}
```

## 外部依赖

核心功能只依赖 Python 3.11+ 标准库。外部工具按 PATH 自动启用；没安装则对应 skill 不运行。

| 能力 | 工具 | 建议版本/说明 |
|---|---|---|
| 端口/服务指纹 | `nmap` | 7.93+ |
| 子域发现 | `subfinder` | ProjectDiscovery v2+ |
| HTTP 指纹 | `httpx` | ProjectDiscovery v1+，不是 Python `httpx` 包 |
| URL 爬取 | `katana` | ProjectDiscovery v1+ |
| 模板漏洞扫描 | `nuclei` | ProjectDiscovery v3+，建议同步 `nuclei-templates` |
| 攻击面枚举 | `amass` | v4+，可选 |
| Web 技术识别 | `whatweb` | 可选 |
| Web 基线扫描 | `nikto` | 可选，intrusive |
| SQL 注入验证 | `sqlmap` | 1.8+，intrusive |
| ZAP baseline | `zap-baseline.py` | OWASP ZAP Docker/脚本，可选，intrusive |
| 分布式队列 | `redis-server` | Redis 6/7；`redis://host:6379/0` |

Docker 镜像内置：Debian bookworm `nmap`、`sqlmap`、ProjectDiscovery `httpx/nuclei/subfinder/naabu/katana`。ProjectDiscovery zip 不进主仓库，构建时按 `docker-assets/manifest.tsv` 下载并校验 SHA256；本地可执行 `docker-assets/fetch.sh` 预取缓存。

裸机安装建议：先装 Python 3.11+、`nmap`、`redis-server`，ProjectDiscovery 工具按官方 release 或 `go install` 放入 PATH；嫌麻烦直接用本仓库 Dockerfile。

## 开发流程

本项目运行时零 Python 第三方依赖；修改代码后跑最小验证链：

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m py_compile autoattack_agent.py
python3 -m unittest -v
python3 autoattack_agent.py selftest
python3 tests/perf_smoke.py
```

涉及 CLI 示例时同步检查：

```bash
python3 autoattack_agent.py --help
python3 autoattack_agent.py run --help
python3 autoattack_agent.py worker --help
python3 autoattack_agent.py web --help
```

## 分布式模式：Redis queue

本实现从 dqlite/libSQL/Redis 三类候选中选择 Redis：部署最简单，worker 语言无关，当前代码用 stdlib RESP 客户端，不增加 Python 依赖。

协调端只规划并入队，worker 消费同一个 workspace；跨节点时使用 Redis：

```bash
docker run -d --name aa-redis -p 6379:6379 redis:7-alpine

python3 autoattack_agent.py run 127.0.0.1 \
  --policy policy.json \
  --workspace /shared/run1 \
  --distributed \
  --queue-backend redis \
  --redis-url redis://127.0.0.1:6379/0 \
  --max-steps 4

python3 autoattack_agent.py jobs /shared/run1 --limit 50 --recent
python3 autoattack_agent.py worker /shared/run1 \
  --worker-id node-a \
  --queue-backend redis \
  --redis-url redis://127.0.0.1:6379/0
python3 autoattack_agent.py status /shared/run1
```

Redis 只负责 job queue；状态、证据、报告仍写入 workspace。跨节点必须让所有节点访问同一 workspace（NFS/共享卷/对象挂载），并保持相同外部工具版本。`--execution-mode queue --queue-backend sqlite` 只适合单机多进程/测试；生产分布式使用 Redis。

## Web 控制台

仅用于整体态势展示和少量人工干预。默认只绑定 localhost：

```bash
python3 autoattack_agent.py web runs/local --host 127.0.0.1 --port 8765
```

控制台展示 status、skill stats/trend、findings、tasks、jobs、approval，并可 approve/deny pending approval。不要直接暴露公网；远程访问放到 SSH tunnel、VPN 或带认证的反向代理后面。

## Skills / approval / AI planner

大量 skills 处理机制的生产级评估见 [`analysis/SKILLS_SCALE_READINESS.md`](analysis/SKILLS_SCALE_READINESS.md)。

```bash
python3 autoattack_agent.py skills list
python3 autoattack_agent.py skills list --source manifest --query headers --limit 20 --summary
python3 autoattack_agent.py skills test python-recon
python3 autoattack_agent.py skills --skills-dir skills show web.headers --raw
python3 autoattack_agent.py skills disable nuclei
python3 autoattack_agent.py skills enable nuclei
python3 autoattack_agent.py skills --skills-dir skills validate skills
python3 autoattack_agent.py skills validate skills --strict
python3 autoattack_agent.py skills normalize skills/web_headers.json
python3 autoattack_agent.py skills normalize skills --write
python3 autoattack_agent.py skills --skills-dir skills explain https://example.com --profile deep --query "headers scan" --tools cap:http
python3 autoattack_agent.py skills --skills-dir skills eval skills-routing-eval.json
python3 autoattack_agent.py skills stats runs/local --limit 20
python3 autoattack_agent.py skills stats runs --recursive --limit 20
python3 autoattack_agent.py skills trace runs/local --target https://example.com --skill web.headers
```

外部 skill 用 JSON manifest 维护；可放到任意目录，运行时通过 `--skills-dir` 或 `AUTOATTACK_SKILLS_DIR` 加载：

```json
{
  "name": "web.headers",
  "schema_version": 1,
  "min_agent_version": "1.0.0",
  "version": "1",
  "description": "Check HTTP response headers",
  "phase": "fingerprint",
  "risk": "safe",
  "tool": "httpx",
  "tags": ["web", "headers"],
  "capabilities": ["http", "headers"],
  "priority": 80,
  "needs_url": true,
  "input_schema": {"type": "object", "required": ["target"]},
  "output_schema": {"type": "object"},
  "depends_on": {"python-recon": ">=1"},
  "conflicts": []
}
```

`skills normalize` 支持单文件/目录批量输出，兼容 `schema_version: 0` 与常见旧字段别名，`--write` 可原子回写规范 JSON；`skills validate --strict` 可作为 CI 门禁，要求文件已是规范化结果。Manifest 字段会被规范化和校验：`name/schema_version/min_agent_version/max_agent_version/version/description/phase/risk/tool/enabled/tags/capabilities/priority/needs_url/input_schema/output_schema/depends_on/dependency_versions/conflicts`；未填写 `tags/capabilities` 时会从 `phase/tool/name` 自动补齐基础路由元数据。`tool` 绑定已有外部工具时可执行；没有 `tool` 的 manifest 只进入 catalog，不会进入执行计划。Router 会按 profile、policy、目标类型、工具可用性、depends_on、priority、term inverted index/query weight 和 conflicts 选择候选；`--tools` 支持精确 skill/tool 名，也支持 `tag:*`、`cap:*`、`phase:*`、`risk:*`、`source:*` 元数据选择器，便于从大量 skills 中先收窄候选面。AI planner 只收到 Top-K 可执行候选摘要和 `contract_sha256`；需要详情时用 `skills show` 按名称二级加载完整规范 manifest/源 JSON 与 input/output schema。`skills list` 支持 phase/risk/source/state/tag/capability/query/limit/offset/sort 过滤分页；`skills explain` 输出 candidates、plans、skipped、score/score_detail、skipped_reason_counts 和 `skillset_sha256`，用于审计海量 skills 场景下为什么选中或跳过；`skills eval` 可用 JSON cases 固化路由期望，作为大量 skills 变更后的回归门禁；`skills stats` 从单个 workspace 或 runs 目录汇总 skill_runs、trend 和 routing events，用于查看高频 skill、状态分布、执行耗时和跳过原因；`skills trace` 输出目标/skill 的路由与执行时间线。

运行时加载：

```bash
python3 autoattack_agent.py run https://example.com \
  --policy policy.json \
  --workspace runs/skills \
  --skills-dir skills \
  --profile deep
```

侵入式工具需要 policy `approval.intrusive=true` 且 CLI `--approve-intrusive`；未预授权的 intrusive skill 会进入 approval queue：

```bash
python3 autoattack_agent.py approvals runs/local
python3 autoattack_agent.py approve runs/local REQUEST_ID
python3 autoattack_agent.py resume runs/local
```

AI planner：

```bash
OPENAI_API_KEY=... python3 autoattack_agent.py run example.com \
  --policy policy.json \
  --workspace runs/ai \
  --ai-planner
```

LLM prompt 会包含当前 blackboard 的 observations/findings 摘要。输出只接受 `{"tasks":[{"target":"...","skill":"...","reason":"...","risk":"..."}]}`，仍会经 scope/policy/router/approval。

## HTTP Header/Cookie 与 HAR 证据

内置轻量能力：

```bash
python3 autoattack_agent.py run https://app.example \
  --policy policy.json \
  --header "Authorization: Bearer TOKEN" \
  --cookie "sid=..."

python3 autoattack_agent.py import-har runs/local traffic.har
```

- `--header/--cookie` 供 Python 内置 HTTP probe 使用，适合带登录态的轻量探测。
- `katana` skill 可做 URL discovery/crawl。
- `import-har` 被动导入 HAR，保留请求/响应状态作为证据。

## 产物

```text
workspace/
  run.json
  policy.json
  state.sqlite3
  raw/
  report.md
  findings.json
  observations.json
  report.sarif.json
  events.jsonl
```

`state.sqlite3` 包含：`runs/tasks/observations/findings/command_cache/tool_runs/artifacts/events/skills/skill_runs/approval_requests/job_queue`；Web API、`jobs`、`approvals` 和黑板快照支持分页/最近 N 条读取，避免长期运行时全表拉取。

## Docker

`docker-assets/manifest.tsv` 固定 ProjectDiscovery release URL 与 SHA256；build 阶段下载并校验 checksum。本地 zip 缓存被 `.gitignore` 排除，不进入主仓库。

```bash
mkdir -p runs && chmod a+w runs   # 容器内非 root 用户写 /runs
docker build -t autoattack-agent .
docker run --rm -v "$PWD/runs:/runs" autoattack-agent init --output /runs/policy.json
docker run --rm -v "$PWD/runs:/runs" autoattack-agent run 127.0.0.1 \
  --policy /runs/policy.json --workspace /runs/local \
  --profile quick --rounds 1 --max-steps 0 --timeout 1
```

Redis 分布式 Docker 最短路径：

```bash
docker network create aa-net
docker run -d --name aa-redis --network aa-net redis:7-alpine
docker run --rm --network aa-net -v "$PWD/runs:/runs" autoattack-agent run 127.0.0.1 \
  --policy /runs/policy.json --workspace /runs/dist \
  --distributed --queue-backend redis --redis-url redis://aa-redis:6379/0 --max-steps 4
docker run --rm --network aa-net -v "$PWD/runs:/runs" autoattack-agent worker /runs/dist \
  --queue-backend redis --redis-url redis://aa-redis:6379/0 --worker-id docker-worker
```

## 验证

```bash
python3 -m py_compile autoattack_agent.py
python3 -m unittest -v
python3 autoattack_agent.py selftest
python3 tests/perf_smoke.py
docker build -t autoattack-agent .
docker run --rm autoattack-agent selftest
```

## 生产边界

已具备生产内测核心闭环：scope/policy、skills、approval、queue、blackboard、evidence、report、Web 干预、Docker 可复现构建。

本项目定位是黑盒自动化渗透编排核心，不替代 nuclei/sqlmap/amass/ZAP 等专业引擎。

## 与 `repos/` 参考项目的关系

本项目不是复刻大型平台，而是取 80/20：

- 借鉴 PentestGPT/watchtower：最小 planner loop。
- 借鉴 Pentest-Swarm-AI/LuaN1aoAgent/airecon：SQLite blackboard、task/finding 状态。
- 借鉴 Strix/Shannon：scope guard、结构化报告、沙箱/Docker 思路。
- 借鉴 nuclei/sqlmap/Nettacker：工具 registry、parser、验证器。
- 借鉴 osmedeus/caldera：operation/task 状态与 artifact/report。
- 借鉴 AutoCVE：skills 管理、多 Agent 审计链路、漏洞管理、CVE 报告工作流、产品化 UI/后端分层。

当前绝对优势是：单文件可审计、零强依赖、单机/Redis queue 双模式、Docker checksum、CLI 生产闭环。基本持平的是：PentestGPT/watchtower 的最小 agent loop、LuaN1aoAgent/airecon 的 SQLite 状态思路、轻量 skills/router/approval 闭环。仍明显落后的是：nuclei/sqlmap 的专业检测深度、amass/subfinder 的 provider 生态、Strix/Shannon 的强 sandbox、Pentest-Swarm-AI 的 Postgres 级 swarm blackboard、AutoCVE 的源码审计/漏洞管理/CVE 报告链路。

### 参考项目横向定位

| 对比对象 | 当前相对位置 |
|---|---|
| PentestGPT / watchtower | 最小 planner loop 基本持平；本项目 scope/policy/report/queue 更硬。 |
| LuaN1aoAgent / airecon | SQLite blackboard 和任务状态思路基本持平；DAG/反思/沙箱弱。 |
| Pentest-Swarm-AI | 轻量 queue 只算兼容；Postgres blackboard、cursor、swarm 调度明显落后。 |
| Strix / Shannon | 报告与 guardrail 有基础；强 sandbox、企业流程明显落后。 |
| nuclei / nuclei-templates | 只作为编排器调用；检测引擎、模板生态、matcher/extractor 明显落后。 |
| sqlmap | 只做轻量调用和解析；SQLi 验证/利用/恢复状态机明显落后。 |
| subfinder / amass | 只做工具接入；provider/rate limit/资产图谱明显落后。 |
| Nettacker / osmedeus / Caldera | CLI 编排有基础；Web/API/workflow/operation 状态机明显落后。 |
| AutoCVE | 黑盒 CLI/审计边界更轻更可控；源码审计、漏洞/CVE 管理、multi-agent 审计链路明显落后。 |

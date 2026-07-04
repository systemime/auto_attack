# 从 0 到 1：综合能力最强的自动化渗透 AI Agent 开发指南

目标：不是复刻任一项目，而是取 80/20：**最小可跑的 agent loop + 可恢复状态 + 工具生态 + 结构化报告 + 可扩展沙箱**。

## 1. 推荐总体架构

```text
Target/Scope
   ↓
Planner（选择下一轮目标/工具/预算）
   ↓
Tool Registry（subfinder/amass/nmap/httpx/nuclei/sqlmap/zap/...）
   ↓
Executor（timeout、并发、sandbox、raw output）
   ↓
Parser/Analyst（observation -> finding，误报控制）
   ↓
Blackboard SQLite（tasks / observations / findings / artifacts）
   ↓
Reporter（MD / JSON / SARIF，可选 LLM 总结）
   ↺
下一轮 Planner 读取黑板继续跑 in-scope 子目标
```

最小闭环只需要 4 个角色：

1. **Planner**：从 scope + 黑板生成任务，不直接执行命令。
2. **Worker/Executor**：只执行 registry 里的工具，记录 raw output。
3. **Analyst**：把工具输出转成 observation/finding，做 dedupe 和 severity。
4. **Reporter**：只从结构化 findings 生成报告。

## 2. 设计原则

- **先 scope guard，再工具调用**：所有 target 必须过 scope；子域只允许属于根域。
- **工具不进 prompt**：工具要有 schema、timeout、parser、intrusive 标记。
- **状态优先 SQLite**：单机 MVP 用 SQLite 足够；后续再换 Postgres。
- **发现与验证分离**：recon/fingerprint 默认安全；`sqlmap/nikto/zap` 这类用 `--allow-intrusive`。
- **结构化 findings 是唯一真相**：报告、AI 总结、SARIF 都从 findings 表生成。
- **循环要有预算**：rounds、max_steps、timeout、max_discovered_targets，避免 agent runaway。
- **raw output 永远落盘**：方便复核和误报处理。
- **LLM 可选增强**：无 key 时仍能跑；LLM 只做 planner/report/enrichment，不影响基础执行。

## 3. 功能需求表

| 模块 | 必须/应该/可选 | 功能 | 参考项目 | 本实现状态 |
|---|---|---|---|---|
| Scope | 必须 | 目标规范化、子域范围控制、out-of-scope 阻断 | Strix/Shannon | 已实现 |
| Planner loop | 必须 | 多轮计划，发现 in-scope 子目标后继续探测 | watchtower/Pentest-Swarm-AI | 已实现 `--rounds` |
| Task budget | 必须 | max steps、timeout、worker 数限制 | nuclei/LuaN1ao | 已实现 |
| State DB | 必须 | tasks/observations/findings 持久化 | LuaN1ao/airecon/osmedeus | 已实现 SQLite |
| Builtin recon | 必须 | DNS、端口、HTTP 指纹、安全头 | subfinder/amass/nuclei | 已实现 |
| Tool registry | 必须 | 外部工具可发现、可过滤、可解析 | Pentest-Swarm-AI/Strix | 已实现 |
| External tools | 必须 | subfinder/amass/nmap/httpx/nuclei/sqlmap/zap 等 | 各项目 | 已适配，按 PATH 自动启用 |
| Parser/Analyst | 必须 | nmap/nuclei/sqlmap/nikto/httpx 结果转 findings | nuclei/sqlmap | 已实现基础 parser |
| Report | 必须 | MD + JSON + raw evidence | Shannon/Strix/Caldera | 已实现 |
| Dedupe | 必须 | observation/finding digest 去重 | nuclei/sqlmap | 已实现 |
| Intrusive gate | 必须 | 高侵入工具显式开关 | Shannon/Strix | 已实现 `--allow-intrusive` |
| Resume | 应该 | 复用 SQLite/已完成 tasks 跳过重复 | nuclei/sqlmap | 已实现外部命令缓存 `--resume` |
| Sandbox | 应该 | Docker/Kali workspace、代理、文件隔离 | Shannon/Strix/airecon | 未内置；可外部用 Docker 跑 |
| SARIF | 应该 | CI/ASPM 消费 | Strix/Pentest-Swarm-AI | 已实现基础 SARIF |
| Web UI/TUI | 可选 | 任务进度、图谱、报告 | Strix/LuaN1ao/Caldera | 未实现 |
| Multi-agent swarm | 可选 | 黑板订阅式 agent 并发 | Pentest-Swarm-AI | 已实现 SQLite job queue + `worker`，兼容单机/共享盘小集群 |
| LLM planner | 可选 | 让模型从 observations 选择下一步 | watchtower/PentestGPT | 已实现受控 JSON `--ai-planner`，仍经 scope/policy/router |
| Template authoring | 可选 | 自定义 YAML checks | nuclei/Nettacker | 复用 nuclei，不重造 |

## 4. 推荐开发路线

### Phase 1：MVP（1-3 天）

- CLI：`run/tools/report/selftest`。
- SQLite：tasks、observations、findings。
- Builtin recon：DNS、常见端口、HTTP headers。
- Tool registry：先接 `nmap/httpx/nuclei/sqlmap`。
- Report：Markdown + JSON。

### Phase 2：可用版（1-2 周）

- 多轮 planner：发现子域/URL 后继续扫。
- 统一 parser：nuclei JSONL、nmap XML、sqlmap 文本、ZAP JSON。
- findings schema：title/severity/target/evidence/source/recommendation/cvss/cwe/cve。
- Dockerfile：内置常用工具，挂载 workspace。
- Resume：同一 command digest 已成功则跳过。

### Phase 3：强能力版（2-6 周）

- LLM planner：读取 blackboard 生成 task JSON，仍由 registry 执行。
- Critic/Reflector：判断 findings 是否需要二次验证。
- SARIF/JUnit/HTML 报告。
- Web UI：run state、tasks、raw output、findings。
- MCP tool registry：让工具可热插拔。

### Phase 4：平台版

- Postgres + queue + distributed workers。（当前先用 SQLite `job_queue` 保持单机/分布式兼容，后续可替换后端）
- Agent roles：recon/classifier/exploit/report。
- Event-driven blackboard：finding type 触发 agent。
- Knowledge base：CVE、ExploitDB、nuclei templates、历史项目 patterns。

## 5. 最小数据模型

```sql
tasks(id, ts, phase, target, tool, status, detail)
observations(id, ts, source, target, kind, digest, data_json)
findings(id, ts, title, severity, target, digest, evidence, source, recommendation)
artifacts(id, ts, type, path, target, source, digest)
```

MVP 可少 `artifacts`，但 raw output 文件必须保留。

## 6. 工具接入规范

每个工具只需要 6 个字段：

```python
ToolSpec(
  name="nuclei",
  phase="scan",
  intrusive=False,
  needs_url=False,
  binary="nuclei",
  build=lambda target, out: ["nuclei", "-jsonl", "-u", target],
  parse=parse_nuclei_jsonl,
)
```

规则：

- `build()` 只返回 argv list，不拼 shell 字符串。
- `parse()` 返回 observations/findings，不直接写报告。
- 所有工具有 timeout。
- 原始 stdout/stderr 保存到 raw 文件。
- 高风险工具标 `intrusive=True`。

## 7. 误报控制

从调研项目提炼：

- nuclei：多 matcher AND、DSL、extractor、global/per-host limiter。
- sqlmap：页面稳定性、动态参数、启发式、technique confirmation、hashDB。
- Nettacker：service discovery 先行，只对已发现服务跑对应模块。
- Caldera：link status / parser result / fact relationship。

落地规则：

1. 单证据只给 low/info；多工具交叉证据才升 medium/high。
2. exploit/validator 成功才标 high/critical。
3. `intrusive` 工具不默认运行。
4. finding 必须带 raw output path 或证据摘要。

## 8. 本仓库实现

`autoattack_agent.py` 是 Phase 1 + Phase 2 + 部分 Phase 3/4：

- 零依赖，Python 3.11 标准库。
- SQLite 黑板。
- 多轮 planner。
- 外部工具 registry。
- Skills/router、approval queue、event log、受控 AI planner。
- SQLite `job_queue` + `worker` CLI，支持单机本地执行和共享 workspace 分布式执行。
- 内置 DNS/port/HTTP 探测。
- MD/JSON/SARIF 报告。
- 可选 OpenAI-compatible LLM 总结。

运行：

```bash
python3 autoattack_agent.py run example.com --profile standard --rounds 2 --max-steps 16
python3 autoattack_agent.py run https://example.com/?id=1 --allow-intrusive --tools sqlmap,nuclei
```

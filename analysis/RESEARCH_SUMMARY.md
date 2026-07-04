# 自动化渗透开源项目调研总结

调研日期：2026-07-04（Asia/Shanghai）。搜索由 3 个子 agent live 检索，另 1 个子 agent 聚合；源码分析基于本地 clone 和 `gitnexus analyze` 索引。

## 1. 候选项目池

### AI / Agentic pentest

| 项目 | 类型 | 选择价值 |
|---|---|---|
| https://github.com/KeygraphHQ/shannon | 白盒 AI pentester | Temporal + Docker + Claude SDK，多阶段 vuln/exploit/report pipeline |
| https://github.com/usestrix/strix | AI 自动渗透 agent | 动态多 agent graph、sandbox、结构化报告/SARIF |
| https://github.com/GreyDGL/PentestGPT | LLM pentest agent | 最小 pipeline/controller/backend 抽象 |
| https://github.com/Armur-Ai/Pentest-Swarm-AI | swarm pentest | 黑板 + pheromone + cursor 的多 agent 调度 |
| https://github.com/GH05TCREW/pentestagent | TUI/crew pentest agent | 单 agent loop + crew worker pool |
| https://github.com/SanMuzZzZz/LuaN1aoAgent | P-E-R agent | Planner/Executor/Reflector + DAG + SQLite |
| https://github.com/pikpikcu/airecon | local-first agent | SQLite memory、Docker sandbox、AgentGraph |
| https://github.com/fzn0x/watchtower | LangGraph pentest | planner→worker→analyst→logic→planner 最小闭环 |
| https://github.com/msoedov/agentic_security | LLM/agent fuzzing | dataset/detector/provider registry，适合 AI 应用安全测试 |

### 传统自动化扫描/利用/编排

| 项目 | 类型 | 选择价值 |
|---|---|---|
| https://github.com/projectdiscovery/nuclei | 模板化漏洞扫描 | 执行引擎、模板、matcher/extractor、rate limit 成熟 |
| https://github.com/projectdiscovery/nuclei-templates | 模板库 | CVE/暴露面/技术识别知识库 |
| https://github.com/sqlmapproject/sqlmap | SQLi 自动验证/利用 | 检测→确认→利用→resume 的强状态机 |
| https://github.com/OWASP/Nettacker | 自动化渗透框架 | YAML module + protocol engine + 多进程/多线程 |
| https://github.com/j3ssie/osmedeus | workflow 编排 | YAML flow/module DAG、scheduler、artifact/report |
| https://github.com/owasp-amass/amass | 攻击面发现 | OAM graph、provider/plugin、backlog/pipeline |
| https://github.com/projectdiscovery/subfinder | 子域发现 | provider 并发、rate limit、去重输出 |
| https://github.com/apache/caldera | 对手仿真 | operation/planner/link/ability/fact/source 攻击链 |

## 2. 已 clone + GitNexus 索引证据

完整机器可读表：`analysis/indexed_repos.tsv`。全部项目均执行过 `gitnexus analyze`，日志在 `analysis/logs/`。

| 项目 | 分支 | commit | 状态 |
|---|---|---:|---|
| shannon | main | 5a2f78c | indexed |
| strix | main | 302efed | indexed |
| PentestGPT | main | b986930 | indexed |
| Pentest-Swarm-AI | main | ca19c93 | indexed |
| LuaN1aoAgent | main | 8bc8e52 | indexed |
| airecon | main | 9a21453 | indexed |
| pentestagent | main | 37be4dd | indexed |
| watchtower | main | e0cc241 | indexed |
| agentic_security | main | 42615e5 | indexed |
| nuclei | dev | e4a83ad | indexed |
| nuclei-templates | main | 4bb9d12 | indexed |
| sqlmap | master | 2b9fd6c | indexed |
| Nettacker | master | ef0c6b0 | indexed |
| osmedeus | main | d5aa39b | indexed |
| amass | main | 79299dc | indexed |
| subfinder | dev | d0ea102 | indexed |
| caldera | master | 3735d9e | indexed |

## 3. 关键设计横向总结

| 维度 | 最佳样板 | 结论 |
|---|---|---|
| 最小闭环 | PentestGPT / watchtower | `planner -> tool -> analyst -> next` 是 MVP 核心 |
| 多 agent 调度 | Pentest-Swarm-AI / Strix | 黑板触发适合大规模；动态 agent graph 适合复杂任务拆分 |
| 状态记忆 | LuaN1aoAgent / airecon / osmedeus | SQLite 足够做 run、task、observation、finding、artifact |
| 工具抽象 | Strix / Pentest-Swarm-AI / nuclei | 统一 registry + schema + timeout + parser，别把工具写死进 prompt |
| 沙箱 | Shannon / Strix / airecon | Docker workspace + 进程/网络隔离是可执行 agent 的底线 |
| 模板扫描 | nuclei + templates | YAML template + matcher/extractor + rate limiter 是扫描能力核心 |
| 强验证 | sqlmap | 稳定性检测、动态参数、technique confirmation、session cache 降误报 |
| 资产发现 | subfinder / amass | provider 并发 + rate limit + 去重 + graph/source confidence |
| 编排 | osmedeus / caldera | DAG flow 与 operation/link 状态机适合长任务恢复和报告 |
| 报告 | Strix / Shannon / Caldera | findings 必须结构化，最终可导出 MD/JSON/SARIF/event logs |

## 4. 项目级源码结论

### Shannon

- 入口：`repos/shannon/apps/cli/src/index.ts`、`apps/cli/src/commands/start.ts`。
- Workflow：`repos/shannon/apps/worker/src/temporal/workflows.ts`。
- Agent：`repos/shannon/apps/worker/src/session-manager.ts`。
- 执行：`repos/shannon/apps/worker/src/services/agent-execution.ts`、`src/ai/claude-executor.ts`。
- 报告：`repos/shannon/apps/worker/src/services/reporting.ts`。
- 可借鉴：`vuln agent -> exploitation queue -> exploit agent -> report`，每个阶段产出 deliverable + git checkpoint。

### Strix

- 入口：`repos/strix/strix/interface/main.py`、`strix/core/runner.py`。
- Loop：`repos/strix/strix/core/execution.py`。
- 多 agent：`repos/strix/strix/tools/agents_graph/tools.py`、`strix/core/agents.py`。
- Sandbox：`repos/strix/strix/runtime/session_manager.py`。
- 报告：`repos/strix/strix/report/state.py`、`tools/reporting/tool.py`、`tools/finish/tool.py`。
- 可借鉴：lifecycle tool 强约束、`create_vulnerability_report` 作为唯一 findings 写入口、agent graph 可恢复。

### PentestGPT

- 入口：`repos/PentestGPT/pentestgpt/interface/main.py`。
- Pipeline：`repos/PentestGPT/pentestgpt/core/pipeline.py`、`core/pipelines.py`。
- Controller：`repos/PentestGPT/pentestgpt/core/controller.py`。
- Backend：`repos/PentestGPT/pentestgpt/core/backend.py`。
- Session：`repos/PentestGPT/pentestgpt/core/session.py`。
- 可借鉴：最小 Backend/EventBus/Pipeline 抽象，适合从 0 到 1。

### Pentest-Swarm-AI

- Swarm：`repos/Pentest-Swarm-AI/internal/engine/swarm_runner.go`、`internal/swarm/scheduler.go`。
- Blackboard：`internal/swarm/blackboard/board.go`、`types.go`、`memory.go`、`postgres.go`。
- Tools：`internal/tools/coordinator.go`、`internal/tools/executor.go`。
- Report：`internal/swarm/agents/report.go`、`internal/agent/report/*`。
- 可借鉴：finding 类型驱动 agent 唤醒，cursor + pheromone 实现 shared blackboard。

### LuaN1aoAgent

- 主循环：`repos/LuaN1aoAgent/agent.py`。
- Graph：`core/graph_manager.py`。
- SQLite：`core/database/models.py`、`core/database/utils.py`。
- Tool/MCP：`core/tool_manager.py`、`core/executor.py`。
- 可借鉴：Planner-Executor-Reflector + task DAG + causal graph + shared findings。

### airecon

- Loop：`repos/airecon/airecon/proxy/agent/loop_tool_cycle.py`。
- DAG：`repos/airecon/airecon/proxy/agent/agent_graph.py`。
- Memory：`repos/airecon/airecon/proxy/memory.py`。
- Docker tool：`repos/airecon/airecon/proxy/docker.py`。
- Report：`repos/airecon/airecon/proxy/reporting.py`。
- 可借鉴：SQLite memory 表完整、Docker execute 统一 shell、AntiLoop/Recovery 状态。

### nuclei / nuclei-templates

- Engine：`repos/nuclei/pkg/core/engine.go`、`executors.go`、`workpool.go`。
- Template：`repos/nuclei/pkg/templates/templates.go`、`compile.go`、`workflows.go`。
- HTTP protocol：`repos/nuclei/pkg/protocols/http/request.go`。
- Output：`repos/nuclei/pkg/output/*`。
- Templates：`repos/nuclei-templates/http/*`、`workflows/*`、`profiles/*`。
- 可借鉴：模板知识库、matchers/extractors、global/per-host rate limit、resume/host error cache。

### sqlmap

- 入口：`repos/sqlmap/sqlmap.py`。
- 主控：`repos/sqlmap/lib/controller/controller.py`。
- 检测：`repos/sqlmap/lib/controller/checks.py`。
- 请求/比较：`repos/sqlmap/lib/request/connect.py`、`comparison.py`。
- 插件：`repos/sqlmap/plugins/dbms/*`、`plugins/generic/*`。
- 可借鉴：stability/dynamic/heuristic/confirmed exploitation 多阶段验证，hashDB resume。

### Nettacker / osmedeus / amass / subfinder / caldera

- Nettacker：`nettacker/core/app.py`、`core/module.py`、`core/template.py`，YAML module + protocol library。
- osmedeus：`internal/core/workflow.go`、`internal/executor/executor.go`、`internal/scheduler/scheduler.go`，workflow DAG + scheduler + artifacts。
- amass：`engine/dispatcher/dispatcher.go`、`engine/registry/pipelines.go`、`engine/plugins/load.go`，provider pipeline + backlog。
- subfinder：`pkg/passive/passive.go`、`pkg/runner/enumerate.go`、`pkg/passive/sources.go`，provider 并发 + 去重。
- caldera：`app/objects/c_operation.py`、`app/service/planning_svc.py`、`app/objects/secondclass/c_link.py`，operation/planner/link 状态机。

## 5. 对本次 Python 工具的映射

`autoattack_agent.py` 采用了最小但覆盖核心 80/20 的设计：

- PentestGPT/watchtower：planner round → worker tools → analyst synth → report。
- Pentest-Swarm-AI：SQLite 黑板（observations/findings/tasks）+ finding 驱动下一轮。
- nuclei/sqlmap/Nettacker：外部工具 registry + parsers + findings。
- subfinder/amass：发现子域后下一轮 in-scope 探测。
- Strix/Shannon：结构化报告、scope guard、可选 LLM summary。

# Skills 大规模处理机制生产级评估

评估日期：2026-07-05。评估对象：`autoattack_agent.py` 当前 `SkillRegistry` / `SkillRouter` / AI planner / SQLite blackboard。

## 结论

**已具备大量 skills 的生产级基础设施雏形。** 当前机制不再依赖纯硬编码 skill 列表，已经支持 JSON manifest 规范化、目录加载、元数据索引、Top-K 候选召回、工具绑定、冲突控制、policy/profile/target 过滤、审批、queue/worker 和审计记录。

仍不能称为完整大型插件生态：缺少 embedding/vector retrieval 和更完整的图形化 trace/trend UI；未来新增 schema v2 时还需要补对应迁移。

## 当前已具备

| 维度 | 当前状态 |
|---|---|
| Registry | `python-recon` + `ToolRegistry.tools` + JSON manifest skills，by-name 缓存和 duplicate 检测。 |
| Manifest | `skills normalize/validate`，支持单文件/目录批量规范化、legacy alias/schema v0 迁移、input/output schema contract、原子回写与 strict CI 门禁；字段规范化：name/schema_version/min_agent_version/max_agent_version/version/description/phase/risk/tool/enabled/tags/capabilities/priority/needs_url/input_schema/output_schema/depends_on/dependency_versions/conflicts；缺省 tags/capabilities 自动从 phase/tool/name 补齐。 |
| Enable/disable | `skills list/test/enable/disable`，`list` 支持过滤/分页/summary，禁用状态原子写入 JSON。 |
| Metadata routing | phase/risk/tags/capabilities/priority/needs_url/input_schema/output_schema/depends_on/dependency_versions/conflicts/source 持久化到 SQLite。 |
| Executable binding | manifest `tool` 绑定已有 `ToolSpec` 后可执行；无 tool 的 manifest 只进入 catalog，不进执行计划。 |
| Router | 按 enabled、selected metadata、availability、policy、profile、target type、depends_on/dependency_versions、priority、query term inverted index/weight、conflicts 过滤和排序。 |
| Policy/approval | `tools.allow`、`tools.intrusive`、`approval.intrusive`、`--approve-intrusive` 双 gate。 |
| AI planner | JSON gate，读取 blackboard，输出仍经 scope/policy/router/approval；只暴露 Top-K 可执行候选摘要和 contract digest。 |
| Routing explainability | `skills list --summary`、`skills explain`、`skills eval`、`skills stats`、`skills trace` 覆盖候选、计划、跳过原因、回归门禁、执行耗时、trend、跨 workspace 聚合统计和单目标/skill 时间线；真实 run 写入 `skill_routing_summary` 事件。 |
| Persistence | SQLite `skills/skill_runs/approval_requests/events/tasks/tool_runs/job_queue`，已补关键索引和热点分页读取。 |
| Queue/concurrency | local thread pool、SQLite queue、Redis queue、worker lease/retry；queue 记录 skill 名称。 |
| Tests | 覆盖 1000 fake skills、缓存、索引、duplicate、policy intrusive risk、AI Top-K、manifest normalize/validate/load、tool binding、depends_on、conflicts。 |

## 大量 skills 当前处理方式

1. **注册**：内置 recon、外部工具、`--skills-dir`/`AUTOATTACK_SKILLS_DIR` JSON manifest 合并成统一 `SkillSpec`。
2. **规范化**：manifest 支持单文件/目录批量 normalize、legacy alias/schema v0 迁移、`--write` 原子回写和 `validate --strict` CI 门禁，统一校验 name、schema_version、agent version range、phase、risk、priority、tags、capabilities、input_schema/output_schema、depends_on/dependency_versions、conflicts、needs_url 等字段；缺省 tags/capabilities 自动补可路由元数据。
3. **索引**：启动时构建 `_by_name/_by_tag/_by_capability/_by_phase/_by_term` 和 query term weight，并生成 `skillset_digest`；CLI list 支持过滤、排序和分页。
4. **召回**：`SkillRegistry.candidates()` 根据 profile、policy、selected、target type、工具可用性过滤；`selected` 支持 skill/tool 精确名和 `tag:*`、`cap:*`、`phase:*`、`risk:*`、`source:*` 选择器。
5. **排序**：按 term 倒排召回 + priority/query term 权重分排序，AI planner 默认最多拿 30 个可执行候选。
6. **路由**：`SkillRouter` 只计划可执行 skill，处理 depends_on/dependency_versions、intrusive approval 和 conflicts。
7. **解释/评估**：`skills list --summary` 展示分页与分布，`skills explain` 展示候选、计划、跳过原因、冲突和分数，`skills eval` 做路由回归，`skills stats` 聚合单 workspace 或 runs 目录下的 skill_runs/routing events，`skills trace` 输出目标/skill 时间线。
8. **执行与审计**：执行结果写入 tasks、skill_runs、tool_runs、events、findings、artifacts；queue 模式保留 skill 名称。

## 对照主流生产机制

| 主流机制 | 当前状态 | 评价 |
|---|---|---|
| Registry + metadata | name/schema_version/agent version range/version/phase/risk/description/tool/source/tags/capabilities/priority/needs_url/input_schema/output_schema/depends_on/dependency_versions/conflicts | 基础达标 |
| Progressive disclosure | AI planner 只给 Top-K 可执行候选 metadata；`skills show` 可按需加载完整规范 manifest/源 JSON | 基础达标 |
| Capability schema | `ToolSpec`/manifest 有 capabilities 与 input_schema/output_schema，AI 候选只暴露 contract digest | 基础达标；未扩展到 OpenAPI/MCP schema |
| Dynamic filtering/routing | policy/profile/target/query term inverted index/metadata selectors/depends_on/dependency_versions/priority/conflicts | 基础达标；无 embedding/retrieval |
| Namespace/tag/grouping | tags/capabilities/source 已有 | 基础达标；无 namespace 级隔离 |
| Policy/permissions/approval | scope/policy/intrusive approval | 基础达标 |
| Observability/tracing/eval | events/tool_runs/skill_runs/report + `skills explain` + `skills eval` + `skills stats` + `skills trace` + `skill_routing_summary` events | 基础达标；无图形化 trace UI |
| Version/dependency management | manifest schema_version、schema v0 迁移、agent version range、depends_on 版本约束、Docker 工具版本固定 | 基础达标 |
| Queue/concurrency/durable execution | Redis/SQLite queue、lease、worker | 基础达标 |

## 仍然存在的差距

- 已有 `depends_on` 存在性/可用性/版本约束、agent 版本范围校验和 schema v0/legacy alias 迁移；未来新增 schema v2 时还需要继续补对应迁移。
- 无 embedding/vector retrieval；当前是轻量规则召回与排序。
- router 已记录 skipped reason 分布，并提供 `skills eval` 离线路由回归、`skills stats` 跨 workspace 聚合与 `skills trace` 时间线；长期趋势图表仍未内置，当前提供 JSON trend 聚合。
- `skills list`、Web API、jobs/approvals CLI 与黑板快照已支持分页/最近 N 条读取；更复杂报表仍可按需继续分页化。
- enable/disable JSON 已原子写入；仍无跨进程锁，极端并发管理时最后写入者获胜。
- SQLite 单条 commit 模式适合内测和中小规模，高吞吐场景需要批量写入/更强队列与存储调优。

## 生产使用建议

- 几十到几百 skills：当前机制可用，建议强制使用 policy allowlist/profile/`--tools tag:*|cap:*|phase:*` 缩小候选面。
- 上千 skills：当前已能保持 Top-K、缓存、依赖约束和路由回归评估；需要语义召回时再补 embedding retrieval。
- manifest-only skill 可用于 catalog 和治理；真正执行必须绑定已有 `ToolSpec.tool`。

## 参考来源

- Claude Agent Skills: https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview
- Agent Skills spec: https://agentskills.io/specification
- MCP Tools: https://modelcontextprotocol.io/specification/2025-06-18/server/tools
- Anthropic engineering: https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills
- LangChain dynamic tools: https://docs.langchain.com/oss/python/langchain/tools
- OpenAI orchestration: https://developers.openai.com/api/docs/guides/agents/orchestration
- LlamaIndex tool retrieval: https://developers.llamaindex.ai/python/examples/agent/openai_agent_retrieval/
- Microsoft tool-space interference: https://www.microsoft.com/en-us/research/blog/tool-space-interference-in-the-mcp-era-designing-for-agent-compatibility-at-scale/
- OpenAI tracing: https://openai.github.io/openai-agents-python/tracing/
- n8n queue mode: https://docs.n8n.io/deploy/host-n8n/configure-n8n/scaling/enable-queue-mode

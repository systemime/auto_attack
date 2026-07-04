# Skills 大规模处理机制生产级评估

评估日期：2026-07-05。评估对象：`autoattack_agent.py` 当前 `SkillRegistry` / `SkillRouter` / AI planner / SQLite blackboard。

## 结论

**已具备大量 skills 的生产级基础设施。** 当前机制不再依赖纯硬编码 skill 列表，已经支持 JSON manifest 规范化、目录加载、元数据索引、Top-K 候选召回、工具绑定、冲突控制、policy/profile/target 过滤、审批、queue/worker 和审计记录。

当前实现以单机/共享 workspace 的黑盒自动化渗透平台为边界；embedding/vector retrieval、OpenAPI/MCP 扩展 schema 和图形化 trace UI 属于后续增强，不阻塞当前生产级 skills 加载与路由目标。

## 当前已具备

| 维度 | 当前状态 |
|---|---|
| Registry | `python-recon` + `ToolRegistry.tools` + JSON manifest skills，by-name 缓存和 duplicate 检测。 |
| Manifest | `skills schema/normalize/validate`，支持 JSON Schema 输出、单文件/目录批量规范化、legacy alias/schema v0 迁移、input/output schema contract、原子回写与 strict CI 门禁；字段规范化：name/schema_version/min_agent_version/max_agent_version/version/description/phase/risk/tool/enabled/tags/capabilities/priority/needs_url/input_schema/output_schema/depends_on/dependency_versions/conflicts；缺省 tags/capabilities 自动从 phase/tool/name 补齐。 |
| Enable/disable | `skills doctor/list/test/enable/disable`，`doctor` 汇总 registry 健康度，`list` 支持过滤/分页/summary，禁用状态原子写入 JSON。 |
| Metadata routing | phase/risk/tags/capabilities/priority/needs_url/input_schema/output_schema/depends_on/dependency_versions/conflicts/source 持久化到 SQLite。 |
| Executable binding | manifest `tool` 绑定已有 `ToolSpec` 后可执行；无 tool 的 manifest 只进入 catalog，不进执行计划。 |
| Router | 按 enabled、selected metadata、availability、policy、profile、target type、depends_on/dependency_versions、priority、query term inverted index/weight、conflicts 校验/过滤和排序。 |
| Policy/approval | `tools.allow`、`tools.intrusive`、`approval.intrusive`、`--approve-intrusive` 双 gate。 |
| AI planner | JSON gate，读取 blackboard，输出仍经 scope/policy/router/approval；只暴露 Top-K 可执行候选摘要和 contract digest。 |
| Routing explainability | `skills list --summary`、`skills explain`、`skills eval`、`skills stats`、`skills trace` 覆盖候选、计划、跳过原因、回归门禁、执行耗时、trend、跨 workspace 聚合统计和单目标/skill 时间线；真实 run 写入 `skill_routing_summary` 事件。 |
| Persistence | SQLite `skills/skill_runs/approval_requests/events/tasks/tool_runs/job_queue`，已补关键索引和热点分页读取。 |
| Queue/concurrency | local thread pool、SQLite queue、Redis queue、worker lease/retry；queue 记录 skill 名称。 |
| Tests | 覆盖 1000 fake skills、缓存、索引、duplicate、policy intrusive risk、AI Top-K、manifest normalize/validate/load、tool binding、depends_on、conflicts 引用校验。 |

## 大量 skills 当前处理方式

1. **注册**：内置 recon、外部工具、`--skills-dir`/`AUTOATTACK_SKILLS_DIR` JSON manifest 合并成统一 `SkillSpec`。
2. **规范化**：manifest 支持 JSON Schema 输出、单文件/目录批量 normalize、legacy alias/schema v0 迁移、`--write` 原子回写和 `validate --strict` CI 门禁，统一校验 name、schema_version、agent version range、phase、risk、priority、tags、capabilities、input_schema/output_schema、depends_on/dependency_versions、conflicts、needs_url 等字段；缺省 tags/capabilities 自动补可路由元数据。
3. **索引**：启动时构建 `_by_name/_by_tag/_by_capability/_by_phase/_by_term` 和 query term weight，并生成 `skillset_digest`；CLI list 支持过滤、排序和分页。
4. **召回**：`SkillRegistry.candidates()` 根据 profile、policy、selected、target type、工具可用性过滤；`selected` 支持 skill/tool 精确名和 `tag:*`、`cap:*`、`phase:*`、`risk:*`、`source:*` 选择器。
5. **排序**：按 term 倒排召回 + priority/query term 权重分排序，AI planner 默认最多拿 30 个可执行候选。
6. **路由**：`SkillRouter` 只计划可执行 skill，处理 depends_on/dependency_versions、intrusive approval 和 conflicts。
7. **解释/评估**：`skills doctor` 做健康检查，`skills search` 做倒排召回，`skills list --summary` 展示分页与分布，`skills explain` 展示候选、计划、跳过原因、冲突、分数和命中 term 权重，`skills eval` 做路由回归，`skills stats` 聚合单 workspace 或 runs 目录下的 skill_runs/routing events，`skills trace` 输出目标/skill 时间线。
8. **执行与审计**：执行结果写入 tasks、skill_runs、tool_runs、events、findings、artifacts；queue 模式保留 skill 名称。

## 对照主流生产机制

| 主流机制 | 当前状态 | 评价 |
|---|---|---|
| Registry + metadata | name/schema_version/agent version range/version/phase/risk/description/tool/source/tags/capabilities/priority/needs_url/input_schema/output_schema/depends_on/dependency_versions/conflicts | 基础达标 |
| Progressive disclosure | AI planner 只给 Top-K 可执行候选 metadata；`skills show` 可按需加载完整规范 manifest/源 JSON | 基础达标 |
| Capability schema | `ToolSpec`/manifest 有 capabilities 与 input_schema/output_schema，AI 候选只暴露 contract digest | 基础达标 |
| Dynamic filtering/routing | policy/profile/target/query term inverted index/metadata selectors/depends_on/dependency_versions/priority/conflicts | 基础达标 |
| Namespace/tag/grouping | tags/capabilities/source 已有 | 基础达标 |
| Policy/permissions/approval | scope/policy/intrusive approval | 基础达标 |
| Observability/tracing/eval | events/tool_runs/skill_runs/report + Web skill stats + `skills explain` + `skills eval` + `skills stats` + `skills trace` + `skill_routing_summary` events | 基础达标 |
| Version/dependency management | manifest schema_version、schema v0 迁移、agent version range、depends_on 版本约束、Docker 工具版本固定 | 基础达标 |
| Queue/concurrency/durable execution | Redis/SQLite queue、lease、worker | 基础达标 |

## 非阻塞增强项

- 未来新增 schema v2 时，需要继续补对应迁移。
- 需要语义召回时，可在当前 term inverted index 之后追加 embedding/vector retrieval。
- 当前已有 JSON trend、Web 摘要和 `skills trace` 时间线；如需更强可视化，可另做图形化 trace UI。
- SQLite 单条 commit 模式适合单机/中小规模；极高吞吐场景可再做批量写入或外部存储调优。

## 生产使用建议

- 几十到几百 skills：当前机制可用，建议强制使用 policy allowlist/profile/`--tools tag:*|cap:*|phase:*` 缩小候选面。
- 上千 skills：当前已能保持 Top-K、缓存、倒排召回、依赖约束和路由回归评估；需要语义召回时再补 embedding retrieval。
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

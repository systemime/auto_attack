# Skills 大规模处理机制生产级评估

评估日期：2026-07-05。评估对象：`autoattack_agent.py` 当前 `SkillRegistry` / `SkillRouter` / AI planner / SQLite blackboard。

## 结论

**已具备大量 skills 的生产级基础设施雏形。** 当前机制不再依赖纯硬编码 skill 列表，已经支持 JSON manifest 规范化、目录加载、元数据索引、Top-K 候选召回、工具绑定、冲突控制、policy/profile/target 过滤、审批、queue/worker 和审计记录。

仍不能称为完整大型插件生态：缺少二级详情按需加载、依赖版本约束、选择评估集、embedding/vector retrieval、schema 级 tool contract 和更完整的 trace UI。

## 当前已具备

| 维度 | 当前状态 |
|---|---|
| Registry | `python-recon` + `ToolRegistry.tools` + JSON manifest skills，by-name 缓存和 duplicate 检测。 |
| Manifest | `skills normalize/validate`，字段规范化：name/version/description/phase/risk/tool/enabled/tags/capabilities/priority/needs_url/conflicts。 |
| Enable/disable | `skills list/test/enable/disable`，禁用状态持久化到 JSON。 |
| Metadata routing | phase/risk/tags/capabilities/priority/needs_url/conflicts/source 持久化到 SQLite。 |
| Executable binding | manifest `tool` 绑定已有 `ToolSpec` 后可执行；无 tool 的 manifest 只进入 catalog，不进执行计划。 |
| Router | 按 enabled、selected、availability、policy、profile、target type、priority、query term、conflicts 过滤和排序。 |
| Policy/approval | `tools.allow`、`tools.intrusive`、`approval.intrusive`、`--approve-intrusive` 双 gate。 |
| AI planner | JSON gate，读取 blackboard，输出仍经 scope/policy/router/approval；只暴露 Top-K 可执行候选 metadata。 |
| Routing explainability | `skills explain` 输出 candidates/plans/skipped/score/skillset_sha256，支持海量 skills 选择审计。 |
| Persistence | SQLite `skills/skill_runs/approval_requests/events/tasks/tool_runs/job_queue`，已补关键索引。 |
| Queue/concurrency | local thread pool、SQLite queue、Redis queue、worker lease/retry；queue 记录 skill 名称。 |
| Tests | 覆盖 1000 fake skills、缓存、索引、duplicate、policy intrusive risk、AI Top-K、manifest normalize/validate/load、tool binding、conflicts。 |

## 大量 skills 当前处理方式

1. **注册**：内置 recon、外部工具、`--skills-dir`/`AUTOATTACK_SKILLS_DIR` JSON manifest 合并成统一 `SkillSpec`。
2. **规范化**：manifest 统一校验 name、phase、risk、priority、tags、capabilities、conflicts、needs_url 等字段。
3. **索引**：启动时构建 `_by_name/_by_tag/_by_capability/_by_phase`，并生成 `skillset_digest`。
4. **召回**：`SkillRegistry.candidates()` 根据 profile、policy、selected、target type、工具可用性过滤。
5. **排序**：按 priority + query term 命中分排序，AI planner 默认最多拿 30 个可执行候选。
6. **路由**：`SkillRouter` 只计划可执行 skill，处理 intrusive approval 和 conflicts。
7. **解释**：`skills explain` 展示候选、计划、跳过原因、冲突和分数，便于审计路由效果。
8. **执行与审计**：执行结果写入 tasks、skill_runs、tool_runs、events、findings、artifacts；queue 模式保留 skill 名称。

## 对照主流生产机制

| 主流机制 | 当前状态 | 评价 |
|---|---|---|
| Registry + metadata | name/version/phase/risk/description/tool/source/tags/capabilities/priority/needs_url/conflicts | 基础达标 |
| Progressive disclosure | AI planner 只给 Top-K 可执行候选 metadata | 部分达标；无二级详情加载 |
| Capability schema | `ToolSpec` 有 build/parse/needs_url，manifest 有 capabilities | 部分达标；无 JSON Schema/OpenAPI/MCP schema |
| Dynamic filtering/routing | policy/profile/target/query/priority/conflicts | 基础达标；无 embedding/retrieval |
| Namespace/tag/grouping | tags/capabilities/source 已有 | 基础达标；无 namespace 级隔离 |
| Policy/permissions/approval | scope/policy/intrusive approval | 基础达标 |
| Observability/tracing/eval | events/tool_runs/skill_runs/report + `skills explain` | 部分达标；无选择评估集/trace UI |
| Version/dependency management | manifest version、Docker 工具版本固定 | 部分达标；无 dependency/schema migration |
| Queue/concurrency/durable execution | Redis/SQLite queue、lease、worker | 基础达标 |

## 仍然存在的差距

- 无 skill 依赖声明、兼容性约束、schema migration。
- 无 embedding/vector retrieval；当前是轻量规则召回与排序。
- 无二级详情加载；候选只给 metadata。
- router 对 skipped reason、latency、选择分数的长期统计仍不完整。
- `Store.rows()` 仍偏全表读取；大规模长期运行需要分页 API。
- enable/disable JSON 没有跨进程文件锁。
- SQLite 单条 commit 模式适合内测和中小规模，高吞吐场景需要批量写入/更强队列与存储调优。

## 生产使用建议

- 几十到几百 skills：当前机制可用，建议强制使用 policy allowlist/profile/`--tools` 缩小候选面。
- 上千 skills：当前已能保持 Top-K 与缓存，但建议补 embedding retrieval、依赖约束、分页观测、选择评估集。
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

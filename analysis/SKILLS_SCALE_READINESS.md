# Skills 大规模处理机制生产级评估

评估日期：2026-07-05。评估对象：`autoattack_agent.py` 当前 `SkillRegistry` / `SkillRouter` / AI planner / SQLite blackboard。

## 结论

**部分达标。** 当前机制已能支撑小到中等规模、静态工具映射型 skills：有 registry、router、policy allowlist、intrusive approval、CLI enable/disable/test、skill_runs/events 持久化、queue/worker 和测试覆盖。

但它还不是完整的“生产级大量动态 skills 平台”。主流生产方案不会把全量工具直接塞给模型，而是采用：**元数据注册 → 按需筛选/检索 → schema 约束调用 → 权限/审批保护 → tracing/eval 闭环**。

## 当前已具备

| 维度 | 当前状态 |
|---|---|
| Registry | `python-recon` + `ToolRegistry.tools` 映射为 skill；已加 by-name 缓存和 duplicate 检测。 |
| Enable/disable | `skills list/test/enable/disable`，禁用状态持久化到 JSON。 |
| Router | 按 enabled、selected、availability、policy、profile、needs_url 过滤。 |
| Policy/approval | `tools.allow`、`tools.intrusive`、`approval.intrusive`、`--approve-intrusive` 双 gate。 |
| AI planner | JSON gate，读取 blackboard，输出仍经 scope/policy/router/approval。已改为最多 30 个候选 skill metadata。 |
| Persistence | SQLite `skills/skill_runs/approval_requests/events/tasks/tool_runs`。已补关键索引。 |
| Queue/concurrency | local thread pool、SQLite queue、Redis queue、worker lease/retry。 |
| Tests | 21 个 unittest，新增 1000 fake skills 性能/缓存、duplicate、policy intrusive risk、AI top-K 覆盖。 |

## 对照主流生产机制

| 主流机制 | 当前状态 | 评价 |
|---|---|---|
| Registry + metadata | 有基础 metadata：name/version/phase/risk/description/tool | 部分达标 |
| Progressive disclosure | AI planner 只给 top-K 候选 metadata | 部分达标；无二级详情加载 |
| Capability schema | `ToolSpec` 有 build/parse/needs_url，但无 JSON Schema/OpenAPI/MCP schema | 未达标 |
| Dynamic filtering/routing | 有 policy/profile/target 过滤 | 部分达标；无 embedding/retrieval |
| Namespace/tag/grouping | 无 namespace/tag/capability 分组 | 未达标 |
| Policy/permissions/approval | 有 scope/policy/intrusive approval | 部分达标 |
| Observability/tracing/eval | 有 events/tool_runs/skill_runs/report | 部分达标；无选择评估集/trace UI |
| Version/dependency management | 内置版本字段、Docker 工具版本固定 | 部分达标；无 skill dependency/schema migration |
| Queue/concurrency/durable execution | 有 Redis/SQLite queue、lease、worker | 部分达标 |

## 本轮已补强

1. `SkillRegistry` 构造时缓存 `self._skills` / `self._by_name`，`get()` 从 O(n) 改 O(1)。
2. 启动时检测 duplicate skill name，避免同名覆盖。
3. `ToolRegistry` 缓存 availability/version，避免每轮/每目标重复 subprocess 探测。
4. SQLite 增加索引：
   - `idx_approval_skill_target_id`
   - `idx_skill_runs_skill_status`
   - `idx_events_kind_id`
   - `idx_job_queue_claim`
5. policy 将 safe tool 标记为 intrusive 时，`SkillPlan.skill.risk/requires_approval` 与实际 approval 状态保持一致。
6. AI planner 不再塞全量 skill name list，改为候选集合：`name/phase/risk/needs_url/description`，默认最多 30 个。
7. 新增测试覆盖大量 skills、缓存、索引、duplicate、policy intrusive risk、AI top-K。

## 仍然存在的差距

- 无 skill manifest 目录、插件发现、动态加载、依赖声明、兼容性约束。
- 无 capability/tags/namespace/conflicts/dependencies/priority。
- 无 embedding/vector retrieval；当前 top-K 是规则过滤后的前 30 个。
- router 对 skipped reason、latency、选择分数的记录仍不完整。
- `Store.rows()` 仍偏全表读取；大规模长期运行需要分页 API。
- enable/disable JSON 没有跨进程文件锁。
- SQLite 单条 commit 模式适合内测和中小规模，不适合高吞吐 SaaS 化执行。

## 生产使用建议

- 当前可称为：**具备生产化雏形的静态 skills 编排机制**。
- 当前不建议称为：**完整生产级大量动态 skills 平台**。
- 如果 skills 从几十增长到几百，当前补强后可继续运行，但应强制使用 policy allowlist/profile/`--tools` 缩小候选面。
- 如果 skills 达到上千且来自动态插件生态，需要新增 manifest/schema、namespace/tag、依赖/冲突、检索式 routing、分页观测和 eval 数据集。

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

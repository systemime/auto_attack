# 高级红队技术经理生产就绪评估

评估日期：2026-07-04。评估对象：`autoattack_agent.py` 及配套文档/调研成果。

## 结论

**已达到单机生产级核心 / 分布式兼容内测版。**

它已经具备授权生产内测所需的核心闭环：scope guard、planner rounds、SQLite 状态、skills/router、approval queue、event log、外部工具 registry、raw evidence、JSON/Markdown/SARIF/events 报告、resume、Dockerfile checksum、以及 SQLite job queue + worker 的单机/共享盘分布式兼容。仍不包含 Web UI、多租户 SaaS、登录态浏览器自动化和 Postgres/Redis 大规模队列。

## 评分

| 维度 | 分数 | 说明 |
|---|---:|---|
| 调研完整度 | 9/10 | 17 个项目 clone/index，覆盖 AI agent、workflow、扫描、资产发现、对手仿真 |
| 架构方向 | 8/10 | planner→skills/router→executor/worker→analyst→report + SQLite blackboard/queue |
| 工程可运行性 | 8/10 | 单文件零依赖可跑，单机默认，queue/worker 兼容分布式 |
| 安全/范围控制 | 8/10 | scope guard、policy、intrusive 双 gate、approval queue |
| 可靠性 | 7/10 | resume/cache/lease queue/测试覆盖；大规模长跑仍需实测 |
| 可观测/审计 | 8/10 | run manifest、events、tool_runs、skill_runs、approval、raw evidence |
| 生产部署 | 7/10 | Docker 非 root、固定 release zip、checksum 校验 |
| 测试 | 7/10 | unittest、selftest、perf smoke、Docker smoke、queue worker fixture |

总体：**8/10，单机生产级核心；分布式兼容但不是大规模 SaaS 平台。**

## 本轮发现并修复的阻断问题

| 问题 | 风险 | 修复 |
|---|---|---|
| 外部工具并发执行时 SQLite 跨线程崩溃 | 一启用外部工具就可能失败，生产阻断 | `sqlite3.connect(check_same_thread=False)` + `threading.Lock` 包住读写 |
| `tools` 命令误把 Python `httpx` CLI 当 ProjectDiscovery `httpx` | 工具可用性显示错误，运行时假阳性 | 统一 `tool_available()` 检测，排除缺依赖的 Python `httpx` |
| 命令缓存表不能被通用 rows 查询 | resume/审计路径潜在崩溃 | `command_cache` 按 `ts` 排序 |
| 并发修复没有回归测试 | 未来易回归 | `selftest` 增加 threaded SQLite/tool execution regression |

## 当前可接受使用场景

- 授权内网/靶场的轻量自动化 recon。
- 作为外部工具编排和报告胶水层。
- 红队工具研发 PoC / internal beta。
- 把 nuclei/sqlmap/nmap 等工具输出统一成 findings。

## 当前不应承诺的场景

- 不应作为无人值守互联网大范围扫描平台。
- 不应直接替代 Shannon/Strix/Caldera 级平台。
- 不应作为多租户商业 SaaS 后端。
- 不应宣称自动利用能力完整；当前更偏扫描/验证/报告编排。

## 升级到生产级的最短路径

1. **工具链镜像**：Dockerfile 改成完整安全工具镜像，固定版本：nmap、ProjectDiscovery httpx/nuclei/subfinder/naabu、sqlmap、zap-baseline。
2. **策略文件**：新增 `policy.yml`：scope、denylist、rate、intrusive approval、tool allowlist。
3. **Run manifest**：已实现 `run.json`：命令、目标、policy hash、tool versions、start/end、exit status。
4. **Resume 完整化**：已实现 command digest 成功跳过、失败可重试、raw evidence 引用稳定。
5. **CI fixtures**：已实现本地 fake tool 覆盖 report、resume、scope、SARIF、queue worker。
6. **沙箱**：已提供非 root Docker；强隔离仍由容器运行时/外部平台提供。
7. **审计**：已记录外部命令、参数、stdout/stderr 摘要、时间戳、events、approval。

## 本轮验证命令

```bash
python3 -m py_compile autoattack_agent.py
python3 -m unittest -v
python3 autoattack_agent.py selftest
python3 autoattack_agent.py tools
python3 autoattack_agent.py run 127.0.0.1 --policy /tmp/policy.json --workspace runs/audit-local --profile quick --max-steps 0 --timeout 1 --rounds 1
python3 tests/perf_smoke.py
docker build -t autoattack-agent .
docker run --rm autoattack-agent selftest
```

验证结果：通过；产物包含 `report.md`、`findings.json`、`observations.json`、`report.sarif.json`、`events.jsonl`、`state.sqlite3`。

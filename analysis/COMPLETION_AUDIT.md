# Completion audit

## Implemented

- CLI: `init`, `run --policy`, `--approve-intrusive`, `--distributed/--queue-backend redis`, `worker`, `jobs`, `web`, `import-har`, `tools --policy`, `skills`, `status`, `resume --retry-failed`, `report --format`, `approvals/approve/deny`.
- Policy JSON: roots/deny scope, CIDR/domain/subdomain matching, limit clamping, tool allowlist, intrusive double approval.
- Run workspace: `run.json`, `policy.json`, `state.sqlite3`, `raw/`, `report.md`, `findings.json`, `observations.json`, `report.sarif.json`.
- SQLite: `runs`, `tasks`, `observations`, `findings`, `command_cache`, `tool_runs`, `artifacts`, `events`, `skills`, `skill_runs`, `approval_requests`, `job_queue`.
- Evidence trace: confidence, evidence_path, command_digest, first_seen, last_seen.
- Resume: reuses command cache; failed cached commands can be retried with `--retry-failed`.
- Distributed compatibility: coordinator mirrors jobs to SQLite `job_queue`; true distributed mode uses Redis queue, while SQLite queue remains for local/test. `worker` claims jobs with leases, executes registry-only tools, records evidence, updates reports/manifests.
- Skills/AI: local skill registry with enable/disable/test, router, approval queue, controlled JSON `--ai-planner` using current blackboard observations/findings.
- Web/HAR: stdlib Web console for status/jobs/findings/approvals; `--header/--cookie`, katana crawl, and `import-har` provide lightweight web-session evidence.
- Tests: unittest coverage and 1000-target perf smoke.
- Dockerfile: Python 3.11, non-root user, nmap/curl/git/ca-certificates, sqlmap, ProjectDiscovery httpx/nuclei/subfinder/naabu/katana from pinned release assets in `docker-assets/`.

## Verified commands

```bash
python3 -m py_compile autoattack_agent.py
python3 -m unittest -v
python3 autoattack_agent.py selftest
python3 autoattack_agent.py init --output /tmp/policy.json
python3 autoattack_agent.py run 127.0.0.1 --policy /tmp/policy.json --workspace runs/prod-smoke --profile quick --max-steps 0 --timeout 1 --rounds 1
python3 autoattack_agent.py status runs/prod-smoke
python3 autoattack_agent.py report runs/prod-smoke --format md,json,sarif
python3 autoattack_agent.py run 127.0.0.1 --policy /tmp/policy.json --workspace runs/queue-smoke --profile quick --max-steps 0 --timeout 1 --rounds 1 --execution-mode queue
python3 autoattack_agent.py worker runs/queue-smoke --once --max-jobs 1
python3 tests/perf_smoke.py
docker build -t autoattack-agent .
docker run --rm autoattack-agent selftest
docker run --rm autoattack-agent tools
```

All passed. Required `runs/prod-smoke/*` artifacts exist.

## Docker note

Direct Go compilation of ProjectDiscovery tools was too slow/flaky in this environment. The final Dockerfile uses pinned upstream release zips stored under `docker-assets/`, keeping `docker build -t autoattack-agent .` deterministic and fast.

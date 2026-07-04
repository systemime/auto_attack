import argparse
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import autoattack_agent as aa


class AutoAttackTests(unittest.TestCase):
    def _capture_json(self, argv):
        from io import StringIO
        old = sys.stdout
        try:
            sys.stdout = StringIO()
            rc = aa.main(argv)
            return rc, json.loads(sys.stdout.getvalue())
        finally:
            sys.stdout = old

    def test_policy_init_parse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            aa.write_policy_template(str(path))
            policy = aa.load_policy(str(path))
            self.assertIn("127.0.0.1", policy.roots)
            self.assertIn("nmap", policy.allow_tools)
            self.assertEqual(policy.sha256, aa._file_sha256(path))

    def test_scope_domain_cidr_deny(self):
        policy = aa.Policy({"scope": {"roots": ["example.com", "10.0.0.0/24"], "deny": ["bad.example.com", "10.0.0.9"]}})
        scope = aa.Scope([], policy=policy)
        self.assertTrue(scope.allowed("www.example.com"))
        self.assertTrue(scope.allowed("10.0.0.8"))
        self.assertFalse(scope.allowed("bad.example.com"))
        self.assertFalse(scope.allowed("10.0.0.9"))
        self.assertFalse(scope.allowed("evil.test"))

    def test_intrusive_gate(self):
        target = aa.normalize_target("https://example.com/?a=1")
        tool = aa.ToolSpec("sqlmap", "validate", "", True, True, "python3", lambda _t, _o: ["python3", "-V"], lambda _r: ([], []))
        reg = aa.ToolRegistry()
        reg.tools = [tool]
        policy = aa.Policy({"scope": {"roots": ["example.com"], "deny": []}, "tools": {"allow": ["sqlmap"], "intrusive": ["sqlmap"]}, "approval": {"intrusive": False}})
        args = argparse.Namespace(rounds=1, max_steps=1, max_workers=1, timeout=1, max_discovered_targets=1, approve_intrusive=True)
        aa.apply_policy_limits(args, policy)
        self.assertFalse(args.allow_intrusive)
        self.assertEqual(reg.plan(target, "deep", args.allow_intrusive, policy=policy), [])
        policy.data["approval"]["intrusive"] = True
        aa.apply_policy_limits(args, policy)
        self.assertTrue(reg.plan(target, "deep", args.allow_intrusive, policy=policy))

    def test_command_cache_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            counter = tmp / "count.txt"
            target = aa.normalize_target("127.0.0.1")
            args = argparse.Namespace(
                allow_out_of_scope=False,
                max_workers=1,
                timeout=5,
                resume=False,
                retry_failed=0,
                tools="",
                profile="quick",
                allow_intrusive=False,
                ai=False,
                base_url=None,
                model="test",
                api_key_env="OPENAI_API_KEY",
                max_steps=1,
                rounds=1,
                max_discovered_targets=1,
                policy_obj=aa.load_policy(None, [target]),
            )
            cmd = [sys.executable, "-c", "from pathlib import Path; import sys; p=Path(sys.argv[1]); n=int(p.read_text() or 0) if p.exists() else 0; p.write_text(str(n+1)); print('ok')", str(counter)]
            tool = aa.ToolSpec("dummy", "test", "", False, False, sys.executable, lambda _t, _o: cmd, lambda _r: ([], []))
            agent = aa.Agent([target], tmp, args)
            agent._run_tools([(tool, target)])
            args.resume = True
            agent._run_tools([(tool, target)])
            self.assertEqual(counter.read_text(), "1")
            self.assertEqual(len(agent.store.rows("command_cache")), 1)
            self.assertTrue(any(r["status"] == "cached" for r in agent.store.rows("tool_runs")))
            stats = aa.skill_stats(agent.store)
            self.assertGreaterEqual(stats["runtime"]["count"], 1)
            self.assertTrue(any(x["skill"] == "dummy" and "runtime" in x for x in stats["skill_runs"]["top_skills"]))

    def test_threaded_sqlite_and_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = aa.Store(Path(tmp) / "state.sqlite3")
            def add(i):
                store.add_observation(aa.Observation("t", str(i), "fake", {"i": i}))
                store.add_finding(aa.Finding("f", "info", str(i), "e", "t", source_skill="skill", source_tool="tool", validation_status="tool-reported", cve="CVE-1", cwe="CWE-79", references=["https://x"]))
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(add, range(50)))
            for i in range(5):
                store.add_task("p", str(i), "t", "done")
            self.assertEqual(len(store.rows("observations")), 50)
            self.assertEqual([r["target"] for r in store.rows("tasks", limit=2, recent=True)], ["3", "4"])
            self.assertEqual([r["target"] for r in store.rows("tasks", limit=2, offset=1, recent=True)], ["2", "3"])
            sarif = aa._sarif([dict(r) for r in store.rows("findings")])
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["results"][0]["properties"]["source_skill"], "skill")
            json.dumps(sarif)

    def test_run_manifest_status_report_resume_smoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            policy = tmp / "policy.json"
            workspace = tmp / "run"
            self.assertEqual(aa.main(["init", "--output", str(policy)]), 0)
            self.assertEqual(aa.main(["run", "127.0.0.1", "--policy", str(policy), "--workspace", str(workspace), "--profile", "quick", "--max-steps", "0", "--timeout", "1", "--rounds", "1"]), 0)
            for name in ("run.json", "policy.json", "state.sqlite3", "report.md", "findings.json", "observations.json", "report.sarif.json"):
                self.assertTrue((workspace / name).exists(), name)
            manifest = json.loads((workspace / "run.json").read_text())
            self.assertEqual(manifest["status"], "completed")
            self.assertIn("policy_sha256", manifest)
            self.assertEqual(len(manifest["effective_args"].get("skillset_sha256", "")), 64)
            self.assertEqual(manifest["agent_version"], aa.AGENT_VERSION)
            self.assertEqual(manifest["skill_schema_version"], aa.SKILL_SCHEMA_VERSION)
            routing_events = [json.loads(r["data"]) for r in aa.Store(workspace / "state.sqlite3").rows("events") if r["kind"] == "skill_routing_summary"]
            self.assertTrue(routing_events)
            self.assertIn("skipped_reason_counts", routing_events[0])
            stats = aa.skill_stats(aa.Store(workspace / "state.sqlite3"))
            self.assertGreaterEqual(stats["skill_runs"]["total"], 1)
            self.assertGreaterEqual(stats["routing"]["events"], 1)
            rc, stats_cli = self._capture_json(["skills", "stats", str(workspace), "--limit", "5"])
            self.assertEqual(rc, 0)
            self.assertIn("routing", stats_cli)
            self.assertEqual(aa.main(["status", str(workspace)]), 0)
            self.assertEqual(aa.main(["report", str(workspace), "--format", "md,json,sarif"]), 0)
            self.assertEqual(aa.main(["resume", str(workspace), "--retry-failed", "1"]), 0)


    def test_out_of_scope_run_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            policy = tmp / "policy.json"
            workspace = tmp / "run"
            policy.write_text(json.dumps({"scope": {"roots": ["127.0.0.1"], "deny": []}, "limits": {"max_rounds": 1, "max_steps": 0, "max_workers": 1, "timeout_seconds": 1, "max_discovered_targets": 1}, "tools": {"allow": [], "intrusive": []}, "approval": {"intrusive": False}}))
            self.assertEqual(aa.main(["run", "evil.test", "--policy", str(policy), "--workspace", str(workspace), "--profile", "quick", "--max-steps", "0", "--timeout", "1", "--rounds", "1"]), 0)
            rows = [dict(r) for r in aa.Store(workspace / "state.sqlite3").rows("tasks")]
            self.assertTrue(any(r["status"] == "skipped" for r in rows))
            self.assertFalse(aa.Store(workspace / "state.sqlite3").rows("observations"))

    def test_failed_cache_retry_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            counter = tmp / "count.txt"
            target = aa.normalize_target("127.0.0.1")
            args = argparse.Namespace(allow_out_of_scope=False, max_workers=1, timeout=5, resume=False, retry_failed=0, tools="", profile="quick", allow_intrusive=False, ai=False, base_url=None, model="test", api_key_env="OPENAI_API_KEY", max_steps=1, rounds=1, max_discovered_targets=1, policy_obj=aa.load_policy(None, [target]))
            code = "from pathlib import Path; import sys; p=Path(sys.argv[1]); n=int(p.read_text() or 0) if p.exists() else 0; p.write_text(str(n+1)); print(n); sys.exit(1 if n == 0 else 0)"
            cmd = [sys.executable, "-c", code, str(counter)]
            tool = aa.ToolSpec("dummy", "test", "", False, False, sys.executable, lambda _t, _o: cmd, lambda _r: ([], []))
            agent = aa.Agent([target], tmp, args)
            agent._run_tools([(tool, target)])
            args.resume = True
            agent._run_tools([(tool, target)])
            self.assertEqual(counter.read_text(), "1")
            args.retry_failed = 1
            agent._run_tools([(tool, target)])
            self.assertEqual(counter.read_text(), "2")

    def test_tools_policy_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            policy = Path(tmp) / "policy.json"
            policy.write_text(json.dumps({"scope": {"roots": ["127.0.0.1"], "deny": []}, "tools": {"allow": ["nmap"], "intrusive": ["sqlmap"]}, "approval": {"intrusive": False}}))
            from io import StringIO
            old = sys.stdout
            try:
                sys.stdout = StringIO()
                self.assertEqual(aa.main(["tools", "--policy", str(policy)]), 0)
                data = json.loads(sys.stdout.getvalue())
            finally:
                sys.stdout = old
            by_name = {x["name"]: x for x in data}
            self.assertTrue(by_name["nmap"]["allowed_by_policy"])
            self.assertFalse(by_name["sqlmap"]["allowed_by_policy"])
            self.assertTrue(by_name["sqlmap"]["requires_approval"])

    def test_skills_cli_enable_disable_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.environ.get("AUTOATTACK_SKILLS_CONFIG")
            os.environ["AUTOATTACK_SKILLS_CONFIG"] = str(Path(tmp) / "skills.json")
            try:
                rc, rows = self._capture_json(["skills", "list"])
                self.assertEqual(rc, 0)
                self.assertIn("python-recon", {x["name"] for x in rows})
                rc, result = self._capture_json(["skills", "test", "python-recon"])
                self.assertEqual(rc, 0)
                self.assertTrue(result["ok"])
                self.assertEqual(self._capture_json(["skills", "disable", "python-recon"])[0], 0)
                self.assertFalse(aa.SkillRegistry(config_path=Path(os.environ["AUTOATTACK_SKILLS_CONFIG"])).get("python-recon").enabled)
                self.assertEqual(self._capture_json(["skills", "enable", "python-recon"])[0], 0)
                self.assertTrue(aa.SkillRegistry(config_path=Path(os.environ["AUTOATTACK_SKILLS_CONFIG"])).get("python-recon").enabled)
                cfg = Path(os.environ["AUTOATTACK_SKILLS_CONFIG"])
                self.assertEqual(json.loads(cfg.read_text())["disabled"], [])
                self.assertFalse(list(cfg.parent.glob("*.tmp")))
            finally:
                if old is None:
                    os.environ.pop("AUTOATTACK_SKILLS_CONFIG", None)
                else:
                    os.environ["AUTOATTACK_SKILLS_CONFIG"] = old

    def test_router_needs_url_policy_and_intrusive_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            tool = aa.ToolSpec("dummy-intrusive", "scan", "", True, True, sys.executable, lambda _t, _o: ["python3", "-V"], lambda _r: ([], []))
            reg = aa.ToolRegistry()
            reg.tools = [tool]
            store = aa.Store(Path(tmp) / "state.sqlite3")
            router = aa.SkillRouter(aa.SkillRegistry(reg, Path(tmp) / "skills.json"), store)
            policy = aa.Policy({"scope": {"roots": ["example.com"], "deny": []}, "tools": {"allow": ["dummy-intrusive"], "intrusive": ["dummy-intrusive"]}, "approval": {"intrusive": False}})
            self.assertEqual(router.plan(aa.normalize_target("example.com"), "deep", False, policy=policy), [])
            plans = router.plan(aa.normalize_target("https://example.com/?a=1"), "deep", False, policy=policy)
            self.assertEqual(plans[0].status, "approval_required")
            rid = store.add_approval_request("intrusive", plans[0].target.raw, plans[0].skill.name, plans[0].skill.tool.name, plans[0].skill.risk, plans[0].reason)
            self.assertTrue(store.decide_approval(rid, "approved"))
            self.assertEqual(router.plan(aa.normalize_target("https://example.com/?a=1"), "deep", False, policy=policy)[0].status, "ready")

    def test_approval_cli_smoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            store = aa.Store(workspace / "state.sqlite3")
            rid = store.add_approval_request("intrusive", "https://x", "sqlmap", "sqlmap", "intrusive", "test")
            rc, rows = self._capture_json(["approvals", str(workspace)])
            self.assertEqual(rc, 0)
            self.assertEqual(rows[0]["status"], "pending")
            rc, result = self._capture_json(["approve", str(workspace), str(rid)])
            self.assertEqual(rc, 0)
            self.assertTrue(result["ok"])
            self.assertEqual(aa.Store(workspace / "state.sqlite3").rows("approval_requests")[0]["status"], "approved")

    def test_ai_planner_bad_json_is_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = aa.Store(Path(tmp) / "state.sqlite3")
            args = argparse.Namespace(api_key_env="AUTOATTACK_TEST_KEY", base_url="http://127.0.0.1", model="test", timeout=1, tools="", profile="deep")
            old_key = os.environ.get("AUTOATTACK_TEST_KEY")
            old_chat = aa.chat_completion
            os.environ["AUTOATTACK_TEST_KEY"] = "x"
            aa.chat_completion = lambda *a, **k: "not json"
            try:
                tasks = aa.ai_plan_tasks([aa.normalize_target("example.com")], aa.SkillRegistry(config_path=Path(tmp) / "skills.json"), args, None, store)
                self.assertEqual(tasks, [])
                self.assertTrue(any(r["kind"] == "ai_planner_error" for r in store.rows("events")))
            finally:
                aa.chat_completion = old_chat
                if old_key is None:
                    os.environ.pop("AUTOATTACK_TEST_KEY", None)
                else:
                    os.environ["AUTOATTACK_TEST_KEY"] = old_key

    def test_ai_planner_reads_blackboard(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = aa.Store(Path(tmp) / "state.sqlite3")
            store.add_observation(aa.Observation("python", "https://example.com", "http", {"url": "https://example.com", "status": 200}))
            store.add_finding(aa.Finding("Missing common security headers", "low", "https://example.com", "csp", "python"))
            args = argparse.Namespace(api_key_env="AUTOATTACK_TEST_KEY", base_url="http://127.0.0.1", model="test", timeout=1, tools="", profile="deep")
            old_key = os.environ.get("AUTOATTACK_TEST_KEY")
            old_chat = aa.chat_completion
            old_available = aa.tool_available
            seen = {}
            os.environ["AUTOATTACK_TEST_KEY"] = "x"
            aa.tool_available = lambda tool: True
            def fake_chat(_base, _key, _model, prompt, **_kw):
                seen["prompt"] = prompt
                return json.dumps({"tasks": [{"target": "https://example.com", "skill": "httpx", "reason": "observed http", "risk": "safe"}]})
            aa.chat_completion = fake_chat
            try:
                tasks = aa.ai_plan_tasks([aa.normalize_target("https://example.com")], aa.SkillRegistry(config_path=Path(tmp) / "skills.json"), args, None, store)
                self.assertEqual(tasks[0]["skill"], "httpx")
                self.assertIn("Missing common security headers", seen["prompt"])
                self.assertIn("\"observations\"", seen["prompt"])
            finally:
                aa.chat_completion = old_chat
                if old_key is None:
                    os.environ.pop("AUTOATTACK_TEST_KEY", None)
                else:
                    os.environ["AUTOATTACK_TEST_KEY"] = old_key


    def test_large_skill_registry_cache_indexes_and_topk(self):
        with tempfile.TemporaryDirectory() as tmp:
            calls = {"available": 0}
            old_available = aa.tool_available
            def fake_available(_tool):
                calls["available"] += 1
                return True
            aa.tool_available = fake_available
            try:
                reg = aa.ToolRegistry()
                reg.tools = [aa.ToolSpec(f"skill{i}", "recon" if i % 2 == 0 else "scan", f"synthetic skill {i}", False, False, sys.executable, lambda _t, _o: [sys.executable, "-V"], lambda _r: ([], [])) for i in range(1000)]
                skills = aa.SkillRegistry(reg, Path(tmp) / "skills.json")
                self.assertEqual(skills.get("skill999").name, "skill999")
                target = aa.normalize_target("example.com")
                router = aa.SkillRouter(skills, aa.Store(Path(tmp) / "state.sqlite3"))
                plans = router.plan(target, "deep", False)
                self.assertEqual(len(plans), 1000)
                self.assertEqual(calls["available"], 1000)
                router.plan(target, "deep", False)
                self.assertEqual(calls["available"], 1000)
                args = argparse.Namespace(tools="", profile="deep")
                candidates = aa.ai_skill_candidates([target], skills, args, None, limit=30)
                self.assertEqual(len(candidates), 30)
                self.assertIn("description", candidates[0])
                self.assertIn("contract_sha256", candidates[0])
                idx = {r["name"] for r in aa.Store(Path(tmp) / "state.sqlite3").db.execute("select name from sqlite_master where type='index'")}
                self.assertIn("idx_approval_skill_target_id", idx)
                self.assertIn("idx_skill_runs_skill_status", idx)
                cols = {r[1] for r in aa.Store(Path(tmp) / "state.sqlite3").db.execute("pragma table_info(skills)")}
                self.assertIn("input_schema", cols)
                self.assertIn("output_schema", cols)
            finally:
                aa.tool_available = old_available

    def test_duplicate_skill_names_are_rejected_and_policy_intrusive_risk_is_reflected(self):
        with tempfile.TemporaryDirectory() as tmp:
            reg = aa.ToolRegistry()
            reg.tools = [aa.ToolSpec("dup", "scan", "a", False, False, sys.executable, lambda _t, _o: [sys.executable, "-V"], lambda _r: ([], [])), aa.ToolSpec("dup", "scan", "b", False, False, sys.executable, lambda _t, _o: [sys.executable, "-V"], lambda _r: ([], []))]
            with self.assertRaises(ValueError):
                aa.SkillRegistry(reg, Path(tmp) / "skills.json")

            reg.tools = [aa.ToolSpec("safe-but-policy-intrusive", "scan", "policy controlled", False, False, sys.executable, lambda _t, _o: [sys.executable, "-V"], lambda _r: ([], []))]
            skills = aa.SkillRegistry(reg, Path(tmp) / "skills2.json")
            store = aa.Store(Path(tmp) / "state.sqlite3")
            router = aa.SkillRouter(skills, store)
            policy = aa.Policy({"scope": {"roots": ["example.com"], "deny": []}, "tools": {"allow": ["safe-but-policy-intrusive"], "intrusive": ["safe-but-policy-intrusive"]}, "approval": {"intrusive": False}})
            plan = router.plan(aa.normalize_target("example.com"), "deep", False, policy=policy)[0]
            self.assertEqual(plan.status, "approval_required")
            self.assertEqual(plan.skill.risk, "intrusive")
            self.assertTrue(plan.skill.requires_approval)

    def test_events_report_and_docker_checksums(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            store = aa.Store(tmp / "state.sqlite3")
            store.add_event("unit", {"ok": True})
            aa.write_report(tmp, store, [], argparse.Namespace(profile="test", allow_intrusive=False, max_steps=0), formats={"events"})
            self.assertTrue((tmp / "events.jsonl").read_text().strip())
        manifest = ROOT / "docker-assets" / "manifest.tsv"
        self.assertTrue(manifest.exists())
        for line in manifest.read_text().splitlines():
            name, version, url, digest = line.split("\t")
            self.assertTrue(url.startswith("https://github.com/projectdiscovery/"))
            cached = ROOT / "docker-assets" / f"{name}.zip"
            if cached.exists():
                self.assertEqual(hashlib.sha256(cached.read_bytes()).hexdigest(), digest)

    def test_distributed_queue_worker_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            counter = tmp / "count.txt"
            tool = aa.ToolSpec(
                "py-dummy",
                "fingerprint",
                "distributed worker fixture",
                False,
                False,
                sys.executable,
                lambda _t, _o: [sys.executable, "-c", "from pathlib import Path; import sys; p=Path(sys.argv[1]); n=int(p.read_text() or 0) if p.exists() else 0; p.write_text(str(n+1)); print('ok')", str(counter)],
                lambda r: ([], [aa.Finding("Distributed dummy", "info", r.target, "ok", r.tool)]),
            )
            class FakeRegistry:
                def __init__(self):
                    self.tools = [tool]
                def available(self):
                    return [tool]
            old = aa.ToolRegistry
            aa.ToolRegistry = FakeRegistry
            try:
                policy = tmp / "policy.json"
                workspace = tmp / "run"
                policy.write_text(json.dumps({"scope": {"roots": ["127.0.0.1"], "deny": []}, "limits": {"max_rounds": 1, "max_steps": 1, "max_workers": 1, "timeout_seconds": 5, "max_discovered_targets": 1}, "tools": {"allow": ["py-dummy"], "intrusive": []}, "approval": {"intrusive": False}}))
                self.assertEqual(aa.main(["run", "127.0.0.1", "--policy", str(policy), "--workspace", str(workspace), "--profile", "quick", "--max-steps", "1", "--timeout", "1", "--rounds", "1", "--execution-mode", "queue", "--tools", "py-dummy"]), 0)
                store = aa.Store(workspace / "state.sqlite3")
                self.assertEqual(store.counts()["jobs_by_status"].get("queued"), 1)
                self.assertEqual(self._capture_json(["jobs", str(workspace)])[1][0]["status"], "queued")
                self.assertEqual(json.loads((workspace / "run.json").read_text())["status"], "queued")
                self.assertEqual(aa.main(["worker", str(workspace), "--once", "--max-jobs", "1"]), 0)
                store = aa.Store(workspace / "state.sqlite3")
                self.assertEqual(store.counts()["jobs_by_status"].get("done"), 1)
                self.assertEqual(counter.read_text(), "1")
                self.assertTrue(any(r["title"] == "Distributed dummy" for r in store.rows("findings")))
                self.assertEqual(json.loads((workspace / "run.json").read_text())["status"], "completed")
            finally:
                aa.ToolRegistry = old

    def test_redis_queue_backend_with_fake(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            counter = tmp / "count.txt"
            tool = aa.ToolSpec(
                "py-dummy",
                "fingerprint",
                "redis worker fixture",
                False,
                False,
                sys.executable,
                lambda _t, _o: [sys.executable, "-c", "from pathlib import Path; import sys; p=Path(sys.argv[1]); p.write_text('1'); print('ok')", str(counter)],
                lambda r: ([], [aa.Finding("Redis dummy", "info", r.target, "ok", r.tool)]),
            )
            class FakeRegistry:
                def __init__(self):
                    self.tools = [tool]
                def available(self):
                    return [tool]
            class FakeRedisQueue:
                queues = {}
                def __init__(self, _url, name):
                    self.name = name
                    self.queues.setdefault(name, [])
                def ping(self):
                    return True
                def push(self, job_id):
                    self.queues[self.name].append(job_id)
                def pop(self):
                    return self.queues[self.name].pop(0) if self.queues[self.name] else None
            old_reg, old_q = aa.ToolRegistry, aa.RedisQueue
            aa.ToolRegistry, aa.RedisQueue = FakeRegistry, FakeRedisQueue
            try:
                policy = tmp / "policy.json"
                workspace = tmp / "run"
                policy.write_text(json.dumps({"scope": {"roots": ["127.0.0.1"], "deny": []}, "limits": {"max_rounds": 1, "max_steps": 1, "max_workers": 1, "timeout_seconds": 5, "max_discovered_targets": 1}, "tools": {"allow": ["py-dummy"], "intrusive": []}, "approval": {"intrusive": False}}))
                self.assertEqual(aa.main(["run", "127.0.0.1", "--policy", str(policy), "--workspace", str(workspace), "--profile", "quick", "--max-steps", "1", "--timeout", "1", "--rounds", "1", "--distributed", "--queue-name", "testq", "--tools", "py-dummy"]), 0)
                self.assertEqual(aa.Store(workspace / "state.sqlite3").counts()["jobs_by_status"].get("queued"), 1)
                self.assertEqual(aa.main(["worker", str(workspace), "--once", "--max-jobs", "1", "--queue-name", "testq"]), 0)
                self.assertEqual(counter.read_text(), "1")
                self.assertTrue(any(r["title"] == "Redis dummy" for r in aa.Store(workspace / "state.sqlite3").rows("findings")))
            finally:
                aa.ToolRegistry, aa.RedisQueue = old_reg, old_q

    def test_har_import_and_web_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            har = tmp / "x.har"
            har.write_text(json.dumps({"log": {"entries": [{"request": {"method": "GET", "url": "https://example.com/a", "headers": [{"name": "Cookie", "value": "secret"}]}, "response": {"status": 500, "content": {"mimeType": "text/html"}}}]}}))
            self.assertEqual(aa.main(["import-har", str(tmp), str(har)]), 0)
            store = aa.Store(tmp / "state.sqlite3")
            self.assertTrue(store.rows("observations"))
            self.assertTrue(store.rows("findings"))
            self.assertIn("AutoAttack Console", aa.render_console(tmp))
            self.assertIn("findings", aa.api_payload(tmp, "status"))
            self.assertLessEqual(len(aa.api_payload(tmp, "findings", "limit=1")), 1)
            args = argparse.Namespace(headers=["Authorization: Bearer x"], cookie="sid=1")
            self.assertEqual(aa._http_headers_from_args(args)["Cookie"], "sid=1")


    def test_skill_manifest_normalize_validate_and_load(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skills_dir = root / "skills"
            skills_dir.mkdir()
            manifest = skills_dir / "web_headers.json"
            manifest.write_text(json.dumps({
                "name": "web.headers",
                "schema_version": 1,
                "min_agent_version": "1.0.0",
                "version": "1.2",
                "description": "Check HTTP response headers",
                "phase": "fingerprint",
                "risk": "safe",
                "tags": "web,headers",
                "capabilities": ["http", "headers", "http"],
                "priority": 88,
                "needs_url": "true",
                "depends_on": "python-recon",
            }))
            normalized = aa.normalize_skill_manifest(json.loads(manifest.read_text()), source=str(manifest))
            self.assertEqual(normalized["schema_version"], 1)
            self.assertEqual(normalized["min_agent_version"], "1.0.0")
            self.assertEqual(normalized["depends_on"], ["python-recon"])
            self.assertEqual(normalized["tags"], ["web", "headers"])
            self.assertEqual(normalized["capabilities"], ["http", "headers"])
            self.assertTrue(normalized["needs_url"])
            self.assertEqual(normalized["input_schema"]["type"], "object")
            self.assertEqual(normalized["output_schema"]["type"], "object")
            versioned = aa.normalize_skill_manifest({"name": "web.versioned", "description": "versioned", "depends_on": {"python-recon": ">=1"}})
            self.assertEqual(versioned["depends_on"], ["python-recon"])
            self.assertEqual(versioned["dependency_versions"], {"python-recon": ">=1"})
            auto = aa.normalize_skill_manifest({"name": "web.auto-headers", "description": "auto terms", "phase": "fingerprint", "tool": "httpx"})
            self.assertIn("web", auto["tags"])
            self.assertIn("httpx", auto["capabilities"])
            legacy = aa.normalize_skill_manifest({"id": "legacy.headers", "summary": "legacy headers", "stage": "fingerprint", "tool_name": "httpx", "schema_version": 0, "requires_url": "yes", "capability": "headers"})
            self.assertEqual(legacy["schema_version"], 1)
            self.assertEqual(legacy["name"], "legacy.headers")
            self.assertEqual(legacy["phase"], "fingerprint")
            self.assertEqual(legacy["tool"], "httpx")
            self.assertTrue(legacy["needs_url"])
            self.assertEqual(legacy["capabilities"], ["headers"])
            raw_manifest = skills_dir / "auto.json"
            raw_manifest.write_text(json.dumps({"name": "web.auto", "description": "auto", "tool": "httpx"}))
            rc, normalized_one = self._capture_json(["skills", "normalize", str(raw_manifest)])
            self.assertEqual(rc, 0)
            self.assertIn("httpx", normalized_one["capabilities"])
            rc, strict_rows = self._capture_json(["skills", "validate", str(skills_dir), "--strict"])
            self.assertEqual(rc, 1)
            self.assertTrue(any("not normalized" in r.get("error", "") for r in strict_rows))
            rc, normalized_rows = self._capture_json(["skills", "normalize", str(skills_dir), "--write"])
            self.assertEqual(rc, 0)
            self.assertTrue(any(r["path"] == str(raw_manifest) and r["changed"] for r in normalized_rows))
            self.assertIn("httpx", json.loads(raw_manifest.read_text())["capabilities"])
            self.assertFalse(list(skills_dir.glob("*.tmp")))
            self.assertEqual(self._capture_json(["skills", "validate", str(skills_dir), "--strict"])[0], 0)
            rc, rows = self._capture_json(["skills", "--skills-dir", str(skills_dir), "validate", str(skills_dir)])
            self.assertEqual(rc, 0)
            self.assertTrue(rows[0]["ok"])
            rc, rows = self._capture_json(["skills", "--skills-dir", str(skills_dir), "list"])
            self.assertEqual(rc, 0)
            by_name = {x["name"]: x for x in rows}
            self.assertIn("web.headers", by_name)
            self.assertEqual(by_name["web.headers"]["source"], str(manifest))
            self.assertEqual(by_name["web.headers"]["priority"], 88)
            self.assertEqual(by_name["web.headers"]["schema_version"], 1)
            rc, shown = self._capture_json(["skills", "--skills-dir", str(skills_dir), "show", "web.headers", "--raw"])
            self.assertEqual(rc, 0)
            self.assertTrue(shown["ok"])
            self.assertEqual(shown["raw_manifest"]["name"], "web.headers")
            rc, shown_tool = self._capture_json(["skills", "--skills-dir", str(skills_dir), "show", "web.auto", "--raw"])
            self.assertEqual(rc, 0)
            self.assertEqual(shown_tool["tool_detail"]["name"], "httpx")
            rc, page = self._capture_json(["skills", "--skills-dir", str(skills_dir), "list", "--source", "manifest", "--query", "headers", "--limit", "1", "--summary"])
            self.assertEqual(rc, 0)
            self.assertEqual(page["total"], 1)
            self.assertEqual(page["returned"], 1)
            self.assertEqual(page["skills"][0]["name"], "web.headers")
            self.assertEqual(page["skills"][0]["depends_on"], ["python-recon"])
            bad_dir = root / "bad"
            bad_dir.mkdir()
            (bad_dir / "bad.json").write_text(json.dumps({"name": "bad.dep", "description": "bad", "depends_on": ["missing.skill"]}))
            bad_version_dir = root / "bad_version"
            bad_version_dir.mkdir()
            (bad_version_dir / "bad.json").write_text(json.dumps({"name": "bad.version", "description": "bad", "depends_on": {"python-recon": ">=2.0"}}))
            bad_schema = root / "bad_schema.json"
            bad_schema.write_text(json.dumps({"name": "bad.schema", "description": "bad", "schema_version": 999}))
            rc, rows = self._capture_json(["skills", "validate", str(bad_schema)])
            self.assertEqual(rc, 1)
            self.assertIn("unsupported schema_version", rows[0]["error"])
            bad_contract = root / "bad_contract.json"
            bad_contract.write_text(json.dumps({"name": "bad.contract", "description": "bad", "input_schema": []}))
            rc, rows = self._capture_json(["skills", "validate", str(bad_contract)])
            self.assertEqual(rc, 1)
            self.assertIn("input_schema must be an object", rows[0]["error"])
            rc, rows = self._capture_json(["skills", "validate", str(bad_dir)])
            self.assertEqual(rc, 1)
            self.assertIn("missing dependencies", rows[0]["error"])
            rc, rows = self._capture_json(["skills", "validate", str(bad_version_dir)])
            self.assertEqual(rc, 1)
            self.assertIn("dependency version mismatch", rows[0]["error"])
            cycle_dir = root / "cycle"
            cycle_dir.mkdir()
            (cycle_dir / "a.json").write_text(json.dumps({"name": "cycle.a", "description": "a", "depends_on": ["cycle.b"]}))
            (cycle_dir / "b.json").write_text(json.dumps({"name": "cycle.b", "description": "b", "depends_on": ["cycle.a"]}))
            rc, rows = self._capture_json(["skills", "validate", str(cycle_dir)])
            self.assertEqual(rc, 1)
            self.assertTrue(any("dependency cycle" in r.get("error", "") for r in rows))

    def test_manifest_skill_tool_binding_conflict_priority_routing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skills_dir = root / "skills"
            skills_dir.mkdir()
            for item in [
                {"name": "dummy.high", "tool": "dummy", "phase": "scan", "risk": "safe", "description": "dummy web scan", "priority": 90, "capabilities": ["web"], "conflicts": ["dummy.low"], "depends_on": ["dummy.base"]},
                {"name": "dummy.low", "tool": "dummy", "phase": "scan", "risk": "safe", "description": "dummy web scan low", "priority": 10, "capabilities": ["web"]},
                {"name": "dummy.blocked", "tool": "dummy", "phase": "scan", "risk": "safe", "description": "missing dep", "priority": 95, "depends_on": ["no.such"]},
                {"name": "dummy.versioned", "tool": "dummy", "phase": "scan", "risk": "safe", "description": "version mismatch", "priority": 96, "depends_on": {"dummy.base": ">=2.0"}},
                {"name": "dummy.base", "phase": "scan", "risk": "safe", "description": "metadata dependency", "priority": 1},
                {"name": "catalog.only", "phase": "scan", "risk": "safe", "description": "metadata only", "priority": 100},
            ]:
                (skills_dir / f"{item['name']}.json").write_text(json.dumps(item))
            tool = aa.ToolSpec("dummy", "scan", "dummy tool", False, False, sys.executable, lambda _t, _o: [sys.executable, "-V"], lambda _r: ([], []))
            reg = aa.ToolRegistry()
            reg.tools = [tool]
            skills = aa.SkillRegistry(reg, Path(tmp) / "disabled.json", skills_dir)
            self.assertIs(skills.get("dummy.high").tool, tool)
            self.assertIn("catalog.only", {s.name for s in skills.candidates(aa.normalize_target("example.com"), "deep")})
            router = aa.SkillRouter(skills)
            plans = router.plan(aa.normalize_target("example.com"), "deep", False, query="web scan")
            plan_names = [p.skill.name for p in plans]
            self.assertEqual(plan_names[0], "dummy.high")
            self.assertNotIn("dummy.low", plan_names)
            self.assertNotIn("dummy.blocked", plan_names)
            self.assertNotIn("catalog.only", plan_names)
            self.assertIn("dummy.high", [p.skill.name for p in router.plan(aa.normalize_target("example.com"), "deep", False, selected={"cap:web"})])
            self.assertFalse(router.plan(aa.normalize_target("example.com"), "deep", False, selected={"tag:nope"}))
            args = argparse.Namespace(tools="", profile="deep")
            candidates = aa.ai_skill_candidates([aa.normalize_target("example.com")], skills, args, None, limit=10)
            self.assertNotIn("catalog.only", {c["name"] for c in candidates})
            explained = aa.explain_skill_routing(skills, aa.normalize_target("example.com"), "deep", False, query="web scan")
            self.assertEqual(explained["plans"][0]["skill"], "dummy.high")
            self.assertEqual(explained["plans"][0]["depends_on"], ["dummy.base"])
            self.assertTrue(any(x["skill"] == "dummy.low" and x["reason"] == "conflict" for x in explained["skipped"]))
            self.assertTrue(any(x["skill"] == "dummy.blocked" and "missing dependency" in x["reason"] for x in explained["skipped"]))
            self.assertTrue(any(x["skill"] == "dummy.versioned" and "version mismatch" in x["reason"] for x in explained["skipped"]))
            self.assertGreaterEqual(explained["skipped_reason_counts"].get("conflict", 0), 1)
            self.assertTrue(any(k.startswith("missing dependency") for k in explained["skipped_reason_counts"]))
            eval_file = root / "eval.json"
            eval_file.write_text(json.dumps({"cases": [
                {"name": "web route", "target": "example.com", "profile": "deep", "query": "web scan", "tools": ["cap:web"], "expect_plans": ["dummy.high"], "reject_plans": ["dummy.low"]},
                {"name": "catalog candidate", "target": "example.com", "profile": "deep", "expect_candidates": ["dummy.high"], "reject_candidates": ["dummy.blocked"]},
            ]}))
            self.assertTrue(aa.eval_skill_routing(skills, eval_file)["ok"])
            old_registry = aa.ToolRegistry
            class FakeRegistry:
                def __init__(self):
                    self.tools = [tool]
                def get(self, name):
                    return tool if name == "dummy" else None
                def is_available(self, _tool):
                    return True
            aa.ToolRegistry = FakeRegistry
            try:
                rc, explained_cli = self._capture_json(["skills", "--skills-dir", str(skills_dir), "explain", "example.com", "--profile", "deep", "--query", "web scan", "--tools", "cap:web"])
                self.assertEqual(rc, 0)
                self.assertEqual(explained_cli["plans"][0]["skill"], "dummy.high")
                rc, eval_result = self._capture_json(["skills", "--skills-dir", str(skills_dir), "eval", str(eval_file)])
                self.assertEqual(rc, 0)
                self.assertEqual(eval_result["passed"], 2)
                runs = root / "runs"
                for name in ("r1", "r2"):
                    store = aa.Store(runs / name / "state.sqlite3")
                    store.add_skill_run("dummy.high", "example.com", "done", "dummy", reason=name)
                    store.add_event("skill_routing_summary", {"target": "example.com", "candidates": 2, "planned": 1, "plan_status": {"ready": 1}, "skipped_reason_counts": {"conflict": 1}})
                rc, stats = self._capture_json(["skills", "stats", str(runs)])
                self.assertEqual(rc, 0)
                self.assertEqual(stats["skill_runs"]["total"], 2)
                self.assertEqual(stats["routing"]["planned"], 2)
                self.assertEqual(stats["routing"]["skipped_reason_counts"]["conflict"], 2)
                rc, trace = self._capture_json(["skills", "trace", str(runs / "r1"), "--skill", "dummy.high"])
                self.assertEqual(rc, 0)
                self.assertTrue(any(x["type"] == "skill_run" and x["skill"] == "dummy.high" for x in trace["events"]))
                self.assertTrue(any(x["type"] == "event" and x["kind"] == "skill_routing_summary" for x in trace["events"]))
            finally:
                aa.ToolRegistry = old_registry

    def test_no_policy_requires_smoke(self):
        with self.assertRaises(SystemExit):
            aa.main(["run", "127.0.0.1", "--profile", "standard", "--max-steps", "0"])


if __name__ == "__main__":
    unittest.main()

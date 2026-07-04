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

    def test_threaded_sqlite_and_sarif(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = aa.Store(Path(tmp) / "state.sqlite3")
            def add(i):
                store.add_observation(aa.Observation("t", str(i), "fake", {"i": i}))
                store.add_finding(aa.Finding("f", "info", str(i), "e", "t", source_skill="skill", source_tool="tool", validation_status="tool-reported", cve="CVE-1", cwe="CWE-79", references=["https://x"]))
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(add, range(50)))
            self.assertEqual(len(store.rows("observations")), 50)
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
                idx = {r["name"] for r in aa.Store(Path(tmp) / "state.sqlite3").db.execute("select name from sqlite_master where type='index'")}
                self.assertIn("idx_approval_skill_target_id", idx)
                self.assertIn("idx_skill_runs_skill_status", idx)
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
            args = argparse.Namespace(headers=["Authorization: Bearer x"], cookie="sid=1")
            self.assertEqual(aa._http_headers_from_args(args)["Cookie"], "sid=1")

    def test_no_policy_requires_smoke(self):
        with self.assertRaises(SystemExit):
            aa.main(["run", "127.0.0.1", "--profile", "standard", "--max-steps", "0"])


if __name__ == "__main__":
    unittest.main()

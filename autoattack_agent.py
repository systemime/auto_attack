#!/usr/bin/env python3
"""Small autonomous pentest agent: planner -> tools -> analyst -> report.

No mandatory dependencies. External security tools are used only when present.
"""
from __future__ import annotations

import argparse
import concurrent.futures as futures
import contextlib
import dataclasses
import datetime as dt
import hashlib
import html
import http.server
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import threading
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from pathlib import Path
from typing import Callable, Iterable, Sequence

COMMON_PORTS = (21, 22, 25, 53, 80, 110, 139, 143, 443, 445, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017)
HTTP_PORTS = {80, 443, 8000, 8080, 8443, 3000, 5000, 5601, 9000, 9200}
BASELINE_PATHS = ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt")
EXPOSURE_PATHS = ("/.git/config", "/.env", "/server-status")
SECURITY_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
}
DEFAULT_POLICY = {
    "scope": {"roots": ["127.0.0.1", "localhost"], "deny": []},
    "limits": {
        "max_rounds": 3,
        "max_steps": 200,
        "max_workers": 8,
        "timeout_seconds": 180,
        "max_discovered_targets": 100,
    },
    "tools": {
        "allow": ["subfinder", "httpx", "katana", "nuclei", "nmap"],
        "intrusive": ["sqlmap", "zap-baseline", "nikto"],
    },
    "approval": {"intrusive": False},
}
AGENT_VERSION = "1.0.0"
SKILL_SCHEMA_VERSION = 1


@dataclasses.dataclass(frozen=True)
class Target:
    raw: str
    host: str
    url: str | None
    kind: str  # ip|domain|url

    @property
    def is_url(self) -> bool:
        return self.url is not None


@dataclasses.dataclass
class Observation:
    source: str
    target: str
    kind: str
    data: dict


@dataclasses.dataclass
class Finding:
    title: str
    severity: str
    target: str
    evidence: str
    source: str
    recommendation: str = ""
    confidence: str = "low"
    evidence_path: str = ""
    command_digest: str = ""
    first_seen: str = ""
    last_seen: str = ""
    source_skill: str = ""
    source_tool: str = ""
    validation_status: str = "unverified"
    cve: str = ""
    cwe: str = ""
    references: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class CommandResult:
    tool: str
    target: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    seconds: float
    output_file: str
    digest: str = ""
    cached: bool = False


@dataclasses.dataclass(frozen=True)
class ToolSpec:
    name: str
    phase: str
    description: str
    intrusive: bool
    needs_url: bool
    binary: str
    build: Callable[[Target, Path], list[str] | None]
    parse: Callable[[CommandResult], tuple[list[Observation], list[Finding]]]
    input_schema: dict[str, object] = dataclasses.field(default_factory=dict)
    output_schema: dict[str, object] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class SkillSpec:
    name: str
    version: str
    phase: str
    risk: str
    requires_approval: bool
    description: str
    tool: ToolSpec | None = None
    enabled: bool = True
    source: str = "builtin"
    tags: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()
    priority: int = 50
    needs_url: bool = False
    conflicts: tuple[str, ...] = ()
    depends_on: tuple[str, ...] = ()
    schema_version: int = SKILL_SCHEMA_VERSION
    min_agent_version: str = ""
    max_agent_version: str = ""
    dependency_versions: tuple[tuple[str, str], ...] = ()
    input_schema: dict[str, object] = dataclasses.field(default_factory=dict)
    output_schema: dict[str, object] = dataclasses.field(default_factory=dict)


@dataclasses.dataclass(frozen=True)
class SkillPlan:
    skill: SkillSpec
    target: Target
    status: str
    reason: str
    score: int = 0


@dataclasses.dataclass
class Policy:
    data: dict
    path: str = ""
    sha256: str = ""

    @property
    def roots(self) -> list[str]:
        return [str(x) for x in self.data.get("scope", {}).get("roots", [])]

    @property
    def deny(self) -> list[str]:
        return [str(x) for x in self.data.get("scope", {}).get("deny", [])]

    @property
    def limits(self) -> dict:
        return dict(self.data.get("limits", {}))

    @property
    def allow_tools(self) -> set[str]:
        return {str(x) for x in self.data.get("tools", {}).get("allow", [])}

    @property
    def intrusive_tools(self) -> set[str]:
        return {str(x) for x in self.data.get("tools", {}).get("intrusive", [])}

    @property
    def intrusive_approved(self) -> bool:
        return bool(self.data.get("approval", {}).get("intrusive", False))


class Store:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(
            """
            create table if not exists observations(
              id integer primary key, ts text, source text, target text, kind text,
              digest text unique, data text
            );
            create table if not exists findings(
              id integer primary key, ts text, title text, severity text, target text,
              digest text unique, evidence text, source text, recommendation text,
              confidence text, evidence_path text, command_digest text, first_seen text, last_seen text,
              source_skill text, source_tool text, validation_status text, cve text, cwe text, "references" text
            );
            create table if not exists tasks(
              id integer primary key, ts text, phase text, target text, tool text,
              status text, detail text
            );
            create table if not exists command_cache(
              digest text primary key, ts text, tool text, target text, command text,
              returncode integer, stdout text, stderr text, seconds real, output_file text
            );
            create table if not exists runs(
              run_id text primary key, started_at text, ended_at text, status text,
              argv text, targets text, policy_sha256 text, tool_versions text, counts text, workspace text
            );
            create table if not exists tool_runs(
              id integer primary key, ts text, digest text, tool text, target text, command text,
              timeout real, returncode integer, seconds real, output_file text,
              stdout_summary text, stderr_summary text, status text
            );
            create table if not exists artifacts(
              id integer primary key, ts text, path text unique, kind text, sha256 text, size integer
            );
            create table if not exists events(
              id integer primary key, ts text, kind text, data text
            );
            create table if not exists skills(
              name text primary key, version text, phase text, risk text, enabled integer,
              requires_approval integer, description text, tool text, source text, tags text,
              capabilities text, priority integer, needs_url integer, conflicts text, depends_on text,
              schema_version integer, min_agent_version text, max_agent_version text, dependency_versions text,
              input_schema text, output_schema text
            );
            create table if not exists skill_runs(
              id integer primary key, ts text, skill text, target text, status text,
              tool text, command_digest text, reason text
            );
            create table if not exists approval_requests(
              id integer primary key, ts text, digest text unique, kind text, target text,
              skill text, tool text, risk text, status text, reason text, decided_at text
            );
            create table if not exists job_queue(
              id integer primary key, ts text, updated_at text, digest text unique,
              phase text, target text, tool text, skill text, command text, status text, reason text,
              attempts integer default 0, max_attempts integer default 1,
              lease_owner text, lease_until real default 0, result_digest text, detail text
            );
            create index if not exists idx_approval_skill_target_id on approval_requests(skill,target,id);
            create index if not exists idx_skill_runs_skill_status on skill_runs(skill,status);
            create index if not exists idx_skills_phase_risk_priority on skills(phase,risk,priority);
            create index if not exists idx_events_kind_id on events(kind,id);
            create index if not exists idx_job_queue_claim on job_queue(status,attempts,lease_until);
            """
        )
        self.db.execute("pragma busy_timeout=5000")
        for col, typ in {
            "confidence": "text",
            "evidence_path": "text",
            "command_digest": "text",
            "first_seen": "text",
            "last_seen": "text",
            "source_skill": "text",
            "source_tool": "text",
            "validation_status": "text",
            "cve": "text",
            "cwe": "text",
            "references": "text",
        }.items():
            self.ensure_column("findings", col, typ)
        for col, typ in {
            "source": "text",
            "tags": "text",
            "capabilities": "text",
            "priority": "integer",
            "needs_url": "integer",
            "conflicts": "text",
            "depends_on": "text",
            "schema_version": "integer",
            "min_agent_version": "text",
            "max_agent_version": "text",
            "dependency_versions": "text",
            "input_schema": "text",
            "output_schema": "text",
        }.items():
            self.ensure_column("skills", col, typ)
        self.ensure_column("job_queue", "skill", "text")
        self.db.commit()

    def ensure_column(self, table: str, column: str, typ: str) -> None:
        cols = {row[1] for row in self.db.execute(f'pragma table_info("{table}")')}
        if column not in cols:
            self.db.execute(f'alter table "{table}" add column "{column}" {typ}')

    def add_observation(self, obs: Observation) -> bool:
        digest = _digest([obs.source, obs.target, obs.kind, _json(obs.data)])
        return self._insert(
            "insert into observations(ts,source,target,kind,digest,data) values(?,?,?,?,?,?)",
            (_now(), obs.source, obs.target, obs.kind, digest, _json(obs.data)),
        )

    def add_finding(self, finding: Finding) -> bool:
        now = _now()
        first_seen = finding.first_seen or now
        last_seen = finding.last_seen or now
        digest = _digest([finding.title, finding.severity, finding.target, finding.evidence, finding.source])
        with self.lock:
            try:
                self.db.execute(
                    """insert into findings(ts,title,severity,target,digest,evidence,source,recommendation,
                       confidence,evidence_path,command_digest,first_seen,last_seen,
                       source_skill,source_tool,validation_status,cve,cwe,"references")
                       values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        now,
                        finding.title,
                        finding.severity,
                        finding.target,
                        digest,
                        finding.evidence,
                        finding.source,
                        finding.recommendation,
                        finding.confidence,
                        finding.evidence_path,
                        finding.command_digest,
                        first_seen,
                        last_seen,
                        finding.source_skill or finding.source,
                        finding.source_tool or finding.source,
                        finding.validation_status or "unverified",
                        finding.cve,
                        finding.cwe,
                        json.dumps(finding.references, ensure_ascii=False) if isinstance(finding.references, list) else str(finding.references or ""),
                    ),
                )
                self.db.commit()
                return True
            except sqlite3.IntegrityError:
                self.db.execute("update findings set last_seen=? where digest=?", (last_seen, digest))
                self.db.commit()
                return False

    def add_task(self, phase: str, target: str, tool: str, status: str, detail: str = "") -> None:
        with self.lock:
            self.db.execute(
                "insert into tasks(ts,phase,target,tool,status,detail) values(?,?,?,?,?,?)",
                (_now(), phase, target, tool, status, detail[:4000]),
            )
            self.db.commit()

    def rows(self, table: str, limit: int = 0, offset: int = 0, recent: bool = False) -> list[sqlite3.Row]:
        if table not in {"observations", "findings", "tasks", "command_cache", "runs", "tool_runs", "artifacts", "events", "skills", "skill_runs", "approval_requests", "job_queue"}:
            raise ValueError(table)
        order = "name" if table == "skills" else ("started_at" if table == "runs" else ("ts" if table == "command_cache" else "id"))
        limit = max(0, int(limit or 0))
        offset = max(0, int(offset or 0))
        sql = f"select * from {table} order by {order} {'desc' if recent else 'asc'}"
        if limit:
            sql += f" limit {limit} offset {offset}"
        with self.lock:
            rows = list(self.db.execute(sql))
        return list(reversed(rows)) if recent else rows

    def get_command(self, digest: str) -> CommandResult | None:
        with self.lock:
            row = self.db.execute("select * from command_cache where digest=?", (digest,)).fetchone()
        if not row:
            return None
        return CommandResult(
            row["tool"],
            row["target"],
            json.loads(row["command"]),
            row["returncode"],
            row["stdout"],
            row["stderr"],
            row["seconds"],
            row["output_file"],
            digest,
            True,
        )

    def save_command(self, digest: str, result: CommandResult) -> None:
        with self.lock:
            self.db.execute(
                "insert or replace into command_cache(digest,ts,tool,target,command,returncode,stdout,stderr,seconds,output_file) values(?,?,?,?,?,?,?,?,?,?)",
                (digest, _now(), result.tool, result.target, json.dumps(result.command), result.returncode, result.stdout, result.stderr, result.seconds, result.output_file),
            )
            self.db.commit()

    def add_tool_run(self, digest: str, tool: str, target: str, command: list[str], timeout: float, status: str, result: CommandResult | None = None, detail: str = "") -> None:
        with self.lock:
            self.db.execute(
                """insert into tool_runs(ts,digest,tool,target,command,timeout,returncode,seconds,output_file,stdout_summary,stderr_summary,status)
                   values(?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    _now(),
                    digest,
                    tool,
                    target,
                    json.dumps(command),
                    timeout,
                    result.returncode if result else None,
                    result.seconds if result else None,
                    result.output_file if result else "",
                    (result.stdout if result else detail)[-2000:],
                    (result.stderr if result else "")[-2000:],
                    status,
                ),
            )
            self.db.commit()

    def add_event(self, kind: str, data: dict) -> None:
        with self.lock:
            self.db.execute(
                "insert into events(ts,kind,data) values(?,?,?)",
                (_now(), kind, json.dumps(data, ensure_ascii=False, sort_keys=True)),
            )
            self.db.commit()

    def upsert_skill(self, skill: SkillSpec) -> None:
        with self.lock:
            self.db.execute(
                """insert or replace into skills(name,version,phase,risk,enabled,requires_approval,description,tool,source,tags,capabilities,priority,needs_url,conflicts,depends_on,schema_version,min_agent_version,max_agent_version,dependency_versions,input_schema,output_schema)
                   values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    skill.name,
                    skill.version,
                    skill.phase,
                    skill.risk,
                    int(skill.enabled),
                    int(skill.requires_approval),
                    skill.description,
                    skill.tool.name if skill.tool else "",
                    skill.source,
                    json.dumps(skill.tags, ensure_ascii=False),
                    json.dumps(skill.capabilities, ensure_ascii=False),
                    int(skill.priority),
                    int(skill.needs_url),
                    json.dumps(skill.conflicts, ensure_ascii=False),
                    json.dumps(skill.depends_on, ensure_ascii=False),
                    int(skill.schema_version),
                    skill.min_agent_version,
                    skill.max_agent_version,
                    json.dumps(dict(skill.dependency_versions), ensure_ascii=False),
                    json.dumps(skill.input_schema or (skill.tool.input_schema if skill.tool and skill.tool.input_schema else _default_tool_input_schema(skill.tool)), ensure_ascii=False),
                    json.dumps(skill.output_schema or (skill.tool.output_schema if skill.tool and skill.tool.output_schema else DEFAULT_TOOL_OUTPUT_SCHEMA), ensure_ascii=False),
                ),
            )
            self.db.commit()

    def add_skill_run(self, skill: str, target: str, status: str, tool: str = "", command_digest: str = "", reason: str = "") -> None:
        with self.lock:
            self.db.execute(
                "insert into skill_runs(ts,skill,target,status,tool,command_digest,reason) values(?,?,?,?,?,?,?)",
                (_now(), skill, target, status, tool, command_digest, reason[:1000]),
            )
            self.db.commit()

    def add_approval_request(self, kind: str, target: str, skill: str, tool: str, risk: str, reason: str) -> int:
        digest = _digest([kind, target, skill, tool, risk])
        with self.lock:
            self.db.execute(
                """insert or ignore into approval_requests(ts,digest,kind,target,skill,tool,risk,status,reason,decided_at)
                   values(?,?,?,?,?,?,?,?,?,?)""",
                (_now(), digest, kind, target, skill, tool, risk, "pending", reason[:1000], ""),
            )
            row = self.db.execute("select id from approval_requests where digest=?", (digest,)).fetchone()
            self.db.commit()
        return int(row["id"]) if row else 0

    def approval_status(self, skill: str, target: str) -> str:
        with self.lock:
            row = self.db.execute(
                "select status from approval_requests where skill=? and target=? order by id desc limit 1",
                (skill, target),
            ).fetchone()
        return str(row["status"]) if row else ""

    def decide_approval(self, request_id: int, status: str) -> bool:
        if status not in {"approved", "denied"}:
            raise ValueError(status)
        with self.lock:
            cur = self.db.execute(
                "update approval_requests set status=?, decided_at=? where id=?",
                (status, _now(), request_id),
            )
            self.db.commit()
        return cur.rowcount > 0

    def enqueue_job(self, tool: ToolSpec, target: Target, command: list[str], reason: str = "", max_attempts: int = 1, skill: str = "") -> int:
        digest = _digest(command)
        with self.lock:
            self.db.execute(
                """insert or ignore into job_queue(ts,updated_at,digest,phase,target,tool,skill,command,status,reason,max_attempts)
                   values(?,?,?,?,?,?,?,?,?,?,?)""",
                (_now(), _now(), digest, tool.phase, target.raw, tool.name, skill or tool.name, json.dumps(command), "queued", reason[:1000], max(1, int(max_attempts))),
            )
            row = self.db.execute("select id from job_queue where digest=?", (digest,)).fetchone()
            self.db.commit()
        return int(row["id"]) if row else 0

    def claim_job(self, worker_id: str, lease_seconds: float = 300) -> dict | None:
        now = time.time()
        with self.lock:
            row = self.db.execute(
                """select * from job_queue
                   where (status='queued' and attempts < max_attempts)
                      or (status='running' and lease_until < ?)
                   order by id limit 1""",
                (now,),
            ).fetchone()
            if not row:
                return None
            cur = self.db.execute(
                """update job_queue set status='running', updated_at=?, lease_owner=?,
                   lease_until=?, attempts=attempts+1
                   where id=? and (status='queued' or lease_until < ?)""",
                (_now(), worker_id, now + lease_seconds, row["id"], now),
            )
            self.db.commit()
            if cur.rowcount != 1:
                return None
            row = self.db.execute("select * from job_queue where id=?", (row["id"],)).fetchone()
        return dict(row) if row else None

    def claim_job_by_id(self, job_id: int, worker_id: str, lease_seconds: float = 300) -> dict | None:
        now = time.time()
        with self.lock:
            cur = self.db.execute(
                """update job_queue set status='running', updated_at=?, lease_owner=?,
                   lease_until=?, attempts=attempts+1
                   where id=? and ((status='queued' and attempts < max_attempts) or (status='running' and lease_until < ?))""",
                (_now(), worker_id, now + lease_seconds, job_id, now),
            )
            self.db.commit()
            if cur.rowcount != 1:
                return None
            row = self.db.execute("select * from job_queue where id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def finish_job(self, job_id: int, status: str, result_digest: str = "", detail: str = "", worker_id: str = "") -> bool:
        with self.lock:
            if worker_id:
                cur = self.db.execute(
                    "update job_queue set status=?, updated_at=?, lease_until=0, result_digest=?, detail=? where id=? and lease_owner=?",
                    (status, _now(), result_digest, detail[:1000], job_id, worker_id),
                )
            else:
                cur = self.db.execute(
                    "update job_queue set status=?, updated_at=?, lease_until=0, result_digest=?, detail=? where id=?",
                    (status, _now(), result_digest, detail[:1000], job_id),
                )
            self.db.commit()
        return cur.rowcount == 1

    def requeue_failed_jobs(self, extra_attempts: int = 1) -> int:
        with self.lock:
            cur = self.db.execute(
                "update job_queue set status='queued', updated_at=?, max_attempts=attempts+? where status in ('failed','error')",
                (_now(), max(1, int(extra_attempts))),
            )
            self.db.commit()
        return cur.rowcount

    def save_run(self, manifest: dict) -> None:
        with self.lock:
            self.db.execute(
                """insert or replace into runs(run_id,started_at,ended_at,status,argv,targets,policy_sha256,tool_versions,counts,workspace)
                   values(?,?,?,?,?,?,?,?,?,?)""",
                (
                    manifest.get("run_id"),
                    manifest.get("started_at"),
                    manifest.get("ended_at"),
                    manifest.get("status"),
                    json.dumps(manifest.get("argv", []), ensure_ascii=False),
                    json.dumps(manifest.get("targets", []), ensure_ascii=False),
                    manifest.get("policy_sha256", ""),
                    json.dumps(manifest.get("tool_versions", {}), ensure_ascii=False),
                    json.dumps(manifest.get("counts", {}), ensure_ascii=False),
                    manifest.get("workspace", ""),
                ),
            )
            self.db.commit()

    def add_artifact(self, path: Path, kind: str) -> None:
        if not path.exists():
            return
        with self.lock:
            self.db.execute(
                "insert or replace into artifacts(ts,path,kind,sha256,size) values(?,?,?,?,?)",
                (_now(), str(path), kind, _file_sha256(path), path.stat().st_size),
            )
            self.db.commit()

    def counts(self) -> dict:
        with self.lock:
            base = {name: self.db.execute(f"select count(*) from {name}").fetchone()[0] for name in ("observations", "findings", "tasks", "command_cache", "tool_runs", "artifacts", "events", "skills", "skill_runs", "approval_requests", "job_queue")}
            task_rows = self.db.execute("select status, count(*) c from tasks group by status").fetchall()
            job_rows = self.db.execute("select status, count(*) c from job_queue group by status").fetchall()
        base["tasks_by_status"] = {row["status"]: row["c"] for row in task_rows}
        base["jobs_by_status"] = {row["status"]: row["c"] for row in job_rows}
        return base

    def _insert(self, sql: str, args: tuple) -> bool:
        with self.lock:
            try:
                self.db.execute(sql, args)
                self.db.commit()
                return True
            except sqlite3.IntegrityError:
                return False


class RedisQueue:
    def __init__(self, url: str, name: str):
        self.url = url or os.getenv("AUTOATTACK_REDIS_URL", "redis://127.0.0.1:6379/0")
        self.name = name
        parsed = urllib.parse.urlparse(self.url)
        if parsed.scheme != "redis":
            raise ValueError("redis URL must start with redis://")
        self.host = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or 6379
        self.username = urllib.parse.unquote(parsed.username or "")
        self.password = urllib.parse.unquote(parsed.password or "")
        self.dbno = int((parsed.path or "/0").strip("/") or 0)

    def push(self, job_id: int) -> None:
        self._cmd("RPUSH", self.name, str(job_id))

    def pop(self) -> int | None:
        value = self._cmd("LPOP", self.name)
        return int(value) if value is not None else None

    def ping(self) -> bool:
        return self._cmd("PING") == "PONG"

    def _cmd(self, *parts: object):
        with socket.create_connection((self.host, self.port), timeout=5) as sock:
            f = sock.makefile("rb")
            if self.password:
                auth = ("AUTH", self.username, self.password) if self.username else ("AUTH", self.password)
                sock.sendall(_resp_encode(auth))
                _resp_read(f)
            if self.dbno:
                sock.sendall(_resp_encode(("SELECT", self.dbno)))
                _resp_read(f)
            sock.sendall(_resp_encode(parts))
            return _resp_read(f)


def _resp_encode(parts: Sequence[object]) -> bytes:
    out = [f"*{len(parts)}\r\n".encode()]
    for part in parts:
        data = str(part).encode()
        out += [f"${len(data)}\r\n".encode(), data, b"\r\n"]
    return b"".join(out)


def _resp_read(f):
    prefix = f.read(1)
    if prefix == b"+":
        return f.readline().rstrip(b"\r\n").decode()
    if prefix == b"-":
        raise RuntimeError(f.readline().rstrip(b"\r\n").decode())
    if prefix == b":":
        return int(f.readline())
    if prefix == b"$":
        n = int(f.readline())
        if n < 0:
            return None
        data = f.read(n)
        f.read(2)
        return data.decode()
    if prefix == b"*":
        n = int(f.readline())
        return [_resp_read(f) for _ in range(n)]
    raise RuntimeError("invalid redis response")


def _queue_name(workspace: Path, run_id: str = "", explicit: str = "") -> str:
    return explicit or f"autoattack:jobs:{run_id or hashlib.sha256(str(workspace).encode()).hexdigest()[:16]}"


class Scope:
    def __init__(self, targets: Sequence[Target], allow_out_of_scope: bool = False, policy: Policy | None = None):
        self.targets = list(targets)
        self.allow_out_of_scope = allow_out_of_scope
        roots = policy.roots if policy else [t.host for t in targets]
        deny = policy.deny if policy else []
        self.roots = [_scope_host(x) for x in roots if _scope_host(x)]
        self.deny = [_scope_host(x) for x in deny if _scope_host(x)]
        self.hosts = {t.host.lower() for t in targets}
        self.domains = {h for h in self.roots if not _is_ip_or_cidr(h)}
        self.ips = {h for h in self.roots if _is_ip(h)}
        self.networks = [ipaddress.ip_network(x, strict=False) for x in self.roots if _is_cidr(x)]

    def allowed(self, target: Target | str) -> bool:
        host = target.host if isinstance(target, Target) else normalize_target(target).host
        host = host.lower().strip("[]")
        if _scope_match(host, self.deny):
            return False
        if self.allow_out_of_scope:
            return True
        return _scope_match(host, self.roots)


ALLOWED_SKILL_PHASES = {"recon", "fingerprint", "scan", "validate", "bruteforce", "report", "test"}
ALLOWED_SKILL_RISKS = {"safe", "intrusive"}


def _terms(text: str) -> set[str]:
    return {x.lower() for x in re.findall(r"[a-zA-Z0-9_.:-]{2,}", text or "")}


def _skill_terms(skill: SkillSpec) -> set[str]:
    return _terms(" ".join((skill.name, skill.phase, skill.risk, skill.description, *skill.tags, *skill.capabilities)))


def _list_str(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = re.split(r"[,\s]+", value)
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        raise ValueError("expected string or list")
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = re.sub(r"[^a-zA-Z0-9_.:-]+", "-", str(item).strip().lower()).strip("-")
        if text and text not in seen:
            seen.add(text)
            out.append(text[:80])
    return out


def _list_names(value: object) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = re.split(r"[,\s]+", value)
    if not isinstance(value, Sequence) or isinstance(value, (bytes, bytearray)):
        raise ValueError("expected string or list")
    out: list[str] = []
    seen: set[str] = set()
    for item in value:
        text = str(item).strip()
        if text and not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,120}", text):
            raise ValueError(f"invalid skill name reference: {text}")
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _dependency_specs(value: object) -> tuple[list[str], tuple[tuple[str, str], ...]]:
    if value is None:
        return [], ()
    if isinstance(value, dict):
        items = [{"name": k, "version": v} for k, v in value.items()]
    elif isinstance(value, str):
        items = re.split(r"[,\s]+", value)
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        items = list(value)
    else:
        raise ValueError("expected dependency string, object, or list")
    names: list[str] = []
    versions: dict[str, str] = {}
    seen: set[str] = set()
    for item in items:
        constraint = ""
        if isinstance(item, dict):
            name = str(item.get("name", "")).strip()
            constraint = str(item.get("version") or item.get("constraint") or "").strip()
        else:
            text = str(item).strip()
            match = re.fullmatch(r"([a-zA-Z0-9_.:-]{1,120})(>=|<=|==|>|<)([a-zA-Z0-9_.:-]+)", text)
            name, constraint = (match.group(1), match.group(2) + match.group(3)) if match else (text, "")
        if name and not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,120}", name):
            raise ValueError(f"invalid skill name reference: {name}")
        if constraint and not re.fullmatch(r"(>=|<=|==|>|<)[a-zA-Z0-9_.:-]+", constraint):
            raise ValueError(f"invalid dependency version constraint for {name}: {constraint}")
        if name and name not in seen:
            seen.add(name)
            names.append(name)
        if name and constraint:
            versions[name] = constraint
    return names, tuple(sorted(versions.items()))


def _json_schema(value: object, field: str, default: dict[str, object] | None = None) -> dict[str, object]:
    if value is None:
        return dict(default or {})
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    schema = dict(value)
    if "type" in schema and str(schema.get("type", "")) not in {"object", "array", "string", "number", "integer", "boolean"}:
        raise ValueError(f"{field}.type is invalid")
    return schema


def _version_satisfies(version: str, constraint: str) -> bool:
    match = re.fullmatch(r"(>=|<=|==|>|<)([a-zA-Z0-9_.:-]+)", constraint or "")
    if not match:
        return True
    left, right = _version_tuple(version), _version_tuple(match.group(2))
    return {">=": left >= right, "<=": left <= right, "==": left == right, ">": left > right, "<": left < right}[match.group(1)]


def _bool(value: object, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _default_skill_terms(name: str, phase: str, tool: str = "") -> list[str]:
    return _list_str([phase, tool, *re.split(r"[.:-]+", name)])


def _default_tool_input_schema(tool: ToolSpec | None = None, needs_url: bool = False) -> dict[str, object]:
    required = ["target"]
    properties: dict[str, object] = {
        "target": {"type": "string"},
        "workspace": {"type": "string"},
    }
    if needs_url or (tool and tool.needs_url):
        properties["target"] = {"type": "string", "format": "uri"}
    return {"type": "object", "required": required, "properties": properties}


DEFAULT_TOOL_OUTPUT_SCHEMA: dict[str, object] = {
    "type": "object",
    "properties": {
        "observations": {"type": "array"},
        "findings": {"type": "array"},
    },
}


def _version_tuple(value: str) -> tuple[int, ...]:
    parts = [int(x) for x in re.findall(r"\d+", value or "0")[:3]] or [0]
    return tuple((parts + [0, 0, 0])[:3])


def _check_skill_compat(data: dict, name: str) -> tuple[int, str, str]:
    schema_version = int(data.get("schema_version", SKILL_SCHEMA_VERSION))
    if schema_version != SKILL_SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version for {name}: {schema_version}")
    min_agent = str(data.get("min_agent_version") or "").strip()
    max_agent = str(data.get("max_agent_version") or "").strip()
    current = _version_tuple(AGENT_VERSION)
    if min_agent and current < _version_tuple(min_agent):
        raise ValueError(f"agent version too old for {name}: need >= {min_agent}")
    if max_agent and current > _version_tuple(max_agent):
        raise ValueError(f"agent version too new for {name}: need <= {max_agent}")
    return schema_version, min_agent, max_agent


def migrate_skill_manifest(data: dict) -> dict:
    migrated = dict(data)
    for old, new in {
        "id": "name",
        "summary": "description",
        "stage": "phase",
        "tool_name": "tool",
        "tag": "tags",
        "capability": "capabilities",
        "requires_url": "needs_url",
        "incompatible_with": "conflicts",
    }.items():
        if new not in migrated and old in migrated:
            migrated[new] = migrated[old]
    if "tool" not in migrated and "tools" in migrated:
        tools = _list_names(migrated["tools"])
        if len(tools) > 1:
            raise ValueError("legacy tools must map to a single tool")
        if tools:
            migrated["tool"] = tools[0]
    legacy_intrusive = _bool(migrated.get("intrusive"), False) or _bool(migrated.get("dangerous"), False)
    if "risk" not in migrated and ("intrusive" in migrated or "dangerous" in migrated):
        migrated["risk"] = "intrusive" if legacy_intrusive else "safe"
    if "requires_approval" not in migrated and ("intrusive" in migrated or "dangerous" in migrated):
        migrated["requires_approval"] = legacy_intrusive
    if int(migrated.get("schema_version", SKILL_SCHEMA_VERSION)) == 0:
        migrated["schema_version"] = SKILL_SCHEMA_VERSION
    return migrated


def normalize_skill_manifest(data: dict, source: str = "") -> dict:
    if not isinstance(data, dict):
        raise ValueError("skill manifest must be a JSON object")
    data = migrate_skill_manifest(data)
    name = str(data.get("name", "")).strip()
    if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,120}", name):
        raise ValueError(f"invalid skill name in {source or '<memory>'}")
    description = str(data.get("description", "")).strip()
    if not description:
        raise ValueError(f"missing description for {name}")
    schema_version, min_agent, max_agent = _check_skill_compat(data, name)
    phase = str(data.get("phase") or "scan").strip().lower()
    risk = str(data.get("risk") or "safe").strip().lower()
    if phase not in ALLOWED_SKILL_PHASES:
        raise ValueError(f"invalid phase for {name}: {phase}")
    if risk not in ALLOWED_SKILL_RISKS:
        raise ValueError(f"invalid risk for {name}: {risk}")
    try:
        priority = max(0, min(100, int(data.get("priority", 50))))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"invalid priority for {name}") from exc
    tool = str(data.get("tool") or "").strip()
    if tool and not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,120}", tool):
        raise ValueError(f"invalid tool for {name}: {tool}")
    conflicts = _list_names(data.get("conflicts", []))
    depends_on, dependency_versions = _dependency_specs(data.get("depends_on", data.get("dependencies", [])))
    if name in depends_on:
        raise ValueError(f"skill cannot depend on itself: {name}")
    auto_terms = _default_skill_terms(name, phase, tool)
    return {
        "name": name,
        "schema_version": schema_version,
        "min_agent_version": min_agent,
        "max_agent_version": max_agent,
        "version": str(data.get("version") or "1").strip()[:80],
        "phase": phase,
        "risk": risk,
        "requires_approval": _bool(data.get("requires_approval"), risk == "intrusive"),
        "description": description[:1000],
        "tool": tool,
        "enabled": _bool(data.get("enabled"), True),
        "tags": _list_str(data.get("tags", [])) or auto_terms,
        "capabilities": _list_str(data.get("capabilities", [])) or auto_terms,
        "priority": priority,
        "needs_url": _bool(data.get("needs_url"), False),
        "conflicts": conflicts,
        "depends_on": depends_on,
        "dependency_versions": dict(dependency_versions),
        "input_schema": _json_schema(data.get("input_schema"), "input_schema", _default_tool_input_schema(needs_url=_bool(data.get("needs_url"), False))),
        "output_schema": _json_schema(data.get("output_schema"), "output_schema", DEFAULT_TOOL_OUTPUT_SCHEMA),
    }


def skill_to_manifest(skill: SkillSpec) -> dict:
    input_schema = skill.input_schema or (skill.tool.input_schema if skill.tool and skill.tool.input_schema else _default_tool_input_schema(skill.tool))
    output_schema = skill.output_schema or (skill.tool.output_schema if skill.tool and skill.tool.output_schema else DEFAULT_TOOL_OUTPUT_SCHEMA)
    return {
        "name": skill.name,
        "version": skill.version,
        "schema_version": skill.schema_version,
        "min_agent_version": skill.min_agent_version,
        "max_agent_version": skill.max_agent_version,
        "phase": skill.phase,
        "risk": skill.risk,
        "requires_approval": skill.requires_approval,
        "description": skill.description,
        "tool": skill.tool.name if skill.tool else "",
        "enabled": skill.enabled,
        "source": skill.source,
        "tags": list(skill.tags),
        "capabilities": list(skill.capabilities),
        "priority": skill.priority,
        "needs_url": skill.needs_url,
        "conflicts": list(skill.conflicts),
        "depends_on": list(skill.depends_on),
        "dependency_versions": dict(skill.dependency_versions),
        "input_schema": input_schema,
        "output_schema": output_schema,
        "executable": bool(skill.tool),
    }


def skill_candidate_payload(skill: SkillSpec) -> dict:
    input_schema = skill.input_schema or (skill.tool.input_schema if skill.tool and skill.tool.input_schema else _default_tool_input_schema(skill.tool))
    output_schema = skill.output_schema or (skill.tool.output_schema if skill.tool and skill.tool.output_schema else DEFAULT_TOOL_OUTPUT_SCHEMA)
    return {
        "name": skill.name,
        "schema_version": skill.schema_version,
        "phase": skill.phase,
        "risk": skill.risk,
        "needs_url": skill.needs_url,
        "tags": list(skill.tags),
        "capabilities": list(skill.capabilities),
        "priority": skill.priority,
        "executable": bool(skill.tool),
        "depends_on": list(skill.depends_on),
        "dependency_versions": dict(skill.dependency_versions),
        "contract_sha256": _json_sha256({"input_schema": input_schema, "output_schema": output_schema}),
        "description": skill.description[:300],
    }


def skill_selectors(value: object) -> set[str] | None:
    items = value if isinstance(value, Sequence) and not isinstance(value, str) else str(value or "").split(",")
    selected = {str(x).strip() for x in items if str(x).strip()}
    return selected or None


def skill_selected(skill: SkillSpec, selected: set[str] | None) -> bool:
    if not selected:
        return True
    source = "manifest" if skill.source not in {"builtin", "tool"} else skill.source
    for item in selected:
        if item in {skill.name, skill.tool.name if skill.tool else ""}:
            return True
        if item.startswith("tag:") and item[4:] in skill.tags:
            return True
        if item.startswith(("cap:", "capability:")) and item.split(":", 1)[1] in skill.capabilities:
            return True
        if item.startswith("phase:") and item[6:] == skill.phase:
            return True
        if item.startswith("risk:") and item[5:] == skill.risk:
            return True
        if item.startswith("source:") and item[7:] == source:
            return True
    return False


def skill_list_row(registry: SkillRegistry, skill: SkillSpec, query_terms: set[str] | None = None, include_schema: bool = False) -> dict:
    row = skill_to_manifest(skill)
    if not include_schema:
        input_schema = row.pop("input_schema")
        output_schema = row.pop("output_schema")
        row["contract_sha256"] = _json_sha256({"input_schema": input_schema, "output_schema": output_schema})
    row["available"] = registry.is_available(skill.tool) if skill.tool else True
    row["score"] = registry.match_score(skill, query_terms or set())
    return row


def filter_skill_rows(registry: SkillRegistry, args: argparse.Namespace) -> tuple[list[dict], int]:
    query_terms = _terms(getattr(args, "query", ""))
    rows: list[dict] = []
    for skill in registry.all():
        source = "manifest" if skill.source not in {"builtin", "tool"} else skill.source
        if getattr(args, "phase", "") and skill.phase != args.phase:
            continue
        if getattr(args, "risk", "") and skill.risk != args.risk:
            continue
        if getattr(args, "source", "") and source != args.source:
            continue
        if getattr(args, "state", "all") == "enabled" and not skill.enabled:
            continue
        if getattr(args, "state", "all") == "disabled" and skill.enabled:
            continue
        if getattr(args, "executable", False) and not skill.tool:
            continue
        if getattr(args, "tag", "") and args.tag not in skill.tags:
            continue
        if getattr(args, "capability", "") and args.capability not in skill.capabilities:
            continue
        text = " ".join((skill.name, skill.phase, skill.risk, skill.description, *skill.tags, *skill.capabilities, *skill.depends_on, *dict(skill.dependency_versions).values())).lower()
        if query_terms and not all(term in text for term in query_terms):
            continue
        row = skill_list_row(registry, skill, query_terms)
        if getattr(args, "available", False) and not row["available"]:
            continue
        rows.append(row)
    sort_key = getattr(args, "sort", "priority")
    if sort_key == "name":
        rows.sort(key=lambda r: r["name"])
    elif sort_key == "phase":
        rows.sort(key=lambda r: (r["phase"], -int(r["priority"]), r["name"]))
    else:
        rows.sort(key=lambda r: (-int(r["score"]), -int(r["priority"]), r["name"]))
    total = len(rows)
    offset = max(0, int(getattr(args, "offset", 0) or 0))
    limit = max(0, int(getattr(args, "limit", 0) or 0))
    rows = rows[offset: offset + limit] if limit else rows[offset:]
    return rows, total


def skill_detail(registry: SkillRegistry, name: str, include_raw: bool = False) -> dict:
    skill = registry.get(name) or next((s for s in registry.all() if s.tool and s.tool.name == name), None)
    if not skill:
        return {"name": name, "ok": False, "error": "unknown skill"}
    detail = skill_list_row(registry, skill, include_schema=True)
    detail["ok"] = True
    if skill.tool:
        detail["tool_detail"] = {"name": skill.tool.name, "phase": skill.tool.phase, "binary": skill.tool.binary, "intrusive": skill.tool.intrusive, "needs_url": skill.tool.needs_url}
    if include_raw and skill.source not in {"builtin", "tool"}:
        with contextlib.suppress(Exception):
            detail["raw_manifest"] = json.loads(Path(skill.source).read_text(encoding="utf-8"))
    return detail


def _inc_count(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def skill_routing_reason_counts(skills: SkillRegistry, target: Target, profile: str, selected: set[str] | None = None, policy: Policy | None = None, plans: Sequence[SkillPlan] = (), candidate_names: set[str] | None = None) -> dict[str, int]:
    plan_names = {plan.skill.name for plan in plans}
    conflicts = {name for plan in plans for name in plan.skill.conflicts}
    conflict_names = (conflicts & (candidate_names if candidate_names is not None else {s.name for s in skills.candidates(target, profile, selected, policy, query=target.raw, executable_only=True)})) - plan_names
    counts: dict[str, int] = {}
    for _ in conflict_names:
        _inc_count(counts, "conflict")
    for skill in skills.all():
        if skill.name in plan_names or skill.name in conflict_names:
            continue
        reason = "builtin_internal" if skill.name == "python-recon" else ("metadata_only" if not skill.tool else skills.skip_reason(skill, target, profile, selected, policy))
        if reason:
            _inc_count(counts, reason)
    return dict(sorted(counts.items()))


def explain_skill_routing(skills: SkillRegistry, target: Target, profile: str, allow_intrusive: bool, selected: set[str] | None = None, policy: Policy | None = None, limit: int = 30, query: str = "", include_skipped: int = 20) -> dict:
    query_terms = _terms(query or target.raw)
    candidates = skills.candidates(target, profile, selected, policy, limit, query or target.raw, executable_only=True)
    router = SkillRouter(skills)
    plans = router.plan(target, profile, allow_intrusive, selected, policy, limit, query or target.raw)
    plan_names = {plan.skill.name for plan in plans}
    candidate_names = {skill.name for skill in candidates}
    reason_counts = skill_routing_reason_counts(skills, target, profile, selected, policy, plans, candidate_names)
    conflicts = {name for plan in plans for name in plan.skill.conflicts}
    skipped: list[dict] = []
    skipped_names: set[str] = set()
    for name in sorted((conflicts & candidate_names) - plan_names):
        skipped.append({"skill": name, "reason": "conflict"})
        skipped_names.add(name)
    for skill in skills.all():
        if len(skipped) >= include_skipped:
            break
        if skill.name in plan_names or skill.name in skipped_names:
            continue
        reason = "builtin_internal" if skill.name == "python-recon" else ("metadata_only" if not skill.tool else skills.skip_reason(skill, target, profile, selected, policy))
        if reason:
            skipped.append({"skill": skill.name, "reason": reason})
            skipped_names.add(skill.name)
    return {
        "target": {"raw": target.raw, "kind": target.kind, "is_url": target.is_url},
        "profile": profile,
        "selected": sorted(selected or []),
        "query": query,
        "skillset_sha256": skills.skillset_digest,
        "counts": {"total": len(skills.all()), "candidates": len(candidates), "planned": len(plans), "skipped_reported": len(skipped)},
        "skipped_reason_counts": reason_counts,
        "candidates": [skill_candidate_payload(skill) | {"score": skills.match_score(skill, query_terms)} for skill in candidates],
        "plans": [{
            "skill": plan.skill.name,
            "tool": plan.skill.tool.name if plan.skill.tool else "",
            "status": plan.status,
            "score": plan.score,
            "risk": plan.skill.risk,
            "reason": plan.reason,
            "conflicts": list(plan.skill.conflicts),
            "depends_on": list(plan.skill.depends_on),
        } for plan in plans],
        "skipped": skipped,
    }


def eval_skill_routing(skills: SkillRegistry, path: Path, policy: Policy | None = None, fail_under: float = 100.0) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    cases = data.get("cases", data) if isinstance(data, dict) else data
    if not isinstance(cases, list):
        raise ValueError("eval file must be a JSON list or {\"cases\": [...]}")
    results = []
    for i, case in enumerate(cases, 1):
        if not isinstance(case, dict):
            raise ValueError(f"case {i} must be an object")
        target = normalize_target(str(case["target"]))
        explained = explain_skill_routing(
            skills,
            target,
            str(case.get("profile", "standard")),
            _bool(case.get("approve_intrusive"), False),
            skill_selectors(case.get("tools", "")),
            policy,
            int(case.get("limit", 30)),
            str(case.get("query", "")),
            0,
        )
        planned = {x["skill"] for x in explained["plans"]}
        candidates = {x["name"] for x in explained["candidates"]}
        expect_plans = set(_list_names(case.get("expect_plans", case.get("expect", []))))
        reject_plans = set(_list_names(case.get("reject_plans", case.get("reject", []))))
        expect_candidates = set(_list_names(case.get("expect_candidates", [])))
        reject_candidates = set(_list_names(case.get("reject_candidates", [])))
        row = {
            "name": str(case.get("name") or f"case-{i}"),
            "ok": True,
            "missing_plans": sorted(expect_plans - planned),
            "unexpected_plans": sorted(reject_plans & planned),
            "missing_candidates": sorted(expect_candidates - candidates),
            "unexpected_candidates": sorted(reject_candidates & candidates),
            "planned": sorted(planned),
            "candidates": sorted(candidates),
        }
        row["ok"] = not (row["missing_plans"] or row["unexpected_plans"] or row["missing_candidates"] or row["unexpected_candidates"])
        results.append(row)
    passed = sum(1 for x in results if x["ok"])
    total = len(results)
    pass_rate = (passed / total * 100.0) if total else 100.0
    return {
        "ok": pass_rate >= fail_under,
        "total": total,
        "passed": passed,
        "failed": total - passed,
        "pass_rate": round(pass_rate, 2),
        "fail_under": fail_under,
        "skillset_sha256": skills.skillset_digest,
        "cases": results,
    }


def skill_stats(store: Store, limit: int = 20, max_events: int = 1000) -> dict:
    with store.lock:
        skill_rows = store.db.execute("select skill,status,count(*) c from skill_runs group by skill,status").fetchall()
        runtime_rows = store.db.execute(
            """select sr.skill skill, count(*) c, sum(tr.seconds) total, avg(tr.seconds) avg, max(tr.seconds) max
               from skill_runs sr join tool_runs tr on sr.command_digest=tr.digest
               where tr.seconds is not null and sr.status in ('done','failed','error','cached')
               group by sr.skill"""
        ).fetchall()
        routing_rows = store.db.execute("select data from events where kind='skill_routing_summary' order by id desc limit ?", (max(0, int(max_events or 0)) or 1000,)).fetchall()
    by_skill: dict[str, dict] = {}
    status_totals: dict[str, int] = {}
    for row in skill_rows:
        skill = row["skill"] or ""
        status = row["status"] or ""
        count = int(row["c"])
        item = by_skill.setdefault(skill, {"skill": skill, "total": 0, "status": {}})
        item["total"] += count
        item["status"][status] = count
        status_totals[status] = status_totals.get(status, 0) + count
    runtime = {"count": 0, "seconds_total": 0.0, "seconds_avg": 0.0, "seconds_max": 0.0}
    for row in runtime_rows:
        skill = row["skill"] or ""
        count = int(row["c"] or 0)
        total = float(row["total"] or 0.0)
        item = by_skill.setdefault(skill, {"skill": skill, "total": 0, "status": {}})
        item["runtime"] = {"count": count, "seconds_total": round(total, 3), "seconds_avg": round(float(row["avg"] or 0.0), 3), "seconds_max": round(float(row["max"] or 0.0), 3)}
        runtime["count"] += count
        runtime["seconds_total"] += total
        runtime["seconds_max"] = max(runtime["seconds_max"], float(row["max"] or 0.0))
    if runtime["count"]:
        runtime["seconds_avg"] = runtime["seconds_total"] / runtime["count"]
    runtime = {k: (round(v, 3) if isinstance(v, float) else v) for k, v in runtime.items()}
    plan_status: dict[str, int] = {}
    skipped_reason_counts: dict[str, int] = {}
    routed_targets = planned = candidates = 0
    for row in routing_rows:
        with contextlib.suppress(Exception):
            data = json.loads(row["data"])
            routed_targets += 1
            planned += int(data.get("planned", 0) or 0)
            candidates += int(data.get("candidates", 0) or 0)
            for key, value in data.get("plan_status", {}).items():
                plan_status[str(key)] = plan_status.get(str(key), 0) + int(value)
            for key, value in data.get("skipped_reason_counts", {}).items():
                skipped_reason_counts[str(key)] = skipped_reason_counts.get(str(key), 0) + int(value)
    top = sorted(by_skill.values(), key=lambda x: (-int(x["total"]), x["skill"]))
    limit = max(0, int(limit or 0))
    return {
        "skill_runs": {"total": sum(status_totals.values()), "by_status": dict(sorted(status_totals.items())), "top_skills": top[:limit] if limit else top},
        "runtime": runtime,
        "routing": {
            "events": routed_targets,
            "candidates": candidates,
            "planned": planned,
            "plan_status": dict(sorted(plan_status.items())),
            "skipped_reason_counts": dict(sorted(skipped_reason_counts.items())),
        },
    }


def skill_stats_workspaces(path: Path, limit: int = 20, max_events: int = 1000, recursive: bool = False) -> dict:
    dbs = sorted(path.rglob("state.sqlite3") if recursive else path.glob("*/state.sqlite3")) if path.is_dir() and not (path / "state.sqlite3").exists() else [path / "state.sqlite3"]
    total = {"workspaces": [], "skill_runs": {"total": 0, "by_status": {}, "top_skills": []}, "runtime": {"count": 0, "seconds_total": 0.0, "seconds_avg": 0.0, "seconds_max": 0.0}, "routing": {"events": 0, "candidates": 0, "planned": 0, "plan_status": {}, "skipped_reason_counts": {}}}
    by_skill: dict[str, dict] = {}
    for db in [p for p in dbs if p.exists()]:
        stats = skill_stats(Store(db), 0, max_events)
        total["workspaces"].append(str(db.parent))
        total["skill_runs"]["total"] += stats["skill_runs"]["total"]
        for key, value in stats["skill_runs"]["by_status"].items():
            total["skill_runs"]["by_status"][key] = total["skill_runs"]["by_status"].get(key, 0) + value
        for item in stats["skill_runs"]["top_skills"]:
            merged = by_skill.setdefault(item["skill"], {"skill": item["skill"], "total": 0, "status": {}})
            merged["total"] += item["total"]
            for key, value in item["status"].items():
                merged["status"][key] = merged["status"].get(key, 0) + value
        total["runtime"]["count"] += stats["runtime"]["count"]
        total["runtime"]["seconds_total"] += stats["runtime"]["seconds_total"]
        total["runtime"]["seconds_max"] = max(total["runtime"]["seconds_max"], stats["runtime"]["seconds_max"])
        for key in ("events", "candidates", "planned"):
            total["routing"][key] += stats["routing"][key]
        for field in ("plan_status", "skipped_reason_counts"):
            for key, value in stats["routing"][field].items():
                total["routing"][field][key] = total["routing"][field].get(key, 0) + value
    if total["runtime"]["count"]:
        total["runtime"]["seconds_avg"] = total["runtime"]["seconds_total"] / total["runtime"]["count"]
    total["runtime"] = {k: (round(v, 3) if isinstance(v, float) else v) for k, v in total["runtime"].items()}
    total["skill_runs"]["by_status"] = dict(sorted(total["skill_runs"]["by_status"].items()))
    total["skill_runs"]["top_skills"] = sorted(by_skill.values(), key=lambda x: (-int(x["total"]), x["skill"]))[:max(0, int(limit or 0)) or None]
    total["routing"]["plan_status"] = dict(sorted(total["routing"]["plan_status"].items()))
    total["routing"]["skipped_reason_counts"] = dict(sorted(total["routing"]["skipped_reason_counts"].items()))
    return total


def skill_trace(store: Store, target: str = "", skill: str = "", limit: int = 200) -> dict:
    timeline: list[dict] = []
    for row in store.rows("events", limit, recent=True):
        with contextlib.suppress(Exception):
            data = json.loads(row["data"])
            if target and target not in str(data.get("target", "")) and target not in str(data.get("targets", "")):
                continue
            if skill and row["kind"] != "skill_routing_summary" and skill not in str(data.get("skill", "")) and skill not in str(data.get("selected", "")):
                continue
            timeline.append({"ts": row["ts"], "type": "event", "kind": row["kind"], "data": data})
    for row in store.rows("skill_runs", limit, recent=True):
        if target and target not in row["target"]:
            continue
        if skill and skill != row["skill"]:
            continue
        timeline.append({"ts": row["ts"], "type": "skill_run", "skill": row["skill"], "target": row["target"], "status": row["status"], "tool": row["tool"], "command_digest": row["command_digest"], "reason": row["reason"]})
    timeline.sort(key=lambda x: x["ts"])
    return {"target": target, "skill": skill, "events": timeline[-max(0, int(limit or 0)):] if limit else timeline}


def _dependency_cycle(graph: dict[str, Sequence[str]]) -> list[str]:
    visiting: list[str] = []
    visited: set[str] = set()

    def walk(name: str) -> list[str]:
        if name in visiting:
            return visiting[visiting.index(name):] + [name]
        if name in visited:
            return []
        visiting.append(name)
        for dep in graph.get(name, ()):
            if dep in graph:
                cycle = walk(dep)
                if cycle:
                    return cycle
        visiting.pop()
        visited.add(name)
        return []

    for name in graph:
        cycle = walk(name)
        if cycle:
            return cycle
    return []


class ToolRegistry:
    def __init__(self):
        self.tools = _default_tools()
        self._availability_cache: dict[tuple[str, str], bool] = {}
        self._version_cache: dict[tuple[str, str], dict] = {}

    def is_available(self, tool: ToolSpec) -> bool:
        key = (tool.name, tool.binary)
        if key not in self._availability_cache:
            self._availability_cache[key] = tool_available(tool)
        return self._availability_cache[key]

    def version(self, tool: ToolSpec) -> dict:
        key = (tool.name, tool.binary)
        if key not in self._version_cache:
            self._version_cache[key] = tool_version(tool)
        return self._version_cache[key]

    def available(self) -> list[ToolSpec]:
        return [t for t in self.tools if self.is_available(t)]

    def get(self, name: str) -> ToolSpec | None:
        return next((t for t in self.tools if t.name == name), None)

    def plan(self, target: Target, profile: str, allow_intrusive: bool, selected: set[str] | None = None, policy: Policy | None = None) -> list[ToolSpec]:
        tools = self.available()
        if selected:
            tools = [t for t in tools if t.name in selected]
        if policy and policy.allow_tools:
            tools = [t for t in tools if t.name in policy.allow_tools]
        if profile == "quick":
            tools = [t for t in tools if t.phase in {"recon", "fingerprint"}]
        elif profile == "deep":
            pass
        else:
            tools = [t for t in tools if t.phase != "bruteforce"]
        if policy:
            tools = [t for t in tools if not (t.intrusive or t.name in policy.intrusive_tools) or allow_intrusive]
        elif not allow_intrusive:
            tools = [t for t in tools if not t.intrusive]
        return [t for t in tools if not (t.needs_url and not target.is_url)]


class SkillRegistry:
    def __init__(self, tool_registry: ToolRegistry | None = None, config_path: Path | None = None, skills_dir: Path | None = None):
        self.tool_registry = tool_registry or ToolRegistry()
        self.config_path = config_path or Path(os.getenv("AUTOATTACK_SKILLS_CONFIG", ".autoattack_skills.json"))
        self.skills_dir = skills_dir or (Path(os.getenv("AUTOATTACK_SKILLS_DIR")) if os.getenv("AUTOATTACK_SKILLS_DIR") else None)
        self.disabled = self._load_disabled()
        self._refresh()

    def _load_disabled(self) -> set[str]:
        with contextlib.suppress(Exception):
            return {str(x) for x in json.loads(self.config_path.read_text()).get("disabled", [])}
        return set()

    def _save(self) -> None:
        write_json_atomic(self.config_path, {"disabled": sorted(self.disabled)})

    def _refresh(self) -> None:
        skills = [
            SkillSpec("python-recon", "1", "recon", "safe", False, "builtin DNS/TCP/HTTP baseline recon", enabled="python-recon" not in self.disabled, source="builtin", tags=("builtin", "recon"), capabilities=("dns", "tcp", "http"), priority=70)
        ]
        for tool in self.tool_registry.tools:
            risk = "intrusive" if tool.intrusive else "safe"
            skills.append(SkillSpec(tool.name, "1", tool.phase, risk, tool.intrusive, tool.description, tool, tool.name not in self.disabled, "tool", (tool.phase,), (tool.name, tool.phase), 50, tool.needs_url, (), (), input_schema=tool.input_schema or _default_tool_input_schema(tool), output_schema=tool.output_schema or DEFAULT_TOOL_OUTPUT_SCHEMA))
        skills.extend(self._load_manifest_skills())
        by_name: dict[str, SkillSpec] = {}
        duplicates: list[str] = []
        by_tool: dict[str, list[SkillSpec]] = {}
        by_tag: dict[str, list[SkillSpec]] = {}
        by_capability: dict[str, list[SkillSpec]] = {}
        by_phase: dict[str, list[SkillSpec]] = {}
        by_risk: dict[str, list[SkillSpec]] = {}
        by_source: dict[str, list[SkillSpec]] = {}
        by_term: dict[str, list[SkillSpec]] = {}
        term_df: Counter[str] = Counter()
        for skill in skills:
            if skill.name in by_name:
                duplicates.append(skill.name)
            by_name[skill.name] = skill
            if skill.tool:
                by_tool.setdefault(skill.tool.name, []).append(skill)
            for tag in skill.tags:
                by_tag.setdefault(tag, []).append(skill)
            for cap in skill.capabilities:
                by_capability.setdefault(cap, []).append(skill)
            by_phase.setdefault(skill.phase, []).append(skill)
            by_risk.setdefault(skill.risk, []).append(skill)
            source = "manifest" if skill.source not in {"builtin", "tool"} else skill.source
            by_source.setdefault(source, []).append(skill)
            terms = _skill_terms(skill)
            term_df.update(terms)
            for term in terms:
                by_term.setdefault(term, []).append(skill)
        if duplicates:
            raise ValueError("duplicate skill names: " + ", ".join(sorted(set(duplicates))))
        for bucket in (by_tool, by_tag, by_capability, by_phase, by_risk, by_source, by_term):
            for values in bucket.values():
                values.sort(key=lambda x: (-x.priority, x.name))
        self._skills = sorted(skills, key=lambda x: (-x.priority, x.name))
        self._by_name = by_name
        self._by_tool = by_tool
        self._by_tag = by_tag
        self._by_capability = by_capability
        self._by_phase = by_phase
        self._by_risk = by_risk
        self._by_source = by_source
        self._by_term = by_term
        self._term_weight = {term: max(1, min(50, len(skills) // count)) for term, count in term_df.items() if count}
        self._skillset_digest = _json_sha256({"skills": [skill_to_manifest(s) for s in self._skills]})

    def _load_manifest_skills(self) -> list[SkillSpec]:
        if not self.skills_dir or not self.skills_dir.exists():
            return []
        out: list[SkillSpec] = []
        for path in sorted(self.skills_dir.rglob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            spec = normalize_skill_manifest(data, source=str(path))
            tool = self.tool_registry.get(spec["tool"]) if spec.get("tool") and hasattr(self.tool_registry, "get") else next((t for t in self.tool_registry.tools if t.name == spec["tool"]), None)
            if spec.get("tool") and not tool:
                raise ValueError(f"unknown tool for {spec['name']}: {spec['tool']}")
            risk = "intrusive" if spec["risk"] == "intrusive" or bool(tool and tool.intrusive) else "safe"
            out.append(SkillSpec(
                spec["name"], spec["version"], spec["phase"], risk, bool(spec["requires_approval"] or risk == "intrusive"),
                spec["description"], tool, spec["name"] not in self.disabled and bool(spec.get("enabled", True)),
                str(path), tuple(spec.get("tags", [])), tuple(spec.get("capabilities", [])), int(spec.get("priority", 50)),
                bool(spec.get("needs_url", False) or (tool and tool.needs_url)), tuple(spec.get("conflicts", [])), tuple(spec.get("depends_on", [])),
                int(spec.get("schema_version", SKILL_SCHEMA_VERSION)), str(spec.get("min_agent_version", "")), str(spec.get("max_agent_version", "")),
                tuple(sorted((spec.get("dependency_versions") or {}).items())), spec.get("input_schema", {}), spec.get("output_schema", {}),
            ))
        return out

    @property
    def skillset_digest(self) -> str:
        return self._skillset_digest

    def all(self) -> list[SkillSpec]:
        return list(self._skills)

    def _selected_pool(self, selected: set[str] | None) -> list[SkillSpec] | None:
        if not selected:
            return None
        picked: dict[str, SkillSpec] = {}
        for item in selected:
            skill = self._by_name.get(item)
            if skill:
                picked[skill.name] = skill
            for skill in self._by_tool.get(item, ()):
                picked[skill.name] = skill
            for prefix, bucket in (("tag:", self._by_tag), ("cap:", self._by_capability), ("capability:", self._by_capability), ("phase:", self._by_phase), ("risk:", self._by_risk), ("source:", self._by_source)):
                if item.startswith(prefix):
                    for skill in bucket.get(item.split(":", 1)[1], ()):
                        picked[skill.name] = skill
        return sorted(picked.values(), key=lambda x: (-x.priority, x.name))

    def candidates(self, target: Target, profile: str, selected: set[str] | None = None, policy: Policy | None = None, limit: int | None = None, query: str = "", executable_only: bool = False) -> list[SkillSpec]:
        query_terms = _terms(query)
        scored: list[tuple[int, SkillSpec]] = []
        selected_pool = self._selected_pool(selected)
        if selected_pool is not None:
            pool = selected_pool
        elif profile == "quick":
            pool = [s for phase in ("recon", "fingerprint") for s in self._by_phase.get(phase, [])]
        elif profile != "deep":
            pool = [s for phase, values in self._by_phase.items() if phase != "bruteforce" for s in values]
        else:
            pool = self._skills
        if query_terms:
            query_hits = {skill.name for term in query_terms for skill in self._by_term.get(term, ())}
            if query_hits:
                pool = [skill for skill in pool if skill.name in query_hits]
        for skill in pool:
            if executable_only and not skill.tool:
                continue
            if not skill_selected(skill, selected):
                continue
            reason = self.skip_reason(skill, target, profile, selected, policy)
            if reason:
                continue
            score = self.match_score(skill, query_terms)
            scored.append((score, skill))
        scored.sort(key=lambda item: (-item[0], -item[1].priority, item[1].name))
        skills = [skill for _, skill in scored]
        return skills[:limit] if limit else skills

    def match_score(self, skill: SkillSpec, query_terms: set[str]) -> int:
        score = int(skill.priority)
        terms = _skill_terms(skill)
        score += sum(10 * self._term_weight.get(term, 1) for term in query_terms if term in terms)
        return score

    def skip_reason(self, skill: SkillSpec, target: Target, profile: str, selected: set[str] | None = None, policy: Policy | None = None) -> str:
        tool = skill.tool
        if not skill.enabled:
            return "disabled"
        if not skill_selected(skill, selected):
            return "not selected"
        dep_reason = self._dependency_skip_reason(skill, target, profile, policy)
        if dep_reason:
            return dep_reason
        if tool and not self.is_available(tool):
            return "unavailable"
        policy_name = tool.name if tool else skill.name
        if policy and policy.allow_tools and policy_name not in policy.allow_tools and skill.name not in policy.allow_tools:
            return "not allowed by policy"
        if profile == "quick" and skill.phase not in {"recon", "fingerprint"}:
            return "profile"
        if profile != "deep" and skill.phase == "bruteforce":
            return "profile"
        if skill.needs_url and not target.is_url:
            return "needs url"
        return ""

    def _dependency_skip_reason(self, skill: SkillSpec, target: Target, profile: str, policy: Policy | None = None) -> str:
        version_constraints = dict(skill.dependency_versions)
        for name in skill.depends_on:
            dep = self.get(name)
            if not dep:
                return f"missing dependency: {name}"
            constraint = version_constraints.get(name, "")
            if constraint and not _version_satisfies(dep.version, constraint):
                return f"dependency version mismatch: {name} {constraint} (found {dep.version})"
            if not dep.enabled:
                return f"disabled dependency: {name}"
            dep_tool = dep.tool
            if dep_tool and not self.is_available(dep_tool):
                return f"unavailable dependency: {name}"
            dep_policy_name = dep_tool.name if dep_tool else dep.name
            if policy and policy.allow_tools and dep_policy_name not in policy.allow_tools and dep.name not in policy.allow_tools:
                return f"dependency not allowed by policy: {name}"
            if profile == "quick" and dep.phase not in {"recon", "fingerprint"}:
                return f"dependency filtered by profile: {name}"
            if profile != "deep" and dep.phase == "bruteforce":
                return f"dependency filtered by profile: {name}"
            if dep.needs_url and not target.is_url:
                return f"dependency needs url: {name}"
        return ""

    def is_available(self, tool: ToolSpec) -> bool:
        return getattr(self.tool_registry, "is_available", tool_available)(tool)

    def get(self, name: str) -> SkillSpec | None:
        return self._by_name.get(name)

    def enable(self, name: str, enabled: bool) -> bool:
        if not self.get(name):
            return False
        if enabled:
            self.disabled.discard(name)
        else:
            self.disabled.add(name)
        self._save()
        self._refresh()
        return True

    def test(self, name: str) -> dict:
        skill = self.get(name)
        if not skill:
            return {"name": name, "ok": False, "error": "unknown skill"}
        build_ok = parse_ok = True
        available = True
        if skill.tool:
            available = self.is_available(skill.tool)
            sample = normalize_target("https://example.com/?id=1") if skill.tool.needs_url else normalize_target("example.com")
            build_ok = skill.tool.build(sample, Path(".")) is not None
            parse_ok = isinstance(skill.tool.parse(CommandResult(skill.tool.name, sample.raw, [], 0, "", "", 0, "")), tuple)
        return {
            "name": skill.name,
            "version": skill.version,
            "enabled": skill.enabled,
            "available": available,
            "build_ok": build_ok,
            "parse_ok": parse_ok,
            "manifest_ok": True,
            "ok": bool(skill.enabled and build_ok and parse_ok and (available or skill.tool is None)),
        }



class SkillRouter:
    def __init__(self, skills: SkillRegistry, store: Store | None = None):
        self.skills = skills
        self.store = store

    def plan(self, target: Target, profile: str, allow_intrusive: bool, selected: set[str] | None = None, policy: Policy | None = None, limit: int | None = None, query: str = "") -> list[SkillPlan]:
        plans: list[SkillPlan] = []
        blocked: set[str] = set()
        for skill in self.skills.candidates(target, profile, selected, policy, limit, query, executable_only=True):
            if skill.name in blocked:
                continue
            tool = skill.tool
            if not tool:
                continue
            intrusive = skill.risk == "intrusive" or bool(tool and tool.intrusive) or bool(policy and ((tool and tool.name in policy.intrusive_tools) or skill.name in policy.intrusive_tools))
            plan_skill = dataclasses.replace(skill, risk="intrusive", requires_approval=True) if intrusive and skill.risk != "intrusive" else skill
            status = "ready"
            if intrusive and not allow_intrusive:
                decision = self.store.approval_status(skill.name, target.raw) if self.store else ""
                status = "ready" if decision == "approved" else ("denied" if decision == "denied" else "approval_required")
            score = self.skills.match_score(plan_skill, _terms(query)) + (40 if status == "ready" else 0)
            plans.append(SkillPlan(plan_skill, target, status, f"{plan_skill.phase}:{profile}", score))
            blocked.update(plan_skill.conflicts)
        return plans

    def _skip_reason(self, skill: SkillSpec, target: Target, profile: str, selected: set[str] | None, policy: Policy | None) -> str:
        return self.skills.skip_reason(skill, target, profile, selected, policy)



class Agent:
    def __init__(self, targets: Sequence[Target], workspace: Path, args: argparse.Namespace):
        self.targets = list(targets)
        self.workspace = workspace
        self.args = args
        self.policy: Policy | None = getattr(args, "policy_obj", None)
        self.scope = Scope(self.targets, args.allow_out_of_scope, self.policy)
        self.registry = ToolRegistry()
        self.store = Store(workspace / "state.sqlite3")
        self.skill_registry = SkillRegistry(self.registry, skills_dir=Path(getattr(args, "skills_dir", "") or os.getenv("AUTOATTACK_SKILLS_DIR", "")) if (getattr(args, "skills_dir", "") or os.getenv("AUTOATTACK_SKILLS_DIR", "")) else None)
        self.args.skillset_sha256 = self.skill_registry.skillset_digest
        self.router = SkillRouter(self.skill_registry, self.store)
        for skill in self.skill_registry.all():
            self.store.upsert_skill(skill)
        self.raw_dir = workspace / "raw"
        self.raw_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> None:
        selected = skill_selectors(self.args.tools)
        seen: set[str] = set()
        pending = list(self.targets)
        steps_left = self.args.max_steps
        skipped: set[str] = set()
        redis_queue = None
        if getattr(self.args, "execution_mode", "local") == "queue" and getattr(self.args, "queue_backend", "sqlite") == "redis":
            redis_queue = RedisQueue(getattr(self.args, "redis_url", ""), getattr(self.args, "queue_name", ""))
            redis_queue.ping()
        for round_no in range(max(1, self.args.rounds)):
            for target in pending:
                if target.host not in skipped and not self.scope.allowed(target):
                    skipped.add(target.host)
                    self.store.add_task("scope", target.raw, "policy", "skipped", "out of scope or denied")
            current = [t for t in pending if self.scope.allowed(t) and t.host not in seen]
            if not current:
                break
            self.store.add_task("plan", ",".join(t.raw for t in current), "planner", "round", f"round={round_no + 1}")
            self.store.add_event("plan_round", {"round": round_no + 1, "targets": [t.raw for t in current]})
            for target in current:
                seen.add(target.host)
                python_skill = self.skill_registry.get("python-recon")
                if not python_skill or python_skill.enabled:
                    self._python_recon(target)
                else:
                    self.store.add_task("recon", target.raw, "python", "skipped", "python-recon disabled")
                    self.store.add_skill_run("python-recon", target.raw, "skipped", "python", reason="disabled")

            jobs: list[tuple[ToolSpec, Target, str]] = []
            job_keys: set[tuple[str, str]] = set()
            for target in current:
                candidates = self.skill_registry.candidates(target, self.args.profile, selected, self.policy, executable_only=True)
                plans = self.router.plan(target, self.args.profile, self.args.allow_intrusive, selected, self.policy)
                status_counts: dict[str, int] = {}
                for plan in plans:
                    _inc_count(status_counts, plan.status)
                self.store.add_event("skill_routing_summary", {
                    "target": target.raw,
                    "profile": self.args.profile,
                    "selected": sorted(selected or []),
                    "candidates": len(candidates),
                    "planned": len(plans),
                    "plan_status": dict(sorted(status_counts.items())),
                    "skipped_reason_counts": skill_routing_reason_counts(self.skill_registry, target, self.args.profile, selected, self.policy, plans, {s.name for s in candidates}),
                    "skillset_sha256": self.skill_registry.skillset_digest,
                })
                for plan in plans:
                    self._queue_plan(plan, jobs, job_keys)
            for plan in self._ai_plans(current, selected):
                self._queue_plan(plan, jobs, job_keys, prefix="ai")
            if jobs and steps_left > 0:
                batch = jobs[:steps_left]
                if getattr(self.args, "execution_mode", "local") == "queue":
                    for pair in batch:
                        tool, target, reason = pair[0], pair[1], pair[2]
                        skill_name = pair[3] if len(pair) > 3 else tool.name
                        cmd = tool.build(target, self.raw_dir)
                        if cmd:
                            job_id = self.store.enqueue_job(tool, target, cmd, reason, skill=skill_name)
                            self.store.add_task(tool.phase, target.raw, tool.name, "queued", f"job={job_id} {reason}")
                            self.store.add_skill_run(skill_name, target.raw, "queued", tool.name, _digest(cmd), reason)
                            self.store.add_event("job_queued", {"job_id": job_id, "skill": skill_name, "tool": tool.name, "target": target.raw})
                            if redis_queue:
                                redis_queue.push(job_id)
                else:
                    self._run_tools(batch)
                steps_left -= len(batch)
            pending = self._new_targets(seen)

        self._synthesize()
        write_report(self.workspace, self.store, self.targets, self.args, self._llm_summary())

    def _python_recon(self, target: Target) -> None:
        self.store.add_task("recon", target.raw, "python", "running")
        self.store.add_skill_run("python-recon", target.raw, "running", "python", reason="builtin recon")
        ips = resolve_host(target.host)
        self.store.add_observation(Observation("python", target.raw, "dns", {"host": target.host, "ips": ips}))
        headers = _http_headers_from_args(self.args)
        if headers:
            self.store.add_observation(Observation("python", target.raw, "http_session", {"headers": sorted(headers), "cookie": "Cookie" in headers}))
        for ip in ips[:8]:
            self.store.add_observation(Observation("python", target.raw, "ip", {"ip": ip}))

        ports = scan_common_ports(target.host, self.args.timeout)
        for port, ok, banner in ports:
            if ok:
                self.store.add_observation(Observation("python", target.raw, "open_port", {"host": target.host, "port": port, "banner": banner}))
                self.store.add_finding(Finding("Open TCP port", "info", f"{target.host}:{port}", banner or f"tcp/{port} open", "python", confidence="medium"))

        urls = _candidate_urls(target, [p for p, ok, _ in ports if ok])
        for url in urls:
            obs, findings = probe_http(url, self.args.timeout, headers)
            for item in obs:
                self.store.add_observation(item)
            for finding in findings:
                self.store.add_finding(finding)
            for item in probe_http_paths(url, self.args.timeout, self.args.allow_intrusive, headers):
                self.store.add_observation(item)
        detail = f"{len(ips)} ips, {sum(1 for _, ok, _ in ports if ok)} open ports"
        self.store.add_task("recon", target.raw, "python", "done", detail)
        self.store.add_skill_run("python-recon", target.raw, "done", "python", reason=detail)

    def _queue_plan(self, plan: SkillPlan, jobs: list[tuple[ToolSpec, Target, str]], job_keys: set[tuple[str, str]], prefix: str = "rule") -> None:
        tool = plan.skill.tool
        if not tool:
            return
        key = (tool.name, plan.target.raw)
        reason = f"{prefix}:{plan.reason}"
        if plan.status == "ready":
            if key not in job_keys:
                job_keys.add(key)
                jobs.append((tool, plan.target, reason, plan.skill.name))
                self.store.add_event("skill_planned", {"skill": plan.skill.name, "target": plan.target.raw, "reason": reason, "score": plan.score})
            return
        if plan.status == "approval_required":
            req_id = self.store.add_approval_request("intrusive", plan.target.raw, plan.skill.name, tool.name, plan.skill.risk, reason)
            self.store.add_task(plan.skill.phase, plan.target.raw, tool.name, "pending_approval", f"approval_request={req_id} {reason}")
            self.store.add_skill_run(plan.skill.name, plan.target.raw, "pending_approval", tool.name, reason=reason)
            self.store.add_event("approval_required", {"request_id": req_id, "skill": plan.skill.name, "tool": tool.name, "target": plan.target.raw})
        elif plan.status == "denied":
            self.store.add_task(plan.skill.phase, plan.target.raw, tool.name, "skipped", "approval denied")
            self.store.add_skill_run(plan.skill.name, plan.target.raw, "denied", tool.name, reason=reason)

    def _ai_plans(self, targets: Sequence[Target], selected: set[str] | None) -> list[SkillPlan]:
        if not getattr(self.args, "ai_planner", False):
            return []
        tasks = ai_plan_tasks(targets, self.skill_registry, self.args, self.policy, self.store)
        plans: list[SkillPlan] = []
        for task in tasks:
            skill_name = str(task.get("skill", ""))
            raw_target = str(task.get("target", ""))
            skill = self.skill_registry.get(skill_name)
            if selected and (not skill or not skill_selected(skill, selected)):
                continue
            with contextlib.suppress(ValueError):
                target = normalize_target(raw_target)
                if self.scope.allowed(target):
                    for plan in self.router.plan(target, self.args.profile, self.args.allow_intrusive, {skill_name}, self.policy):
                        plans.append(dataclasses.replace(plan, reason=f"{plan.reason}; {task.get('reason', '')}"[:1000]))
        return plans

    def _new_targets(self, seen: set[str]) -> list[Target]:
        found: list[Target] = []
        added: set[str] = set()
        for row in self.store.rows("observations"):
            data = json.loads(row["data"])
            host = data.get("host") if row["kind"] in {"host", "dns", "open_port"} else None
            if not host or host in seen or host in added:
                continue
            with contextlib.suppress(ValueError):
                target = normalize_target(host)
                if self.scope.allowed(target):
                    added.add(target.host)
                    found.append(target)
        found.sort(key=lambda t: t.host)
        return found[: max(0, self.args.max_discovered_targets)]

    def _run_tools(self, jobs: list[tuple]) -> None:
        def run_one(pair: tuple) -> tuple[str, str]:
            tool, target = pair[0], pair[1]
            reason = pair[2] if len(pair) > 2 else ""
            skill_name = pair[3] if len(pair) > 3 else ""
            return execute_tool_job(self.store, self.registry, self.scope, self.raw_dir, self.args, tool, target, reason, skill_name=skill_name)

        with futures.ThreadPoolExecutor(max_workers=max(1, self.args.max_workers)) as pool:
            list(pool.map(run_one, jobs))

    def _synthesize(self) -> None:
        ports_by_host: dict[str, set[int]] = {}
        urls: set[str] = set()
        for row in self.store.rows("observations"):
            data = json.loads(row["data"])
            if row["kind"] == "open_port":
                ports_by_host.setdefault(data.get("host", row["target"]), set()).add(int(data["port"]))
            if row["kind"] == "http":
                urls.add(data.get("url", row["target"]))
            if row["kind"] == "http_path":
                url = data.get("url", "")
                if any(url.endswith(path) for path in EXPOSURE_PATHS):
                    self.store.add_finding(Finding("Potential exposed web artifact", "medium", url, f"status={data.get('status')}", "synth", "Remove public access or require authentication.", confidence="medium"))
        for host, ports in ports_by_host.items():
            risky = {p for p in ports if p in {21, 23, 445, 1433, 3306, 3389, 5432, 6379, 9200, 27017}}
            if risky:
                self.store.add_finding(Finding("Internet-exposed sensitive service", "medium", host, f"ports={sorted(risky)}", "synth", "Restrict access or put behind VPN/allowlist.", confidence="medium"))
        for url in urls:
            if url.startswith("http://"):
                self.store.add_finding(Finding("Plain HTTP endpoint", "low", url, "HTTP without TLS observed", "synth", "Prefer HTTPS and redirect HTTP to HTTPS.", confidence="medium"))

    def _llm_summary(self) -> str:
        if not self.args.ai:
            return ""
        key = os.getenv(self.args.api_key_env)
        base = self.args.base_url or os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1"
        if not key:
            return ""
        findings = [dict(r) for r in self.store.rows("findings")]
        prompt = "Summarize these authorized pentest findings as concise risk-ranked next steps:\n" + json.dumps(findings[:80], ensure_ascii=False)
        try:
            return chat_completion(base, key, self.args.model, prompt, timeout=self.args.timeout)
        except Exception as exc:
            return f"LLM summary unavailable: {exc}"


def execute_tool_job(store: Store, registry: ToolRegistry, scope: Scope, raw_dir: Path, args: argparse.Namespace, tool: ToolSpec, target: Target, reason: str = "", command: list[str] | None = None, skill_name: str = "") -> tuple[str, str]:
    skill_name = skill_name or tool.name
    cmd = command or tool.build(target, raw_dir)
    if not cmd:
        return "skipped", ""
    digest = _digest(cmd)
    if not scope.allowed(target):
        store.add_task(tool.phase, target.raw, tool.name, "skipped", "out of scope or denied")
        store.add_skill_run(skill_name, target.raw, "skipped", tool.name, digest, "out of scope or denied")
        return "skipped", digest
    if getattr(args, "resume", False):
        cached = store.get_command(digest)
        if cached and (cached.returncode == 0 or getattr(args, "retry_failed", 0) <= 0):
            store.add_task(tool.phase, target.raw, tool.name, "cached", " ".join(cmd))
            store.add_tool_run(digest, tool.name, target.raw, cmd, args.timeout, "cached", cached)
            store.add_skill_run(skill_name, target.raw, "cached", tool.name, digest, reason)
            store.add_event("tool_cached", {"tool": tool.name, "target": target.raw, "digest": digest})
            _record_tool_result(store, tool, cached, skill_name)
            return "cached", digest
    store.add_task(tool.phase, target.raw, tool.name, "running", " ".join(cmd))
    store.add_skill_run(skill_name, target.raw, "running", tool.name, digest, reason)
    store.add_event("tool_start", {"tool": tool.name, "target": target.raw, "digest": digest})
    try:
        result = run_command(tool.name, target.raw, cmd, raw_dir, args.timeout)
        store.save_command(digest, result)
        status = "done" if result.returncode == 0 else "failed"
        store.add_task(tool.phase, target.raw, tool.name, status, f"rc={result.returncode} {result.seconds:.1f}s")
        store.add_tool_run(digest, tool.name, target.raw, cmd, args.timeout, status, result)
        store.add_skill_run(skill_name, target.raw, status, tool.name, digest, reason)
        store.add_event("tool_done", {"tool": tool.name, "target": target.raw, "digest": digest, "status": status, "returncode": result.returncode})
        _record_tool_result(store, tool, result, skill_name)
        return status, digest
    except Exception as exc:  # subprocess edge cases should not kill the run
        store.add_task(tool.phase, target.raw, tool.name, "error", str(exc))
        store.add_tool_run(digest, tool.name, target.raw, cmd, args.timeout, "error", detail=str(exc))
        store.add_skill_run(skill_name, target.raw, "error", tool.name, digest, str(exc))
        store.add_event("tool_error", {"tool": tool.name, "target": target.raw, "digest": digest, "error": str(exc)})
        return "error", digest


def _record_tool_result(store: Store, tool: ToolSpec, result: CommandResult, skill_name: str = "") -> None:
    observations, findings = tool.parse(result)
    for obs in observations:
        store.add_observation(obs)
    for finding in findings:
        if result.output_file and not finding.evidence_path:
            finding.evidence_path = result.output_file
        if result.digest and not finding.command_digest:
            finding.command_digest = result.digest
        if not finding.confidence:
            finding.confidence = "medium" if result.returncode == 0 else "low"
        finding.source_skill = finding.source_skill or skill_name or result.tool
        finding.source_tool = finding.source_tool or result.tool
        store.add_finding(finding)


# ---------- policy / scope ----------


def default_policy() -> dict:
    return json.loads(json.dumps(DEFAULT_POLICY))


def load_policy(path: str | None, targets: Sequence[Target] | None = None) -> Policy:
    if path:
        raw = Path(path).read_bytes()
        data = json.loads(raw.decode("utf-8"))
        return Policy(data, str(Path(path).resolve()), hashlib.sha256(raw).hexdigest())
    data = default_policy()
    if targets:
        data["scope"]["roots"] = sorted({t.host for t in targets})
    return Policy(data, "", _json_sha256(data))


def write_policy_template(output: str) -> Path:
    path = Path(output).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(default_policy(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def enforce_smoke_without_policy(args: argparse.Namespace) -> None:
    if args.policy:
        return
    if args.profile == "quick" and args.max_steps == 0 and args.rounds == 1:
        return
    raise SystemExit("--policy is required unless using smoke mode: --profile quick --max-steps 0 --rounds 1")


def apply_policy_limits(args: argparse.Namespace, policy: Policy) -> None:
    limits = policy.limits
    args.rounds = min(int(args.rounds), int(limits.get("max_rounds", args.rounds)))
    args.max_steps = min(int(args.max_steps), int(limits.get("max_steps", args.max_steps)))
    args.max_workers = min(int(args.max_workers), int(limits.get("max_workers", args.max_workers)))
    args.timeout = min(float(args.timeout), float(limits.get("timeout_seconds", args.timeout)))
    args.max_discovered_targets = min(int(args.max_discovered_targets), int(limits.get("max_discovered_targets", args.max_discovered_targets)))
    args.allow_intrusive = bool(getattr(args, "approve_intrusive", False) and policy.intrusive_approved)
    args.policy_obj = policy


def _scope_host(value: str) -> str:
    value = value.strip().lower()
    if not value:
        return ""
    if "://" in value:
        return normalize_target(value).host
    return value.strip("[]")


def _scope_match(host: str, rules: Sequence[str]) -> bool:
    for rule in rules:
        if _is_cidr(rule):
            with contextlib.suppress(ValueError):
                if ipaddress.ip_address(host) in ipaddress.ip_network(rule, strict=False):
                    return True
        elif _is_ip(rule):
            if host == rule:
                return True
        elif host == rule or host.endswith("." + rule):
            return True
    return False


def _is_cidr(value: str) -> bool:
    if "/" not in value:
        return False
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_ip_or_cidr(value: str) -> bool:
    return _is_ip(value) or _is_cidr(value)


# ---------- target / builtin recon ----------


def normalize_target(raw: str) -> Target:
    raw = raw.strip()
    if not raw:
        raise ValueError("empty target")
    parsed = urllib.parse.urlparse(raw if "://" in raw else "//" + raw)
    host = parsed.hostname or raw.split("/")[0]
    host = host.strip().strip("[]").lower()
    if not re.fullmatch(r"[a-z0-9_.:-]+", host):
        raise ValueError(f"unsupported target host: {raw}")
    kind = "ip" if _is_ip(host) else "domain"
    if "://" in raw:
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"only http(s) URLs are supported: {raw}")
        return Target(raw, host, raw.rstrip("/"), "url")
    return Target(raw, host, None, kind)


def resolve_host(host: str) -> list[str]:
    if _is_ip(host):
        return [host]
    try:
        return sorted({info[4][0] for info in socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)})
    except socket.gaierror:
        return []


def scan_common_ports(host: str, timeout: float) -> list[tuple[int, bool, str]]:
    results: list[tuple[int, bool, str]] = []
    per = min(max(timeout / 5, 0.4), 2.0)
    for port in COMMON_PORTS:
        banner = ""
        with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(per)
            try:
                sock.connect((host, port))
                if port not in {443, 8443}:
                    with contextlib.suppress(Exception):
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        banner = sock.recv(200).decode("utf-8", "replace").strip()
                results.append((port, True, banner[:200]))
            except OSError:
                results.append((port, False, ""))
    return results


def probe_http(url: str, timeout: float, headers: dict[str, str] | None = None) -> tuple[list[Observation], list[Finding]]:
    req_headers = {"User-Agent": "autoattack-agent/0.1"}
    req_headers.update(headers or {})
    req = urllib.request.Request(url, headers=req_headers)
    observations: list[Observation] = []
    findings: list[Finding] = []
    try:
        ctx = ssl.create_default_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(200_000).decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            title = _title(body)
            observations.append(Observation("python", url, "http", {"url": url, "status": resp.status, "title": title, "headers": headers}))
            missing = sorted(SECURITY_HEADERS - set(headers))
            if missing:
                findings.append(Finding("Missing common security headers", "low", url, ", ".join(missing), "python", "Set baseline client-side security headers where applicable.", confidence="medium"))
            server = headers.get("server", "")
            if server:
                findings.append(Finding("Server header exposed", "info", url, server, "python", "Hide exact versions if they reveal patch level.", confidence="medium"))
    except urllib.error.HTTPError as exc:
        observations.append(Observation("python", url, "http", {"url": url, "status": exc.code, "headers": dict(exc.headers.items())}))
    except Exception as exc:
        observations.append(Observation("python", url, "http_error", {"url": url, "error": str(exc)}))
    return observations, findings


def probe_http_paths(base_url: str, timeout: float, include_exposure: bool = False, headers: dict[str, str] | None = None) -> list[Observation]:
    paths = BASELINE_PATHS + (EXPOSURE_PATHS if include_exposure else ())
    out: list[Observation] = []
    root = base_url.rstrip("/")
    for path in paths:
        url = root + path
        req_headers = {"User-Agent": "autoattack-agent/0.1"}
        req_headers.update(headers or {})
        req = urllib.request.Request(url, headers=req_headers)
        try:
            with urllib.request.urlopen(req, timeout=min(timeout, 10)) as resp:
                sample = resp.read(400).decode("utf-8", "replace")
                if resp.status < 400:
                    out.append(Observation("python", base_url, "http_path", {"url": url, "status": resp.status, "sample": sample[:400]}))
        except urllib.error.HTTPError as exc:
            if exc.code in {200, 401, 403}:
                out.append(Observation("python", base_url, "http_path", {"url": url, "status": exc.code}))
        except Exception:
            pass
    return out


def _candidate_urls(target: Target, open_ports: Sequence[int]) -> list[str]:
    if target.url:
        return [target.url]
    urls = []
    for port in open_ports:
        if port not in HTTP_PORTS:
            continue
        scheme = "https" if port in {443, 8443} else "http"
        suffix = "" if (scheme == "http" and port == 80) or (scheme == "https" and port == 443) else f":{port}"
        urls.append(f"{scheme}://{target.host}{suffix}")
    return urls


# ---------- external tools ----------


def tool_available(tool: ToolSpec) -> bool:
    if not shutil.which(tool.binary):
        return False
    if tool.name == "httpx":
        probe = subprocess.run([tool.binary, "-version"], text=True, capture_output=True, timeout=3, check=False)
        bad = "required dependencies were not installed" in (probe.stdout + probe.stderr)
        return not bad
    return True


def tool_version(tool: ToolSpec) -> dict:
    path = shutil.which(tool.binary)
    if not path:
        return {"installed": False}
    version = ""
    for flag in (("-version",), ("--version",), ("-V",)):
        with contextlib.suppress(Exception):
            proc = subprocess.run([tool.binary, *flag], text=True, capture_output=True, timeout=3, check=False)
            text = _strip_ansi((proc.stdout or "") + "\n" + (proc.stderr or ""))
            lines = [x.strip() for x in text.splitlines() if x.strip()]
            version = next((x for x in lines if re.search(r"(?i)version|current", x)), lines[0] if lines else "")[:200]
            if version:
                break
    return {"installed": True, "path": path, "version": version}


def collect_tool_versions(registry: ToolRegistry | None = None) -> dict:
    registry = registry or ToolRegistry()
    version_fn = getattr(registry, "version", tool_version)
    return {tool.name: version_fn(tool) for tool in registry.tools}


def _default_tools() -> list[ToolSpec]:
    return [
        ToolSpec("subfinder", "recon", "passive subdomain enumeration", False, False, "subfinder", _build_subfinder, _parse_lines_as_hosts),
        ToolSpec("amass", "recon", "attack surface enumeration", False, False, "amass", _build_amass, _parse_lines_as_hosts),
        ToolSpec("nmap", "fingerprint", "service/version scan", False, False, "nmap", _build_nmap, _parse_nmap),
        ToolSpec("httpx", "fingerprint", "HTTP probing", False, False, "httpx", _build_httpx, _parse_httpx),
        ToolSpec("katana", "recon", "HTTP crawl and URL discovery", False, True, "katana", _build_katana, _parse_katana),
        ToolSpec("whatweb", "fingerprint", "web technology fingerprint", False, True, "whatweb", _build_whatweb, _parse_text_info),
        ToolSpec("nuclei", "scan", "template vulnerability scan", False, False, "nuclei", _build_nuclei, _parse_nuclei),
        ToolSpec("nikto", "scan", "web server checks", True, True, "nikto", _build_nikto, _parse_nikto),
        ToolSpec("sqlmap", "validate", "SQL injection validation", True, True, "sqlmap", _build_sqlmap, _parse_sqlmap),
        ToolSpec("zap-baseline", "scan", "OWASP ZAP baseline", True, True, "zap-baseline.py", _build_zap, _parse_text_info),
    ]


def run_command(tool: str, target: str, command: list[str], raw_dir: Path, timeout: float) -> CommandResult:
    digest = _digest(command)
    started = time.time()
    proc = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    seconds = time.time() - started
    stem = re.sub(r"[^a-zA-Z0-9_.-]+", "_", f"{tool}-{target}")[:100]
    out = raw_dir / f"{stem}-{digest[:12]}.txt"
    stdout = proc.stdout[-2_000_000:]
    stderr = proc.stderr[-500_000:]
    out.write_text("$ " + " ".join(command) + "\n\nSTDOUT\n" + stdout + "\n\nSTDERR\n" + stderr, encoding="utf-8", errors="replace")
    return CommandResult(tool, target, command, proc.returncode, stdout, stderr, seconds, str(out), digest)


def _build_subfinder(t: Target, out: Path) -> list[str] | None:
    if t.kind == "ip" or t.is_url:
        return None
    return ["subfinder", "-silent", "-d", t.host]


def _build_amass(t: Target, out: Path) -> list[str] | None:
    if t.kind == "ip" or t.is_url:
        return None
    return ["amass", "enum", "-passive", "-norecursive", "-noalts", "-d", t.host]


def _build_nmap(t: Target, out: Path) -> list[str] | None:
    return ["nmap", "-Pn", "-sV", "--top-ports", "100", "-oX", "-", t.host]


def _build_httpx(t: Target, out: Path) -> list[str] | None:
    return ["httpx", "-silent", "-json", "-u", t.url or t.host]


def _build_katana(t: Target, out: Path) -> list[str] | None:
    if not t.url:
        return None
    return ["katana", "-silent", "-jsonl", "-u", t.url]


def _build_whatweb(t: Target, out: Path) -> list[str] | None:
    return ["whatweb", "--no-errors", t.url or f"http://{t.host}"]


def _build_nuclei(t: Target, out: Path) -> list[str] | None:
    return ["nuclei", "-silent", "-jsonl", "-u", t.url or t.host]


def _build_nikto(t: Target, out: Path) -> list[str] | None:
    return ["nikto", "-nointeractive", "-host", t.url or t.host]


def _build_sqlmap(t: Target, out: Path) -> list[str] | None:
    if not t.url or "?" not in t.url:
        return None
    return ["sqlmap", "-u", t.url, "--batch", "--level", "1", "--risk", "1", "--smart", "--flush-session"]


def _build_zap(t: Target, out: Path) -> list[str] | None:
    if not t.url:
        return None
    return ["zap-baseline.py", "-t", t.url, "-J", "-", "-m", "3"]


def _parse_lines_as_hosts(r: CommandResult) -> tuple[list[Observation], list[Finding]]:
    obs = []
    for line in r.stdout.splitlines():
        host = line.strip()
        if host and re.fullmatch(r"[a-zA-Z0-9_.:-]+", host):
            obs.append(Observation(r.tool, r.target, "host", {"host": host}))
    return obs, []


def _parse_nmap(r: CommandResult) -> tuple[list[Observation], list[Finding]]:
    obs: list[Observation] = []
    findings: list[Finding] = []
    for m in re.finditer(r'<port protocol="tcp" portid="(\d+)">.*?<state state="open".*?</port>', r.stdout, re.S):
        block = m.group(0)
        port = int(m.group(1))
        svc = re.search(r'<service name="([^"]*)"(?: product="([^"]*)")?(?: version="([^"]*)")?', block)
        service = " ".join(x for x in (svc.groups() if svc else ()) if x) if svc else ""
        obs.append(Observation("nmap", r.target, "open_port", {"host": r.target, "port": port, "service": html.unescape(service)}))
        findings.append(Finding("Open TCP port", "info", f"{r.target}:{port}", html.unescape(service) or "open", "nmap", confidence="medium"))
    return obs, findings


def _parse_httpx(r: CommandResult) -> tuple[list[Observation], list[Finding]]:
    obs: list[Observation] = []
    findings: list[Finding] = []
    for line in r.stdout.splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            item = json.loads(line)
            url = item.get("url") or item.get("input") or r.target
            obs.append(Observation("httpx", r.target, "http", item))
            if item.get("webserver"):
                findings.append(Finding("Web technology fingerprint", "info", url, str(item.get("webserver")), "httpx", confidence="medium"))
    return obs, findings


def _parse_katana(r: CommandResult) -> tuple[list[Observation], list[Finding]]:
    obs: list[Observation] = []
    for line in r.stdout.splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            item = json.loads(line)
            url = item.get("url") or item.get("request", {}).get("endpoint")
            if url:
                obs.append(Observation("katana", r.target, "url", {"url": url, "source": item.get("source", "")}))
    return obs, []


def _parse_nuclei(r: CommandResult) -> tuple[list[Observation], list[Finding]]:
    obs: list[Observation] = []
    findings: list[Finding] = []
    for line in r.stdout.splitlines():
        with contextlib.suppress(json.JSONDecodeError):
            item = json.loads(line)
            info = item.get("info", {})
            sev = str(info.get("severity", "info")).lower()
            title = info.get("name") or item.get("template-id") or "Nuclei finding"
            target = item.get("matched-at") or item.get("host") or r.target
            evidence = json.dumps({k: item.get(k) for k in ("template-id", "type", "matcher-name", "curl-command") if item.get(k)}, ensure_ascii=False)
            classification = info.get("classification", {}) if isinstance(info, dict) else {}
            cve = classification.get("cve-id", "") if isinstance(classification, dict) else ""
            cwe = classification.get("cwe-id", "") if isinstance(classification, dict) else ""
            refs = info.get("reference", []) if isinstance(info, dict) else []
            if isinstance(refs, str):
                refs = [refs]
            obs.append(Observation("nuclei", r.target, "nuclei", item))
            findings.append(Finding(str(title), _severity(sev), str(target), evidence, "nuclei", "Review template evidence and patch the affected component/configuration.", confidence="high", validation_status="tool-reported", cve=",".join(cve) if isinstance(cve, list) else str(cve), cwe=",".join(cwe) if isinstance(cwe, list) else str(cwe), references=[str(x) for x in refs]))
    return obs, findings


def _parse_nikto(r: CommandResult) -> tuple[list[Observation], list[Finding]]:
    findings = []
    for line in r.stdout.splitlines():
        if line.startswith("+") and any(x in line.lower() for x in ("vulner", "outdated", "cve", "allowed", "header")):
            findings.append(Finding("Nikto web finding", "medium" if "cve" in line.lower() else "low", r.target, line[:1000], "nikto", confidence="medium"))
    return [Observation("nikto", r.target, "text", {"output_file": r.output_file, "returncode": r.returncode})], findings


def _parse_sqlmap(r: CommandResult) -> tuple[list[Observation], list[Finding]]:
    text = r.stdout + "\n" + r.stderr
    findings = []
    if re.search(r"is vulnerable|parameter '.+?' is vulnerable|sqlmap identified", text, re.I):
        findings.append(Finding("SQL injection validated", "high", r.target, _grep(text, r"(?i)(parameter .{0,160}vulnerable|sqlmap identified.{0,160})"), "sqlmap", "Fix the parameterized query and retest.", confidence="high"))
    return [Observation("sqlmap", r.target, "text", {"output_file": r.output_file, "returncode": r.returncode})], findings


def _parse_text_info(r: CommandResult) -> tuple[list[Observation], list[Finding]]:
    return [Observation(r.tool, r.target, "text", {"output_file": r.output_file, "returncode": r.returncode, "sample": r.stdout[:1000]})], []


# ---------- reporting / LLM ----------


def write_report(workspace: Path, store: Store, targets: Sequence[Target], args: argparse.Namespace, llm_summary: str = "", formats: set[str] | None = None) -> Path:
    formats = formats or {"md", "json", "sarif"}
    findings = [dict(r) for r in store.rows("findings")]
    observations = [dict(r) for r in store.rows("observations")]
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda x: (sev_order.get(str(x["severity"]).lower(), 9), x["target"], x["title"]))
    report = workspace / "report.md"
    if "md" in formats:
        report.write_text(_render_report(targets, findings, observations, args, llm_summary), encoding="utf-8")
        store.add_artifact(report, "report")
    if "json" in formats:
        findings_path = workspace / "findings.json"
        observations_path = workspace / "observations.json"
        findings_path.write_text(json.dumps(findings, indent=2, ensure_ascii=False), encoding="utf-8")
        observations_path.write_text(json.dumps(observations, indent=2, ensure_ascii=False), encoding="utf-8")
        store.add_artifact(findings_path, "findings")
        store.add_artifact(observations_path, "observations")
    if "sarif" in formats:
        sarif_path = workspace / "report.sarif.json"
        sarif_path.write_text(json.dumps(_sarif(findings), indent=2, ensure_ascii=False), encoding="utf-8")
        store.add_artifact(sarif_path, "sarif")
    if "events" in formats:
        events_path = workspace / "events.jsonl"
        events_path.write_text("\n".join(json.dumps(dict(r), ensure_ascii=False) for r in store.rows("events")) + "\n", encoding="utf-8")
        store.add_artifact(events_path, "events")
    store.add_artifact(workspace / "state.sqlite3", "state")
    return report


def _render_report(targets: Sequence[Target], findings: list[dict], observations: list[dict], args: argparse.Namespace, llm_summary: str) -> str:
    counts: dict[str, int] = {}
    for f in findings:
        counts[str(f["severity"]).lower()] = counts.get(str(f["severity"]).lower(), 0) + 1
    lines = [
        "# AutoAttack Agent Report",
        "",
        f"Generated: {_now()}",
        f"Targets: {', '.join(t.raw for t in targets)}",
        f"Profile: {getattr(args, 'profile', 'report')}; intrusive={getattr(args, 'allow_intrusive', False)}; max_steps={getattr(args, 'max_steps', 0)}",
        "",
        "## Summary",
        "",
        ", ".join(f"{k}: {v}" for k, v in sorted(counts.items())) or "No findings.",
        "",
    ]
    if llm_summary:
        lines += ["## AI summary", "", llm_summary, ""]
    lines += ["## Findings", ""]
    if not findings:
        lines.append("No findings were produced by the enabled probes/tools.")
    for f in findings:
        lines += [
            f"### [{str(f['severity']).upper()}] {f['title']}",
            "",
            f"- Target: `{f['target']}`",
            f"- Source: `{f['source']}`",
            f"- Source skill/tool: `{f.get('source_skill') or f.get('source')}` / `{f.get('source_tool') or f.get('source')}`",
            f"- Confidence: `{f.get('confidence') or 'low'}`",
            f"- Validation: `{f.get('validation_status') or 'unverified'}`",
            f"- Evidence: {f['evidence']}",
        ]
        if f.get("cve"):
            lines.append(f"- CVE: `{f['cve']}`")
        if f.get("cwe"):
            lines.append(f"- CWE: `{f['cwe']}`")
        refs = _refs_from_db(f.get("references"))
        if refs:
            lines.append("- References: " + ", ".join(refs))
        if f.get("evidence_path"):
            lines.append(f"- Evidence path: `{f['evidence_path']}`")
        if f.get("command_digest"):
            lines.append(f"- Command digest: `{f['command_digest']}`")
        if f.get("first_seen") or f.get("last_seen"):
            lines.append(f"- Seen: `{f.get('first_seen') or ''}` -> `{f.get('last_seen') or ''}`")
        if f.get("recommendation"):
            lines.append(f"- Recommendation: {f['recommendation']}")
        lines.append("")
    lines += ["## Observation inventory", ""]
    by_kind: dict[str, int] = {}
    for o in observations:
        by_kind[o["kind"]] = by_kind.get(o["kind"], 0) + 1
    lines += [f"- {k}: {v}" for k, v in sorted(by_kind.items())]
    lines.append("")
    return "\n".join(lines)


def _sarif(findings: list[dict]) -> dict:
    level = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
    rules = {}
    results = []
    for finding in findings:
        rule_id = re.sub(r"[^a-zA-Z0-9_.-]+", "-", finding["title"].lower()).strip("-") or "finding"
        rules.setdefault(rule_id, {"id": rule_id, "shortDescription": {"text": finding["title"]}})
        results.append({
            "ruleId": rule_id,
            "level": level.get(str(finding["severity"]).lower(), "warning"),
            "message": {"text": f"{finding['target']}: {finding['evidence']}"},
            "properties": {
                "source": finding["source"],
                "severity": finding["severity"],
                "confidence": finding.get("confidence") or "low",
                "evidence_path": finding.get("evidence_path") or "",
                "command_digest": finding.get("command_digest") or "",
                "first_seen": finding.get("first_seen") or "",
                "last_seen": finding.get("last_seen") or "",
                "source_skill": finding.get("source_skill") or finding.get("source") or "",
                "source_tool": finding.get("source_tool") or finding.get("source") or "",
                "validation_status": finding.get("validation_status") or "unverified",
                "cve": finding.get("cve") or "",
                "cwe": finding.get("cwe") or "",
                "references": _refs_from_db(finding.get("references")),
            },
        })
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "autoattack-agent", "informationUri": "https://github.com/", "rules": list(rules.values())}},
            "results": results,
        }],
    }


def _refs_from_db(value: object) -> list[str]:
    if not value:
        return []
    if isinstance(value, list):
        return [str(x) for x in value if x]
    with contextlib.suppress(Exception):
        data = json.loads(str(value))
        if isinstance(data, list):
            return [str(x) for x in data if x]
    return [str(value)]


def ai_skill_candidates(targets: Sequence[Target], skills: SkillRegistry, args: argparse.Namespace, policy: Policy | None, limit: int = 30) -> list[dict]:
    selected = skill_selectors(getattr(args, "tools", ""))
    profile = getattr(args, "profile", "standard")
    query = " ".join(t.raw for t in targets)
    out: list[dict] = []
    seen: set[str] = set()
    for target in targets:
        for skill in skills.candidates(target, profile, selected, policy, limit, query, executable_only=True):
            if skill.name in seen:
                continue
            out.append(skill_candidate_payload(skill))
            seen.add(skill.name)
            if len(out) >= limit:
                return out
    return out


def ai_plan_tasks(targets: Sequence[Target], skills: SkillRegistry, args: argparse.Namespace, policy: Policy | None, store: Store | None = None) -> list[dict]:
    key = os.getenv(args.api_key_env)
    if not key:
        if store:
            store.add_event("ai_planner_skipped", {"reason": "missing api key", "api_key_env": args.api_key_env})
        return []
    base = args.base_url or os.getenv("OPENAI_BASE_URL") or "https://api.openai.com/v1"
    candidates = ai_skill_candidates(targets, skills, args, policy, int(os.getenv("AUTOATTACK_AI_SKILL_LIMIT", "30")))
    blackboard = blackboard_snapshot(store) if store else {}
    prompt = (
        "Return only JSON: {\"tasks\":[{\"target\":\"...\",\"skill\":\"...\",\"reason\":\"...\",\"risk\":\"safe|intrusive\"}]} .\n"
        "Choose from these skill candidates only, never propose shell commands.\n"
        f"Targets: {[t.raw for t in targets]}\n"
        "Skill candidates:\n"
        + json.dumps(candidates, ensure_ascii=False)
        + "\n"
        f"Policy tools: {sorted(policy.allow_tools) if policy else []}\n"
        "Current blackboard observations/findings:\n"
        + json.dumps(blackboard, ensure_ascii=False)[:12000]
        + "\n"
    )
    try:
        text = chat_completion(
            base,
            key,
            args.model,
            prompt,
            timeout=args.timeout,
            system="You are a controlled black-box DAST planner. Propose safe tool skills as JSON only.",
        )
        data = _parse_json_object(text)
    except Exception as exc:
        if store:
            store.add_event("ai_planner_error", {"error": str(exc)})
        return []
    tasks = data.get("tasks") if isinstance(data, dict) else None
    if not isinstance(tasks, list):
        if store:
            store.add_event("ai_planner_rejected", {"reason": "missing tasks"})
        return []
    allowed_skills = {item["name"] for item in candidates}
    out: list[dict] = []
    for item in tasks[:20]:
        if not isinstance(item, dict):
            continue
        skill = str(item.get("skill", ""))
        target = str(item.get("target", ""))
        if skill in allowed_skills and target:
            out.append({"skill": skill, "target": target, "reason": str(item.get("reason", ""))[:500], "risk": str(item.get("risk", ""))[:50]})
    if store:
        store.add_event("ai_planner_tasks", {"accepted": len(out), "proposed": len(tasks), "candidates": len(candidates)})
    return out

def blackboard_snapshot(store: Store | None, limit: int = 30) -> dict:
    if not store:
        return {}
    observations = []
    for row in store.rows("observations", limit=limit, recent=True):
        observations.append({"target": row["target"], "kind": row["kind"], "source": row["source"], "data": json.loads(row["data"])})
    findings = []
    for row in store.rows("findings", limit=limit, recent=True):
        findings.append({"title": row["title"], "severity": row["severity"], "target": row["target"], "source": row["source"], "evidence": row["evidence"][:500]})
    return {"observations": observations, "findings": findings}


def _parse_json_object(text: str) -> dict:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            raise
        data = json.loads(m.group(0))
    if not isinstance(data, dict):
        raise ValueError("planner JSON must be an object")
    return data


def chat_completion(base_url: str, api_key: str, model: str, prompt: str, timeout: float, system: str = "You are a concise authorized penetration testing report analyst.") -> str:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode())
    return data["choices"][0]["message"]["content"].strip()


# ---------- manifests / CLI ----------


def build_manifest(run_id: str, started_at: str, status: str, workspace: Path, targets: Sequence[Target], policy: Policy, args: argparse.Namespace, ended_at: str = "", counts: dict | None = None, tool_versions: dict | None = None) -> dict:
    return {
        "run_id": run_id,
        "started_at": started_at,
        "ended_at": ended_at,
        "status": status,
        "argv": list(sys.argv),
        "targets": [t.raw for t in targets],
        "policy_sha256": policy.sha256,
        "tool_versions": tool_versions or {},
        "agent_version": AGENT_VERSION,
        "skill_schema_version": SKILL_SCHEMA_VERSION,
        "counts": counts or {},
        "workspace": str(workspace),
        "effective_args": {
            "profile": args.profile,
            "rounds": args.rounds,
            "max_discovered_targets": args.max_discovered_targets,
            "max_steps": args.max_steps,
            "max_workers": args.max_workers,
            "timeout": args.timeout,
            "tools": args.tools or "",
            "allow_intrusive": bool(getattr(args, "allow_intrusive", False)),
            "allow_out_of_scope": bool(args.allow_out_of_scope),
            "ai": bool(args.ai),
            "ai_planner": bool(getattr(args, "ai_planner", False)),
            "execution_mode": getattr(args, "execution_mode", "local"),
            "queue_backend": getattr(args, "queue_backend", "sqlite"),
            "queue_name": getattr(args, "queue_name", ""),
            "skills_dir": getattr(args, "skills_dir", "") or "",
            "skillset_sha256": getattr(args, "skillset_sha256", "") or "",
            "headers": [str(h).split(":", 1)[0].strip() for h in (getattr(args, "headers", []) or [])],
            "cookie": bool(getattr(args, "cookie", "")),
            "model": args.model,
            "api_key_env": args.api_key_env,
            "base_url": args.base_url,
        },
    }


def write_manifest(workspace: Path, store: Store | None, manifest: dict) -> None:
    path = workspace / "run.json"
    path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if store:
        store.save_run(manifest)
        store.add_artifact(path, "manifest")
        store.add_artifact(workspace / "policy.json", "policy")


def load_manifest(workspace: Path) -> dict:
    return json.loads((workspace / "run.json").read_text(encoding="utf-8"))


def status_payload(workspace: Path) -> dict:
    manifest = load_manifest(workspace) if (workspace / "run.json").exists() else {"run_id": "", "status": "unknown", "targets": []}
    store = Store(workspace / "state.sqlite3")
    counts = store.counts()
    return {
        "run_id": manifest.get("run_id"),
        "status": manifest.get("status"),
        "started_at": manifest.get("started_at"),
        "ended_at": manifest.get("ended_at"),
        "workspace": str(workspace),
        "targets": len(manifest.get("targets", [])),
        "observations": counts.get("observations", 0),
        "findings": counts.get("findings", 0),
        "tasks": counts.get("tasks_by_status", {}),
        "command_cache": counts.get("command_cache", 0),
        "tool_runs": counts.get("tool_runs", 0),
        "skill_runs": counts.get("skill_runs", 0),
        "approval_requests": counts.get("approval_requests", 0),
        "events": counts.get("events", 0),
        "job_queue": counts.get("jobs_by_status", {}),
    }


def cmd_init(args: argparse.Namespace) -> int:
    print(write_policy_template(args.output))
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    policy = load_policy(args.policy) if args.policy else None
    registry = ToolRegistry()
    rows = []
    for tool in registry.tools:
        intrusive = tool.intrusive or bool(policy and tool.name in policy.intrusive_tools)
        allowed = True if not policy or not policy.allow_tools else tool.name in policy.allow_tools
        rows.append({
            "name": tool.name,
            "phase": tool.phase,
            "binary": tool.binary,
            "available": registry.is_available(tool),
            "version": registry.version(tool).get("version", ""),
            "allowed_by_policy": allowed,
            "intrusive": intrusive,
            "requires_approval": intrusive and not bool(policy and policy.intrusive_approved),
            "description": tool.description,
        })
    print(json.dumps(rows, indent=2, ensure_ascii=False))
    return 0


def cmd_skills(args: argparse.Namespace) -> int:
    if args.skill_cmd == "normalize":
        root = Path(args.path)
        paths = sorted(root.rglob("*.json")) if root.is_dir() else [root]
        rows = []
        ok = True
        for path in paths:
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                normalized = normalize_skill_manifest(raw, source=str(path))
                changed = raw != normalized
                if args.write:
                    write_json_atomic(path, normalized)
                rows.append({"path": str(path), "ok": True, "changed": changed, "manifest": normalized})
            except Exception as exc:
                ok = False
                rows.append({"path": str(path), "ok": False, "error": str(exc)})
        payload = rows[0]["manifest"] if len(rows) == 1 and rows[0].get("ok") and not args.write else rows
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0 if ok else 1
    if args.skill_cmd == "validate":
        rows = []
        ok = True
        seen: dict[str, str] = {}
        tools = ToolRegistry()
        manifests: dict[str, dict] = {}
        for path in sorted(Path(args.path).rglob("*.json") if Path(args.path).is_dir() else [Path(args.path)]):
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
                manifest = normalize_skill_manifest(raw, source=str(path))
                if getattr(args, "strict", False) and raw != manifest:
                    raise ValueError("manifest is not normalized; run: skills normalize --write")
                duplicate = seen.get(manifest["name"])
                if duplicate:
                    raise ValueError(f"duplicate skill name {manifest['name']} also in {duplicate}")
                if manifest.get("tool") and not tools.get(manifest["tool"]):
                    raise ValueError(f"unknown tool for {manifest['name']}: {manifest['tool']}")
                seen[manifest["name"]] = str(path)
                manifests[manifest["name"]] = manifest
                rows.append({"path": str(path), "ok": True, "manifest": manifest})
            except Exception as exc:
                ok = False
                rows.append({"path": str(path), "ok": False, "error": str(exc)})
        known = {"python-recon", *(t.name for t in tools.tools), *manifests}
        known_versions = {"python-recon": "1", **{t.name: "1" for t in tools.tools}, **{name: manifest.get("version", "1") for name, manifest in manifests.items()}}
        for row in rows:
            manifest = row.get("manifest") if row.get("ok") else None
            missing = [name for name in (manifest or {}).get("depends_on", []) if name not in known]
            if missing:
                row["ok"] = False
                row["error"] = f"missing dependencies: {missing}"
                ok = False
                continue
            mismatched = [f"{name}{constraint} (found {known_versions.get(name, '')})" for name, constraint in (manifest or {}).get("dependency_versions", {}).items() if name in known_versions and not _version_satisfies(str(known_versions.get(name, "")), str(constraint))]
            if mismatched:
                row["ok"] = False
                row["error"] = f"dependency version mismatch: {mismatched}"
                ok = False
        cycle = _dependency_cycle({name: manifest.get("depends_on", []) for name, manifest in manifests.items()})
        if cycle:
            ok = False
            cycle_set = set(cycle)
            for row in rows:
                manifest = row.get("manifest") if row.get("ok") else None
                if manifest and manifest["name"] in cycle_set:
                    row["ok"] = False
                    row["error"] = "dependency cycle: " + " -> ".join(cycle)
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0 if ok else 1
    if args.skill_cmd == "stats":
        print(json.dumps(skill_stats_workspaces(Path(args.workspace).resolve(), args.limit, args.max_events, args.recursive), indent=2, ensure_ascii=False))
        return 0
    if args.skill_cmd == "trace":
        store = Store(Path(args.workspace).resolve() / "state.sqlite3")
        print(json.dumps(skill_trace(store, args.target, args.skill, args.limit), indent=2, ensure_ascii=False))
        return 0
    registry = SkillRegistry(config_path=Path(args.config) if getattr(args, "config", "") else None, skills_dir=Path(args.skills_dir) if getattr(args, "skills_dir", "") else None)
    if args.skill_cmd == "list":
        rows, total = filter_skill_rows(registry, args)
        if getattr(args, "summary", False):
            by_phase: dict[str, int] = {}
            by_source: dict[str, int] = {}
            for row in rows:
                by_phase[row["phase"]] = by_phase.get(row["phase"], 0) + 1
                source = "manifest" if row["source"] not in {"builtin", "tool"} else row["source"]
                by_source[source] = by_source.get(source, 0) + 1
            print(json.dumps({"total": total, "returned": len(rows), "offset": args.offset, "limit": args.limit, "by_phase": by_phase, "by_source": by_source, "skills": rows}, indent=2, ensure_ascii=False))
        else:
            print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    if args.skill_cmd == "test":
        print(json.dumps(registry.test(args.name), indent=2, ensure_ascii=False))
        return 0
    if args.skill_cmd == "show":
        detail = skill_detail(registry, args.name, args.raw)
        print(json.dumps(detail, indent=2, ensure_ascii=False))
        return 0 if detail.get("ok") else 1
    if args.skill_cmd == "explain":
        target = normalize_target(args.target)
        policy = load_policy(args.policy, [target]) if getattr(args, "policy", "") else None
        selected = skill_selectors(getattr(args, "tools", ""))
        allow_intrusive = bool(getattr(args, "approve_intrusive", False) and (not policy or policy.intrusive_approved))
        print(json.dumps(explain_skill_routing(registry, target, args.profile, allow_intrusive, selected, policy, args.limit, args.query, args.include_skipped), indent=2, ensure_ascii=False))
        return 0
    if args.skill_cmd == "eval":
        policy = load_policy(args.policy) if getattr(args, "policy", "") else None
        result = eval_skill_routing(registry, Path(args.path), policy, args.fail_under)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["ok"] else 1
    if args.skill_cmd in {"enable", "disable"}:
        ok = registry.enable(args.name, args.skill_cmd == "enable")
        print(json.dumps({"name": args.name, "enabled": args.skill_cmd == "enable", "ok": ok}, indent=2))
        return 0 if ok else 1
    raise SystemExit(f"unknown skills command: {args.skill_cmd}")


def cmd_approvals(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    store = Store(workspace / "state.sqlite3")
    print(json.dumps([dict(r) for r in store.rows("approval_requests", args.limit, args.offset, args.recent)], indent=2, ensure_ascii=False))
    return 0


def cmd_jobs(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    store = Store(workspace / "state.sqlite3")
    print(json.dumps([dict(r) for r in store.rows("job_queue", args.limit, args.offset, args.recent)], indent=2, ensure_ascii=False))
    return 0


def cmd_web(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt: str, *a) -> None:
            if args.verbose:
                super().log_message(fmt, *a)

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path.startswith("/api/"):
                self._json(api_payload(workspace, parsed.path.removeprefix("/api/"), parsed.query))
                return
            self._html(render_console(workspace))

        def do_POST(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            qs = urllib.parse.parse_qs(parsed.query)
            rid = int((qs.get("id") or ["0"])[0])
            store = Store(workspace / "state.sqlite3")
            if parsed.path == "/approve":
                store.decide_approval(rid, "approved")
            elif parsed.path == "/deny":
                store.decide_approval(rid, "denied")
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()

        def _json(self, data: object) -> None:
            body = json.dumps(data, indent=2, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _html(self, body: str) -> None:
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    server = http.server.ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"http://{args.host}:{server.server_port}")
    server.serve_forever()
    return 0


def cmd_import_har(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    store = Store(workspace / "state.sqlite3")
    data = json.loads(Path(args.har).read_text(encoding="utf-8"))
    entries = data.get("log", {}).get("entries", [])
    count = 0
    for entry in entries[: args.limit]:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        url = str(req.get("url", ""))
        if not url:
            continue
        store.add_observation(Observation("har", url, "har_request", {"method": req.get("method"), "url": url, "headers": [h.get("name") for h in req.get("headers", []) if h.get("name")]}))
        store.add_observation(Observation("har", url, "har_response", {"url": url, "status": resp.get("status"), "mimeType": resp.get("content", {}).get("mimeType", "")}))
        if int(resp.get("status") or 0) >= 500:
            store.add_finding(Finding("Server error observed in HAR", "low", url, f"status={resp.get('status')}", "har", confidence="medium", validation_status="observed"))
        count += 1
    store.add_event("har_imported", {"path": str(Path(args.har).resolve()), "entries": count})
    store.add_artifact(Path(args.har), "har")
    if (workspace / "run.json").exists():
        manifest = load_manifest(workspace)
        targets = [normalize_target(x) for x in manifest.get("targets", [])]
        write_report(workspace, store, targets, _report_args_from_manifest(manifest), formats={"md", "json", "sarif", "events"})
    print(json.dumps({"imported": count}, indent=2))
    return 0


def _query_int(qs: dict[str, list[str]], name: str, default: int) -> int:
    with contextlib.suppress(Exception):
        return max(0, int((qs.get(name) or [str(default)])[0]))
    return default


def api_payload(workspace: Path, name: str, query: str = "") -> object:
    store = Store(workspace / "state.sqlite3")
    if name == "status":
        return status_payload(workspace)
    if name in {"findings", "tasks", "events", "job_queue", "approval_requests", "skill_runs", "tool_runs"}:
        qs = urllib.parse.parse_qs(query)
        limit = _query_int(qs, "limit", 200)
        offset = _query_int(qs, "offset", 0)
        recent = _bool((qs.get("recent") or ["true"])[0], True)
        return [dict(r) for r in store.rows(name, limit, offset, recent)]
    return {"error": "unknown endpoint"}


def render_console(workspace: Path) -> str:
    status = status_payload(workspace)
    store = Store(workspace / "state.sqlite3")
    findings = [dict(r) for r in store.rows("findings", 20, recent=True)]
    jobs = [dict(r) for r in store.rows("job_queue", 20, recent=True)]
    approvals = [dict(r) for r in store.rows("approval_requests", 20, recent=True)]
    tasks = [dict(r) for r in store.rows("tasks", 30, recent=True)]
    def esc(v: object) -> str:
        return html.escape(str(v))
    def table(rows: list[dict], cols: list[str]) -> str:
        body = "".join("<tr>" + "".join(f"<td>{r.get(c, '') if c == 'action' else esc(r.get(c, ''))}</td>" for c in cols) + "</tr>" for r in rows)
        head = "".join(f"<th>{esc(c)}</th>" for c in cols)
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
    approval_rows = []
    for r in approvals:
        action = ""
        if r.get("status") == "pending":
            action = f"<form method='post' action='/approve?id={r['id']}'><button>approve</button></form><form method='post' action='/deny?id={r['id']}'><button>deny</button></form>"
        rr = dict(r)
        rr["action"] = action
        approval_rows.append(rr)
    return f"""<!doctype html>
<meta charset="utf-8"><meta http-equiv="refresh" content="10">
<title>AutoAttack Console</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;margin:24px;background:#0b1020;color:#e7eaf3}}
a{{color:#8ab4ff}} .cards{{display:flex;gap:12px;flex-wrap:wrap}} .card{{background:#151b2e;padding:12px 16px;border-radius:10px}}
table{{width:100%;border-collapse:collapse;margin:10px 0 24px;background:#11172a}} th,td{{border-bottom:1px solid #2b3450;padding:6px;text-align:left;vertical-align:top}} th{{color:#9db2ff}}
button{{margin:2px;padding:4px 8px}} code{{color:#ffd479}}
</style>
<h1>AutoAttack Console</h1>
<p>Workspace: <code>{esc(workspace)}</code></p>
<div class="cards">
{''.join(f"<div class='card'><b>{esc(k)}</b><br>{esc(v)}</div>" for k,v in status.items() if k not in {'tasks','job_queue'})}
<div class='card'><b>tasks</b><br>{esc(status.get('tasks'))}</div>
<div class='card'><b>job_queue</b><br>{esc(status.get('job_queue'))}</div>
</div>
<p>JSON: <a href="/api/status">status</a> · <a href="/api/findings">findings</a> · <a href="/api/tasks">tasks</a> · <a href="/api/job_queue">jobs</a> · <a href="/api/events">events</a></p>
<h2>Approvals</h2>{table(approval_rows, ['id','status','target','skill','tool','risk','reason','action'])}
<h2>Recent Findings</h2>{table(findings, ['id','severity','title','target','source','confidence','validation_status'])}
<h2>Recent Jobs</h2>{table(jobs, ['id','status','tool','target','attempts','lease_owner','detail'])}
<h2>Recent Tasks</h2>{table(tasks, ['id','phase','tool','target','status','detail'])}
"""


def cmd_approval_decision(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    store = Store(workspace / "state.sqlite3")
    status = "approved" if args.cmd == "approve" else "denied"
    ok = store.decide_approval(int(args.request_id), status)
    store.add_event("approval_decided", {"request_id": int(args.request_id), "status": status, "ok": ok})
    print(json.dumps({"request_id": int(args.request_id), "status": status, "ok": ok}, indent=2))
    return 0 if ok else 1


def cmd_worker(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    manifest = load_manifest(workspace)
    targets = [normalize_target(x) for x in manifest.get("targets", [])]
    policy = load_policy(str(workspace / "policy.json"), targets)
    effective = manifest.get("effective_args", {})
    ns = argparse.Namespace(
        allow_out_of_scope=effective.get("allow_out_of_scope", False),
        max_workers=1,
        timeout=effective.get("timeout", 120.0),
        resume=True,
        retry_failed=args.retry_failed,
        tools=effective.get("tools", ""),
        profile=effective.get("profile", "quick"),
        allow_intrusive=effective.get("allow_intrusive", False),
        ai=False,
        ai_planner=False,
        execution_mode="local",
        queue_backend=args.queue_backend or effective.get("queue_backend", "sqlite"),
        queue_name=args.queue_name or effective.get("queue_name", "") or _queue_name(workspace, manifest.get("run_id", "")),
        skills_dir=effective.get("skills_dir", ""),
        skillset_sha256=effective.get("skillset_sha256", ""),
        base_url=effective.get("base_url"),
        model=effective.get("model", os.getenv("OPENAI_MODEL", "gpt-4o-mini")),
        api_key_env=effective.get("api_key_env", "OPENAI_API_KEY"),
        max_steps=effective.get("max_steps", 0),
        rounds=effective.get("rounds", 1),
        max_discovered_targets=effective.get("max_discovered_targets", 25),
        policy_obj=policy,
    )
    store = Store(workspace / "state.sqlite3")
    if args.retry_failed:
        store.requeue_failed_jobs(args.retry_failed)
    registry = ToolRegistry()
    scope = Scope(targets, ns.allow_out_of_scope, policy)
    raw_dir = workspace / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    worker_id = args.worker_id or f"{socket.gethostname()}-{os.getpid()}"
    redis_queue = None
    if ns.queue_backend == "redis":
        redis_queue = RedisQueue(args.redis_url, ns.queue_name)
        redis_queue.ping()
    processed = 0
    idle = 0
    while args.max_jobs <= 0 or processed < args.max_jobs:
        if redis_queue:
            job_id = redis_queue.pop()
            row = store.claim_job_by_id(job_id, worker_id, args.lease_seconds) if job_id else None
            if job_id and not row:
                continue
        else:
            row = store.claim_job(worker_id, args.lease_seconds)
        if not row:
            if args.once or idle >= args.idle_limit:
                break
            idle += 1
            time.sleep(args.poll_interval)
            continue
        idle = 0
        tool = next((t for t in registry.tools if t.name == row["tool"]), None)
        if not tool:
            store.finish_job(row["id"], "error", detail=f"unknown tool {row['tool']}", worker_id=worker_id)
            store.add_event("job_error", {"job_id": row["id"], "error": f"unknown tool {row['tool']}"})
            processed += 1
            continue
        target = normalize_target(row["target"])
        status, digest = execute_tool_job(store, registry, scope, raw_dir, ns, tool, target, row["reason"], json.loads(row["command"]), skill_name=row.get("skill") or tool.name)
        store.finish_job(row["id"], "done" if status in {"done", "cached"} else status, digest, status, worker_id=worker_id)
        store.add_event("job_finished", {"job_id": row["id"], "tool": tool.name, "target": target.raw, "status": status})
        processed += 1
    agent = Agent(targets, workspace, ns)
    agent._synthesize()
    write_report(workspace, store, targets, _report_args_from_manifest(manifest), formats={"md", "json", "sarif", "events"})
    counts = store.counts()
    manifest["counts"] = counts
    if not (counts.get("jobs_by_status", {}).get("queued") or counts.get("jobs_by_status", {}).get("running")):
        manifest["status"] = "completed"
        manifest["ended_at"] = _now()
    else:
        manifest["status"] = "running"
    write_manifest(workspace, store, manifest)
    print(json.dumps({"worker_id": worker_id, "processed": processed, "job_queue": counts.get("jobs_by_status", {})}, indent=2, ensure_ascii=False))
    return 0


def cmd_run(args: argparse.Namespace) -> int:
    enforce_smoke_without_policy(args)
    if getattr(args, "distributed", False):
        args.execution_mode = "queue"
        if getattr(args, "queue_backend", "sqlite") == "sqlite":
            args.queue_backend = "redis"
    targets = [normalize_target(x) for x in args.targets]
    policy = load_policy(args.policy, targets)
    apply_policy_limits(args, policy)
    workspace = Path(args.workspace or ("runs/" + dt.datetime.now().strftime("%Y%m%d-%H%M%S"))).resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "raw").mkdir(parents=True, exist_ok=True)
    (workspace / "policy.json").write_text(json.dumps(policy.data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    store = Store(workspace / "state.sqlite3")
    run_id = getattr(args, "run_id", "") or str(uuid.uuid4())
    args.queue_backend = getattr(args, "queue_backend", "sqlite")
    args.queue_name = _queue_name(workspace, run_id, getattr(args, "queue_name", ""))
    started_at = _now()
    versions = collect_tool_versions()
    manifest = build_manifest(run_id, started_at, "running", workspace, targets, policy, args, tool_versions=versions)
    write_manifest(workspace, store, manifest)
    store.add_event("run_started", {"run_id": run_id, "targets": [t.raw for t in targets], "workspace": str(workspace)})
    rc = 0
    try:
        scope = Scope(targets, args.allow_out_of_scope, policy)
        for target in targets:
            if not scope.allowed(target):
                store.add_task("scope", target.raw, "policy", "skipped", "target outside policy scope")
        Agent(targets, workspace, args).run()
        job_counts = store.counts().get("jobs_by_status", {})
        status = "queued" if getattr(args, "execution_mode", "local") == "queue" and job_counts.get("queued", 0) else "completed"
    except Exception as exc:
        status = "failed"
        rc = 1
        store.add_task("run", ",".join(t.raw for t in targets), "agent", "error", str(exc))
        store.add_event("run_failed", {"run_id": run_id, "error": str(exc)})
        print(f"run failed: {exc}", file=sys.stderr)
    counts = store.counts()
    manifest = build_manifest(run_id, started_at, status, workspace, targets, policy, args, ended_at=_now(), counts=counts, tool_versions=versions)
    write_manifest(workspace, store, manifest)
    store.add_event("run_completed", {"run_id": run_id, "status": status, "counts": counts})
    print(workspace / "report.md")
    return rc


def cmd_status(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    print(json.dumps(status_payload(workspace), indent=2, ensure_ascii=False))
    return 0


def _report_args_from_manifest(manifest: dict) -> argparse.Namespace:
    effective = manifest.get("effective_args", {})
    return argparse.Namespace(
        profile=effective.get("profile", "report"),
        allow_intrusive=effective.get("allow_intrusive", False),
        max_steps=effective.get("max_steps", 0),
    )


def cmd_report(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    manifest = load_manifest(workspace) if (workspace / "run.json").exists() else {"targets": []}
    targets = [normalize_target(x) for x in manifest.get("targets", [])]
    store = Store(workspace / "state.sqlite3")
    formats = {x.strip() for x in args.format.split(",") if x.strip()}
    report = write_report(workspace, store, targets, _report_args_from_manifest(manifest), formats=formats)
    print(report)
    return 0


def cmd_resume(args: argparse.Namespace) -> int:
    workspace = Path(args.workspace).resolve()
    manifest = load_manifest(workspace)
    effective = manifest.get("effective_args", {})
    ns = argparse.Namespace(
        targets=manifest.get("targets", []),
        workspace=str(workspace),
        policy=str(workspace / "policy.json"),
        profile=effective.get("profile", "quick"),
        rounds=effective.get("rounds", 1),
        max_discovered_targets=effective.get("max_discovered_targets", 25),
        max_steps=effective.get("max_steps", 0),
        max_workers=effective.get("max_workers", 4),
        timeout=effective.get("timeout", 120.0),
        tools=effective.get("tools", ""),
        resume=True,
        retry_failed=args.retry_failed,
        approve_intrusive=effective.get("allow_intrusive", False),
        allow_intrusive=effective.get("allow_intrusive", False),
        allow_out_of_scope=effective.get("allow_out_of_scope", False),
        ai=False,
        ai_planner=effective.get("ai_planner", False),
        execution_mode=effective.get("execution_mode", "local"),
        queue_backend=effective.get("queue_backend", "sqlite"),
        queue_name=effective.get("queue_name", ""),
        skills_dir=effective.get("skills_dir", ""),
        skillset_sha256=effective.get("skillset_sha256", ""),
        headers=[],
        cookie="",
        base_url=effective.get("base_url"),
        model=effective.get("model", os.getenv("OPENAI_MODEL", "gpt-4o-mini")),
        api_key_env=effective.get("api_key_env", "OPENAI_API_KEY"),
        run_id=manifest.get("run_id") or str(uuid.uuid4()),
    )
    return cmd_run(ns)


def cmd_selftest(_: argparse.Namespace) -> int:
    t1 = normalize_target("https://example.com/a?b=1")
    assert t1.host == "example.com" and t1.is_url
    t2 = normalize_target("127.0.0.1")
    assert t2.kind == "ip"
    policy = load_policy(None, [normalize_target("example.com")])
    scope = Scope([normalize_target("example.com")], policy=policy)
    assert scope.allowed("www.example.com") and not scope.allowed("evil.test")
    cidr = Policy({"scope": {"roots": ["10.0.0.0/24"], "deny": ["10.0.0.9"]}})
    assert Scope([], policy=cidr).allowed("10.0.0.5") and not Scope([], policy=cidr).allowed("10.0.0.9")
    fake = CommandResult("nuclei", "https://x", ["nuclei"], 0, json.dumps({"template-id": "t", "info": {"name": "xss", "severity": "high"}, "matched-at": "https://x/a"}) + "\n", "", 0.1, "raw.txt", "d")
    _, findings = _parse_nuclei(fake)
    assert findings and findings[0].severity == "high"
    with tempfile.TemporaryDirectory() as tmp:
        args = argparse.Namespace(
            allow_out_of_scope=False,
            max_workers=2,
            timeout=3,
            resume=False,
            retry_failed=0,
            tools="",
            profile="quick",
            allow_intrusive=False,
            ai=False,
            ai_planner=False,
            execution_mode="local",
            base_url=None,
            model="test",
            api_key_env="OPENAI_API_KEY",
            max_steps=1,
            rounds=1,
            max_discovered_targets=1,
            policy_obj=load_policy(None, [normalize_target("127.0.0.1")]),
        )
        target = normalize_target("127.0.0.1")
        agent = Agent([target], Path(tmp), args)
        tool = ToolSpec(
            "dummy",
            "test",
            "threaded sqlite regression",
            False,
            False,
            "python3",
            lambda _t, _o: ["python3", "-c", "print('ok')"],
            lambda _r: ([Observation("dummy", "127.0.0.1", "dummy", {"ok": True})], [Finding("Dummy finding", "info", "127.0.0.1", "ok", "dummy")]),
        )
        agent.registry.tools.append(tool)
        agent._run_tools([(tool, target), (tool, target)])
        assert agent.store.rows("findings") and agent.store.rows("command_cache") and agent.store.rows("tool_runs")
        assert json.loads(json.dumps(_sarif([dict(agent.store.rows("findings")[0])])))["runs"]
    print("selftest ok")
    return 0


# ---------- misc ----------


def _digest(parts: Iterable[str]) -> str:
    h = hashlib.sha256()
    for part in parts:
        h.update(str(part).encode())
        h.update(b"\0")
    return h.hexdigest()


def _json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, sort_keys=True)


def write_json_atomic(path: Path, data: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(data, indent=2, ensure_ascii=False) + "\n"
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def _json_sha256(data: dict) -> str:
    return hashlib.sha256((json.dumps(data, ensure_ascii=False, sort_keys=True) + "\n").encode()).hexdigest()


def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().isoformat(timespec="seconds")


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _title(body: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:200] if m else ""


def _severity(value: str) -> str:
    value = value.lower()
    return value if value in {"critical", "high", "medium", "low", "info"} else "info"


def _grep(text: str, pattern: str) -> str:
    m = re.search(pattern, text, re.S)
    return re.sub(r"\s+", " ", m.group(0)).strip()[:1000] if m else text[:1000]


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", text)


def _http_headers_from_args(args: argparse.Namespace) -> dict[str, str]:
    headers: dict[str, str] = {}
    for item in getattr(args, "headers", []) or []:
        if ":" in item:
            k, v = item.split(":", 1)
            if k.strip():
                headers[k.strip()] = v.strip()
    if getattr(args, "cookie", ""):
        headers["Cookie"] = args.cookie
    return headers


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Autonomous authorized pentest agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    init = sub.add_parser("init", help="write a policy template")
    init.add_argument("--output", default="policy.json")
    init.set_defaults(func=cmd_init)

    run = sub.add_parser("run", help="run planner -> tools -> analyst -> report")
    run.add_argument("targets", nargs="+", help="domain, IP, or http(s) URL")
    run.add_argument("--workspace", help="output directory")
    run.add_argument("--policy", help="policy JSON path")
    run.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    run.add_argument("--rounds", type=int, default=2, help="planner rounds; later rounds inspect discovered in-scope hosts")
    run.add_argument("--max-discovered-targets", type=int, default=25)
    run.add_argument("--max-steps", type=int, default=16, help="max external tool tasks")
    run.add_argument("--max-workers", type=int, default=4)
    run.add_argument("--timeout", type=float, default=120.0, help="per tool timeout seconds")
    run.add_argument("--tools", help="comma-separated skill/tool selectors, e.g. nmap,nuclei,cap:web,tag:headers")
    run.add_argument("--skills-dir", default=os.getenv("AUTOATTACK_SKILLS_DIR", ""), help="directory of JSON skill manifests")
    run.add_argument("--execution-mode", choices=["local", "queue"], default="local", help="local executes immediately; queue plans jobs for distributed workers")
    run.add_argument("--distributed", action="store_true", help="alias for --execution-mode queue")
    run.add_argument("--queue-backend", choices=["sqlite", "redis"], default="sqlite", help="distributed queue backend")
    run.add_argument("--redis-url", default=os.getenv("AUTOATTACK_REDIS_URL", "redis://127.0.0.1:6379/0"))
    run.add_argument("--queue-name", default="", help="override distributed queue name")
    run.add_argument("--resume", action="store_true", help="reuse cached external tool command results in the workspace DB")
    run.add_argument("--retry-failed", type=int, default=0)
    run.add_argument("--approve-intrusive", action="store_true", help="approve policy-enabled intrusive tools")
    run.add_argument("--allow-intrusive", dest="approve_intrusive", action="store_true", help=argparse.SUPPRESS)
    run.add_argument("--allow-out-of-scope", action="store_true")
    run.add_argument("--header", dest="headers", action="append", default=[], help="extra HTTP header for builtin web probes, e.g. 'Authorization: Bearer ...'")
    run.add_argument("--cookie", default="", help="Cookie header for builtin web probes")
    run.add_argument("--ai", action="store_true", help="optional OpenAI-compatible report summarizer")
    run.add_argument("--ai-planner", action="store_true", help="optional controlled JSON skill planner; gated by scope/policy/router")
    run.add_argument("--base-url")
    run.add_argument("--model", default=os.getenv("OPENAI_MODEL", "gpt-4o-mini"))
    run.add_argument("--api-key-env", default="OPENAI_API_KEY")
    run.set_defaults(func=cmd_run)

    tools = sub.add_parser("tools", help="list external tool availability")
    tools.add_argument("--policy", help="policy JSON path")
    tools.set_defaults(func=cmd_tools)

    skills = sub.add_parser("skills", help="list/test/enable/disable/normalize/validate local skills")
    skills.add_argument("--config", default="", help=argparse.SUPPRESS)
    skills.add_argument("--skills-dir", default=os.getenv("AUTOATTACK_SKILLS_DIR", ""), help="directory of JSON skill manifests")
    skill_sub = skills.add_subparsers(dest="skill_cmd", required=True)
    skills_list = skill_sub.add_parser("list", help="list local skills")
    skills_list.add_argument("--phase", choices=sorted(ALLOWED_SKILL_PHASES), default="")
    skills_list.add_argument("--risk", choices=sorted(ALLOWED_SKILL_RISKS), default="")
    skills_list.add_argument("--source", choices=["builtin", "tool", "manifest"], default="")
    skills_list.add_argument("--state", choices=["all", "enabled", "disabled"], default="all")
    skills_list.add_argument("--tag", default="")
    skills_list.add_argument("--capability", default="")
    skills_list.add_argument("--query", default="")
    skills_list.add_argument("--limit", type=int, default=0)
    skills_list.add_argument("--offset", type=int, default=0)
    skills_list.add_argument("--sort", choices=["priority", "name", "phase"], default="priority")
    skills_list.add_argument("--executable", action="store_true")
    skills_list.add_argument("--available", action="store_true")
    skills_list.add_argument("--summary", action="store_true")
    skills_list.set_defaults(func=cmd_skills)
    skills_test = skill_sub.add_parser("test", help="test a local skill manifest/build/parser")
    skills_test.add_argument("name")
    skills_test.set_defaults(func=cmd_skills)
    skills_show = skill_sub.add_parser("show", help="show full normalized skill details")
    skills_show.add_argument("name")
    skills_show.add_argument("--raw", action="store_true", help="include source JSON for manifest skills")
    skills_show.set_defaults(func=cmd_skills)
    skills_norm = skill_sub.add_parser("normalize", help="normalize a JSON skill manifest")
    skills_norm.add_argument("path")
    skills_norm.add_argument("--write", action="store_true", help="rewrite manifest file(s) with normalized JSON")
    skills_norm.set_defaults(func=cmd_skills)
    skills_validate = skill_sub.add_parser("validate", help="validate a JSON skill manifest or directory")
    skills_validate.add_argument("path")
    skills_validate.add_argument("--strict", action="store_true", help="fail if file content is not already normalized")
    skills_validate.set_defaults(func=cmd_skills)
    skills_explain = skill_sub.add_parser("explain", help="explain skill routing for one target")
    skills_explain.add_argument("target")
    skills_explain.add_argument("--profile", choices=["quick", "standard", "deep"], default="standard")
    skills_explain.add_argument("--tools", default="", help="comma-separated skill/tool selectors, e.g. nmap,cap:web,tag:headers")
    skills_explain.add_argument("--policy", default="", help="policy JSON path")
    skills_explain.add_argument("--limit", type=int, default=30)
    skills_explain.add_argument("--query", default="")
    skills_explain.add_argument("--include-skipped", type=int, default=20)
    skills_explain.add_argument("--approve-intrusive", action="store_true")
    skills_explain.set_defaults(func=cmd_skills)
    skills_eval = skill_sub.add_parser("eval", help="evaluate skill routing against JSON cases")
    skills_eval.add_argument("path")
    skills_eval.add_argument("--policy", default="", help="policy JSON path")
    skills_eval.add_argument("--fail-under", type=float, default=100.0)
    skills_eval.set_defaults(func=cmd_skills)
    skills_stats = skill_sub.add_parser("stats", help="summarize skill routing and run outcomes from a workspace")
    skills_stats.add_argument("workspace")
    skills_stats.add_argument("--limit", type=int, default=20)
    skills_stats.add_argument("--max-events", type=int, default=1000)
    skills_stats.add_argument("--recursive", action="store_true", help="aggregate nested workspaces under a runs directory")
    skills_stats.set_defaults(func=cmd_skills)
    skills_trace = skill_sub.add_parser("trace", help="show skill routing/execution timeline for a workspace")
    skills_trace.add_argument("workspace")
    skills_trace.add_argument("--target", default="")
    skills_trace.add_argument("--skill", default="")
    skills_trace.add_argument("--limit", type=int, default=200)
    skills_trace.set_defaults(func=cmd_skills)
    for name in ("enable", "disable"):
        p = skill_sub.add_parser(name, help=f"{name} a local skill")
        p.add_argument("name")
        p.set_defaults(func=cmd_skills)

    status = sub.add_parser("status", help="show run status as JSON")
    status.add_argument("workspace")
    status.set_defaults(func=cmd_status)

    resume = sub.add_parser("resume", help="resume a workspace using its manifest and command cache")
    resume.add_argument("workspace")
    resume.add_argument("--retry-failed", type=int, default=0)
    resume.set_defaults(func=cmd_resume)

    worker = sub.add_parser("worker", help="execute queued jobs from a workspace")
    worker.add_argument("workspace")
    worker.add_argument("--worker-id", default="")
    worker.add_argument("--once", action="store_true", help="exit when no job is immediately available")
    worker.add_argument("--max-jobs", type=int, default=0, help="0 means unlimited until idle limit")
    worker.add_argument("--poll-interval", type=float, default=2.0)
    worker.add_argument("--idle-limit", type=int, default=0, help="empty polls before exit; 0 exits after first empty poll")
    worker.add_argument("--lease-seconds", type=float, default=300.0)
    worker.add_argument("--retry-failed", type=int, default=0)
    worker.add_argument("--queue-backend", choices=["", "sqlite", "redis"], default="", help="override manifest queue backend")
    worker.add_argument("--redis-url", default=os.getenv("AUTOATTACK_REDIS_URL", "redis://127.0.0.1:6379/0"))
    worker.add_argument("--queue-name", default="", help="override manifest queue name")
    worker.set_defaults(func=cmd_worker)

    jobs = sub.add_parser("jobs", help="list queued/distributed jobs")
    jobs.add_argument("workspace")
    jobs.add_argument("--limit", type=int, default=0)
    jobs.add_argument("--offset", type=int, default=0)
    jobs.add_argument("--recent", action="store_true")
    jobs.set_defaults(func=cmd_jobs)

    web = sub.add_parser("web", help="serve a lightweight local control console")
    web.add_argument("workspace")
    web.add_argument("--host", default="127.0.0.1")
    web.add_argument("--port", type=int, default=8765)
    web.add_argument("--verbose", action="store_true")
    web.set_defaults(func=cmd_web)

    har = sub.add_parser("import-har", help="import passive HAR as web evidence")
    har.add_argument("workspace")
    har.add_argument("har")
    har.add_argument("--limit", type=int, default=1000)
    har.set_defaults(func=cmd_import_har)

    report = sub.add_parser("report", help="regenerate reports from a run directory")
    report.add_argument("workspace")
    report.add_argument("--format", default="md,json,sarif", help="comma-separated: md,json,sarif,events")
    report.set_defaults(func=cmd_report)

    approvals = sub.add_parser("approvals", help="list pending/decided approval requests")
    approvals.add_argument("workspace")
    approvals.add_argument("--limit", type=int, default=0)
    approvals.add_argument("--offset", type=int, default=0)
    approvals.add_argument("--recent", action="store_true")
    approvals.set_defaults(func=cmd_approvals)

    approve = sub.add_parser("approve", help="approve an approval request")
    approve.add_argument("workspace")
    approve.add_argument("request_id", type=int)
    approve.set_defaults(func=cmd_approval_decision)

    deny = sub.add_parser("deny", help="deny an approval request")
    deny.add_argument("workspace")
    deny.add_argument("request_id", type=int)
    deny.set_defaults(func=cmd_approval_decision)

    selftest = sub.add_parser("selftest", help="run minimal assertions")
    selftest.set_defaults(func=cmd_selftest)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

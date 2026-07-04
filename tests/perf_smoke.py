#!/usr/bin/env python3
import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import autoattack_agent as aa


def main() -> int:
    start = time.time()
    with tempfile.TemporaryDirectory() as tmp:
        workspace = Path(tmp)
        store = aa.Store(workspace / "state.sqlite3")
        targets = [aa.Target(f"10.0.{i // 255}.{i % 255}", f"10.0.{i // 255}.{i % 255}", None, "ip") for i in range(1000)]
        for i, target in enumerate(targets):
            store.add_observation(aa.Observation("fake", target.raw, "open_port", {"host": target.host, "port": 80}))
            store.add_finding(aa.Finding("Fake finding", "info", target.host, "ok", "fake"))
        aa.write_report(workspace, store, targets, argparse.Namespace(profile="perf", allow_intrusive=False, max_steps=0))
        assert json.loads((workspace / "report.sarif.json").read_text())["runs"]
        assert len(json.loads((workspace / "observations.json").read_text())) == 1000
    elapsed = time.time() - start
    print(f"perf_smoke ok: 1000 targets in {elapsed:.2f}s")
    assert elapsed < 20
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

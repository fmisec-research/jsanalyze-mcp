#!/usr/bin/env python3
"""Full v2 integration test — drives server.analyze on the fixture (VENV python: needs
mcp + the enricher tools):

    ./.venv/bin/python tests/test_enrichers.py

Asserts the triaged artifacts are written, leads are distinct and gated, secrets masked,
and issues are surfaced.
"""
from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "example.xml"

import jsanalyze.server as S

FULL_SECRETS = ["AKIAIOSFODNN7EXAMPLE", "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH"]
ARTIFACTS = ["endpoints.json", "sinks.json", "postmessage.json", "secrets.json", "libs.json",
             "graphql.json", "flags.json", "routes.json", "storage.json", "chunks.json",
             "sourcemaps.json", "framework.json", "csp.json", "history.json", "source_notes.json",
             "responses.json", "leads.json", "issues.json", "endpoints.txt", "report.md"]


def main() -> int:
    summary = S.analyze(str(FIX), label="server-smoke", scope_hosts=["target.tld"])
    run_dir = Path([ln for ln in summary.splitlines() if ln.startswith("Workspace:")][0]
                   .split("Workspace:", 1)[1].strip())
    try:
        assert run_dir.is_dir(), run_dir
        for name in ARTIFACTS:
            p = run_dir / name
            assert p.exists(), f"missing artifact: {name}"
        for name in ARTIFACTS:
            if name.endswith(".json"):
                json.loads((run_dir / name).read_text())  # valid JSON

        leads = json.loads((run_dir / "leads.json").read_text())
        classes = {l["class"] for l in leads}
        print(f"[*] leads={len(leads)} classes={sorted(classes)}")
        assert {"xss-sink", "postmessage-listener", "bfla-candidate", "secret-location",
                "vulnerable-library"} <= classes, f"missing core classes: {classes}"
        # v2: every lead carries a composite score and the queue is ordered by it (desc)
        assert all("score" in l for l in leads), "leads missing v2 score"
        scores = [float(l["score"]) for l in leads]
        assert scores == sorted(scores, reverse=True), "leads not ordered by score"
        assert not leads[0]["class"].startswith("postmessage"), \
            "a postMessage listener is top of queue (scoring regression)"
        # BFLA deduped to one despite method variants
        assert sum(1 for l in leads if l["class"] == "bfla-candidate") == 1
        # the tainted innerHTML is the sink lead
        assert any(l["class"] == "xss-sink" and "location.hash" in (l.get("evidence") or "")
                   for l in leads)
        # round 7: a message-handler `e.data` flowing to innerHTML is recovered as a REAL xss-sink
        # (the `.data` property is no longer dropped to the bare ident `e`), not under-classified
        assert any(l["class"] == "xss-sink" and "e.data" in (l.get("evidence") or "")
                   for l in leads), "e.data message-handler sink not recovered as xss-sink"
        # ...while a genuinely sourceless sink (panel.js `innerHTML = props.body`) stays a low
        # sink-untraced AUDIT lead — the tracer discloses its bound rather than faking taint
        assert any(l["class"] == "sink-untraced" for l in leads), "untraced audit sink missing"

        # sinks.json keeps audit clusters, most NOT leads
        sinks = json.loads((run_dir / "sinks.json").read_text())
        assert sinks and any(not c.get("lead") for c in sinks)

        # masking everywhere human-readable
        report = (run_dir / "report.md").read_text()
        for blob, where in ((json.dumps(leads), "leads.json"), (report, "report.md")):
            for s in FULL_SECRETS:
                assert s not in blob, f"UNMASKED secret in {where}: {s}"
        # but secrets.json keeps full values (gitignored)
        assert any(s in (run_dir / "secrets.json").read_text() for s in FULL_SECRETS)

        # endpoints.txt is the clean fetchable feed (no module/asset/garbage)
        eptxt = (run_dir / "endpoints.txt").read_text()
        assert ".js" not in eptxt and "audio/" not in eptxt

        print("artifacts OK; leads distinct; secrets masked; sinks gated.")
        print("\n✅ SERVER INTEGRATION TEST PASSED")
        return 0
    finally:
        shutil.rmtree(run_dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, IndexError) as e:
        print(f"\n❌ FAILED: {type(e).__name__}: {e}")
        sys.exit(1)

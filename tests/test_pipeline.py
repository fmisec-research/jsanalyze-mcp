#!/usr/bin/env python3
"""Stdlib-core NOISE-GATE test (no mcp, no enricher tools beyond jsluice):

    PYTHONPATH=src python3 -P tests/test_pipeline.py

Exercises load_input -> jsluice -> triage (sinks/postmessage/endpoints) -> build_leads
and asserts the de-noising contract: distinct leads, a real tainted sink becomes a lead,
postMessage families are split, endpoints are deduped/classified, secrets masked.
"""
from __future__ import annotations

import collections
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures" / "example.xml"

from jsanalyze.analyzers.endpoints import normalize_endpoints
from jsanalyze.analyzers.jsluice_wrapper import resolve_jsluice, run_jsluice
from jsanalyze.analyzers.postmessage import classify_postmessage
from jsanalyze.analyzers.sinks import triage_sinks
from jsanalyze.leads.lead_engine import build_leads
from jsanalyze.models import Triaged
from jsanalyze.parsers.inputs import load_input
from jsanalyze.utils import workspace as W

FULL_SECRETS = ["AKIAIOSFODNN7EXAMPLE", "sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEFGH"]


def main() -> int:
    assert FIX.exists(), FIX
    assert resolve_jsluice(), "jsluice not resolvable — run setup"
    run = W.new_run("pipeline-smoke")
    sh = ["target.tld"]
    try:
        js_items, _maps, _refs = load_input(FIX, scope_hosts=sh, out_dir=run.js_dir)
        assert js_items, "no JS items"
        a = run_jsluice(js_items, cfg=W.load_config())

        tri = Triaged(
            endpoints=normalize_endpoints(list(a.urls), js_items, None, sh),
            sinks=triage_sinks(a.sinks, js_items, None, sh),
            postmessage=classify_postmessage(a.postmessage, js_items, None, sh),
            secrets=list(a.secrets),
        )
        leads = build_leads(tri)
        classes = collections.Counter(l["class"] for l in leads)
        print(f"[*] leads={len(leads)} classes={dict(classes)}")

        # ids sequential
        assert [l["id"] for l in leads] == [f"lead-{i:04d}" for i in range(1, len(leads) + 1)]

        # a genuinely tainted sink (el.innerHTML = location.hash) IS a lead ...
        xss = [l for l in leads if l["class"] == "xss-sink"]
        assert xss and any("location.hash" in (l.get("evidence") or "") for l in xss), \
            f"tainted innerHTML sink missing from leads: {xss}"
        # ... but a sink cluster that is not really tainted is NOT a lead (stays in sinks.json)
        assert any(not c.get("lead") for c in tri.sinks), "expected non-lead audit sink clusters"

        # postMessage: the no-origin-check listener is a lead; onmessage-style never a lead
        assert any(l["class"] == "postmessage-listener" for l in leads)

        # endpoints: BFLA deduped to ONE despite method/type variants; classes present
        bfla = [l for l in leads if l["class"] == "bfla-candidate"]
        assert len(bfla) == 1, f"BFLA not deduped: {bfla}"
        assert {"auth-endpoint", "graphql-candidate"} <= set(classes)

        # masking: no full secret anywhere in the leads
        blob = json.dumps(leads)
        for s in FULL_SECRETS:
            assert s not in blob, f"UNMASKED secret leaked: {s}"

        print("\n".join(f"  [{l['id']}] {l['class']:22s} {l['confidence']}/{l['severity_hint']:8s} "
                        f"{l['suggested_skill']:20s} {l['evidence'][:44]}" for l in leads))
        print("\n✅ NOISE-GATE PIPELINE TEST PASSED")
        return 0
    finally:
        import shutil
        shutil.rmtree(run.dir, ignore_errors=True)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"\n❌ ASSERTION FAILED: {e}")
        sys.exit(1)

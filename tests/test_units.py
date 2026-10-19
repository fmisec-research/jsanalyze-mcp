#!/usr/bin/env python3
"""Unit tests for the v2 pure modules (no jsluice, no mcp, no network):

    PYTHONPATH=src python3 tests/test_units.py

Covers the judgement layer added for the critique: path/endpoint normalization,
call-site body-key recovery, the bounded taint tracer, and composite scoring.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from jsanalyze.analyzers.callsites import object_keys, request_shape
from jsanalyze.analyzers.taint import backtrace, discover_html_sinks, sink_arg_idents, source_label
from jsanalyze.leads.scoring import ScoreInputs, score_lead
from jsanalyze.models import Lead
from jsanalyze.utils.normalize import (
    API_CALL, ASSET_PREFIX, SPA_ROUTE, classify_string_kind, endpoint_key, history_key,
    normalize_path,
)

_passed = []


def check(name, cond):
    assert cond, name
    _passed.append(name)


def test_normalize():
    check("digit seg -> {id}", normalize_path("/orders/123/items") == "/orders/{id}/items")
    check("uuid seg -> {id}",
          normalize_path("/u/550e8400-e29b-41d4-a716-446655440000") == "/u/{id}")
    check("EXPR -> {id}", normalize_path("/orders/EXPR") == "/orders/{id}")
    check("trailing slash dropped", normalize_path("/a/b/") == "/a/b")
    # endpoint (rooted, no host) and history (absolute) collapse to the same norm
    ek = endpoint_key("GET", "", "/orders/42")
    hk = history_key("GET", "https://x.tld/orders/42")
    check("endpoint/history norm match", ek[2] == hk[2] == "/orders/{id}")
    check("graphql keyed per op", endpoint_key("POST", "", "/graphql", operation_name="GetUser")[2]
          == "graphql#GetUser")
    check("asset prefix", classify_string_kind("/static/js/app.js", "") == ASSET_PREFIX)
    check("fetch call -> api", classify_string_kind("/x", "fetch") == API_CALL)
    check("route when known", classify_string_kind("/register", "", is_route=True) == SPA_ROUTE)
    # a LinkFinder/stringLiteral hit is NOT a call site -> a known route must beat it
    check("linkfinder does not override route",
          classify_string_kind("/register", "linkfinder", is_route=True) == SPA_ROUTE)
    check("stringLiteral does not override route",
          classify_string_kind("/register", "stringLiteral", is_route=True) == SPA_ROUTE)
    check("genuine fetch DOES override route",
          classify_string_kind("/register", "fetch", is_route=True) == API_CALL)


def test_callsites():
    check("shorthand+quoted+spread+nested",
          object_keys('{a:1, "b-c":2, d:{e:3}, name, ...rest}') == ["a", "b-c", "d", "name"])
    check("values not captured", object_keys('{role:"admin", qty:n}') == ["role", "qty"])
    rs = request_shape('fetch("/x",{method:"POST",body:JSON.stringify({role, qty})})', 1)
    check("JSON.stringify body keys", rs["body_keys"] == ["role", "qty"] and rs["method"] == "POST")
    rs2 = request_shape('axios.put("/o/"+id,{status:"x"})', 1)
    check("axios verb+direct body", rs2["method"] == "PUT" and rs2["body_keys"] == ["status"])
    check("variable body -> no keys", request_shape('fetch(u,{body: payload})', 1)["body_keys"] == [])


def test_taint():
    text = ('var t = location.hash.slice(1);\nfunction render(x){return {__html:x};}\n'
            'el.dangerouslySetInnerHTML = render(t);\nq.innerHTML = t;\nvar c="k";\nn.innerHTML=c;\n')
    lab, chain = backtrace(text, sink_arg_idents("innerHTML", "q.innerHTML = t"))
    check("one-hop trace to location.hash", lab == "location.hash" and chain)
    lab2, _ = backtrace(text, sink_arg_idents("innerHTML", "n.innerHTML = c"))
    check("constant not tainted", lab2 is None)
    disc = discover_html_sinks(text)
    check("dangerouslySetInnerHTML discovered",
          any(d["kind"] == "dangerouslySetInnerHTML" for d in disc))
    check("nav-only location.pathname excluded", source_label("location.pathname") is None)
    check("event.data is a source", source_label("e.data") == "e.data" or "data" in (source_label("e.data") or ""))


def test_scoring():
    base = dict(id="", cls="idor-candidate", title="", suggested_skill="hunt-idor",
                severity_hint="medium", confidence="medium")
    first = Lead(**base)
    s_first, f_first = score_lead(first, ScoreInputs(party="first", in_scope=True, has_id_segment=True))
    vend = Lead(**base)
    s_vend, _ = score_lead(vend, ScoreInputs(party="vendor", in_scope=True))
    check("first-party outscores vendor", s_first > s_vend)

    listener = Lead(id="", cls="postmessage-listener", title="", suggested_skill="hunt-xss",
                    severity_hint="medium", confidence="low")
    s_no_sink, f = score_lead(listener, ScoreInputs(party="first", in_scope=True, pm_has_signal=False))
    s_sink, _ = score_lead(listener, ScoreInputs(party="first", in_scope=True, pm_has_signal=True))
    check("listener w/o sink penalised", s_no_sink < s_sink and "-listener_no_sink" in f)

    untested = Lead(id="", cls="endpoint-unverified", title="", suggested_skill="hunt-api",
                    severity_hint="low", confidence="low", seen_in_history=False, method="GET")
    s_unt, fu = score_lead(untested, ScoreInputs(party="first", in_scope=True, history_known=True))
    check("not-in-history boosts", "+not_in_history" in fu)


def main() -> int:
    for fn in (test_normalize, test_callsites, test_taint, test_scoring):
        fn()
    for n in _passed:
        print(f"  ✓ {n}")
    print(f"\n✅ UNIT TESTS PASSED ({len(_passed)} checks)")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"\n❌ UNIT ASSERTION FAILED: {e}")
        sys.exit(1)

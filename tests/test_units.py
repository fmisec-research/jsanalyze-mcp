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
from jsanalyze.analyzers.chunks import map_chunks
from jsanalyze.analyzers.endpoints import _b64decode, _url_like
from jsanalyze.analyzers.framework import _firebase_configs
from jsanalyze.analyzers.strings import _build_consts, fold_expr
from jsanalyze.analyzers.taint import backtrace, discover_html_sinks, sink_arg_idents, source_label
from jsanalyze.leads.lead_engine import _body_delta_leads, _sink_leads
from jsanalyze.leads.scoring import ScoreInputs, score_lead
from jsanalyze.models import Lead, Triaged
from jsanalyze.parsers.history import _json_keys_and_gql, _parse_request_fields
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


def test_taint_minified():
    # round 2 pt 2: in a minified one-liner `t` is reassigned; the def that taints a sink
    # is the nearest one BEFORE it, never the first in the file.
    text = ('var t="safe";el0.innerHTML=t;var q=1;t=location.hash.slice(1);el1.innerHTML=t;')
    i0 = text.index("el0.innerHTML=t")
    i1 = text.index("el1.innerHTML=t")
    lab0, _ = backtrace(text, ["t"], before=i0)
    check("nearest-def before 1st sink = constant (untainted)", lab0 is None)
    lab1, chain1 = backtrace(text, ["t"], before=i1)
    check("nearest-def before 2nd sink reaches location.hash", lab1 == "location.hash" and bool(chain1))
    labf, _ = backtrace(text, ["t"], before=None)
    check("before=None keeps old first-def behaviour (constant)", labf is None)


def test_source_tightened():
    # round 2 pt 2: the loose \\w*\\.?data matcher is gone — only message-event .data counts
    check("formData is NOT a source", source_label("formData") is None)
    check("metadata is NOT a source", source_label("metadata") is None)
    check("res.data is NOT a source", source_label("res.data") is None)
    check("event.data IS a source", source_label("event.data") == "event.data")
    check("location.search IS a source", source_label("location.search") == "location.search")


def test_new_sinks():
    text = ('new DOMParser().parseFromString(location.search,"text/html");'
            'r.createContextualFragment(x);frame.srcdoc=userHtml;')
    kinds = {d["kind"] for d in discover_html_sinks(text)}
    check("parseFromString discovered", "parseFromString" in kinds)
    check("createContextualFragment discovered", "createContextualFragment" in kinds)
    check("iframe srcdoc discovered", "srcdoc" in kinds)


def test_atob():
    check("base64 decodes to a path", _b64decode("L2FwaS92MS9zZWNyZXQ") == "/api/v1/secret")
    check("url_like yields a rooted path", list(_url_like("/api/v1/secret")) == ["/api/v1/secret"])
    check("url_like rejects a plain word", list(_url_like("notaurl")) == [])
    check("b64 of binary rejected", _b64decode("////") == "")


def test_chunk_runtime_missing():
    # round 2 pt 3: a webpackJsonp bundle with NO map must not be silent
    class _I:
        saved_path = None
        js_body = "(window.webpackJsonp=window.webpackJsonp||[]).push([[1],{}]);"
        url = "https://x.tld/app/a.js"
    recs = map_chunks([_I()])
    check("webpackJsonp w/o map -> runtime-missing record",
          any(c.get("kind") == "runtime-missing" for c in recs))


def test_firebase_config():
    text = ('var cfg={apiKey:"AIzaSyFAKE0000000000000000000000000000",'
            'authDomain:"demo.firebaseapp.com",projectId:"demo-1",'
            'databaseURL:"https://demo.firebaseio.com"};')
    fcs = _firebase_configs(text)
    check("firebase config detected as one", len(fcs) == 1)
    check("firebase apiKey captured for folding", fcs[0]["apikey"].startswith("AIzaSyFAKE"))


def test_string_fold():
    # round 3 pt 3: jsluice fragments `API + "/admin"` — fold the const back together
    consts = _build_consts('const API="/api/v2"; var H="https://x.tld";')
    check("const resolved", consts.get("API") == "/api/v2")
    check("concat folded to full path", fold_expr('API + "/admin/users"', consts)[0] == "/api/v2/admin/users")
    check("unresolved ident -> EXPR", fold_expr('H + "/o/" + id', consts) == ("https://x.tld/o/EXPR", True))
    check("pure literals not marked used_ident", fold_expr('"/a" + "/b"', consts)[1] is False)


def test_request_body_parse():
    # round 3 pt 1: the <request> blob the operator sent — parse query + body keys + gql op
    req = (b"POST /api/v1/users?expand=1 HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
           b'{"role":"admin","locale":"en"}')
    q, b, g = _parse_request_fields(req)
    check("sent query key parsed", q == {"expand"})
    check("sent body keys parsed", b == {"role", "locale"})
    check("no gql on plain json", g == set())
    gb, gg = _json_keys_and_gql({"query": "mutation DeleteUser($id:ID!){x}",
                                 "operationName": "DeleteUser", "variables": {"id": "1"}})
    check("gql op extracted", gg == {"DeleteUser"})
    check("gql variables as body keys", gb == {"id"})


def test_body_delta():
    # round 3 pt 1: an authz/money field the bundle can send but was never sent -> a lead;
    # a benign field (locale) stays silent; a mutation never POSTed -> graphql-unsent
    tri = Triaged(
        endpoints=[{"host": "", "norm_path": "/api/v1/users/{id}", "path": "/api/v1/users/42",
                    "method": "PATCH", "body_keys": ["role", "locale"], "query": [],
                    "party": "first", "in_scope": True, "where_found": "a.js:3"}],
        graphql=[{"operation": "mutation", "operationName": "DeleteUser", "variables": ["$id"],
                  "file": "a.js", "party": "first"}],
    )
    hist = {"sent": {("", "/api/v1/users/{id}"): {"body": {"locale"}, "query": set(), "gql": set()},
                     ("", "/graphql"): {"body": set(), "query": set(), "gql": {"GetUser"}}}}
    pairs = _body_delta_leads(tri, hist)
    classes = {ld.cls for ld, _ in pairs}
    bf = [ld for ld, _ in pairs if ld.cls == "body-field-unsent"]
    check("body-field-unsent emitted", bool(bf))
    check("authz field 'role' flagged, benign 'locale' not",
          bf and bf[0].body_keys == ["role"])
    check("unsent graphql mutation flagged", "graphql-unsent" in classes)


def test_untraced_cap():
    # round 3 pt 2: cap untraced sinks and require a non-empty chain
    def _cluster(i, chain):
        return {"sink_class": "html", "kind": "innerHTML", "party": "first", "untraced": True,
                "lead": False, "caller_chain": chain, "count": 1,
                "occurrences": [{"file": "a.js", "line": i, "source": "el.innerHTML=x"}]}
    sinks = [_cluster(i, ["x = f()"]) for i in range(8)] + [_cluster(99, [])]
    tri = Triaged(sinks=sinks)
    leads = [ld for ld, _ in _sink_leads(tri, set())]
    unt = [l for l in leads if l.cls == "sink-untraced"]
    check("untraced capped at 5", len(unt) == 5)
    check("empty-chain untraced excluded", all(l.line != 99 for l in unt))


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
    for fn in (test_normalize, test_callsites, test_taint, test_taint_minified,
               test_source_tightened, test_new_sinks, test_atob, test_chunk_runtime_missing,
               test_firebase_config, test_string_fold, test_request_body_parse,
               test_body_delta, test_untraced_cap, test_scoring):
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

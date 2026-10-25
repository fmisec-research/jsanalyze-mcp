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
from jsanalyze.analyzers.comment_miner import _CRED_RE, _INTERNAL_HOST_RE, _MOCK_PATH_RE, _scan
from jsanalyze.analyzers.endpoints import _b64decode, _url_like, classify_endpoint
from jsanalyze.analyzers.framework import _PROTO_LODASH_RE, _firebase_configs, _scan_gadgets
from jsanalyze.analyzers.postmessage import _TOKENISH, _WILDCARD_TARGET, _origin_strength
from jsanalyze.analyzers.sinks import _STRLIT_RE, _anon_param_of_sink, _enclosing_fn, _san_component
from jsanalyze.analyzers.strings import (
    _CLIENT_DEF_RE, _build_consts, _client_base_map, _join, fold_expr,
)
from jsanalyze.analyzers.taint import (
    _arg_expr, _definition_rhs, _rhs_slice, backtrace, discover_html_sinks, sink_arg_idents,
    source_label,
)
from jsanalyze.leads.lead_engine import _body_delta_leads, _sink_leads, _vuln_sink_leads
from jsanalyze.leads.scoring import ScoreInputs, score_lead
from jsanalyze.models import Lead, Triaged
from jsanalyze.parsers.history import (
    _gql_op_names, _json_keys_and_gql, _multipart_field_names, _parse_request_fields,
)
from jsanalyze.parsers.responses import _SENSITIVE_KEY_RE, _flatten
from jsanalyze.utils.normalize import normalize_path as _np
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
    req = (b"POST /api/v1/users?expand=1 HTTP/1.1\r\nContent-Type: application/json\r\n"
           b"Authorization: Bearer x\r\nCookie: sid=abc; theme=dark\r\n\r\n"
           b'{"role":"admin","locale":"en","user":{"owner":"a"}}')
    q, b, g, auth = _parse_request_fields(req)
    check("sent query key parsed", q == {"expand"})
    check("sent body keys parsed (+nested)", {"role", "locale", "user", "owner"} <= b)
    check("no gql on plain json", g == set())
    check("auth header name captured", "Authorization" in auth["headers"])
    check("session cookie name captured", "sid" in auth["cookies"])
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


def test_baseurl_join_and_guard():
    # round 4 pt 1: axios.create({baseURL}) + client.get("/x") -> one joined path
    cm = _client_base_map('const c = axios.create({ baseURL: "/api/v2" });', {})
    check("client baseURL mapped", cm.get("c") == "/api/v2")
    check("join base+path", _join("/api/v2", "/admin/users") == "/api/v2/admin/users")
    # a half-folded EXPR path must NOT become IDOR; a genuine one still does
    part = {"path": "/api/EXPR/users", "url": "/api/EXPR/users", "norm_path": _np("/api/EXPR/users"),
            "string_kind": "api", "query": [], "body_keys": [], "fold_partial": True}
    check("partial-fold EXPR not idor", classify_endpoint(part) is None)
    genuine = dict(part); genuine["fold_partial"] = False
    check("genuine EXPR still idor", (classify_endpoint(genuine) or [None])[0] == "idor-candidate")


def test_supabase_gadget():
    g = _scan_gadgets('const sb = createClient("https://xyz.supabase.co", "anonKeyFAKE");', "first", "a.js")
    sup = [x for x in g if x.get("gadget") == "supabase-config"]
    check("supabase createClient -> cloud-config", bool(sup) and sup[0]["suggested_skill"] == "hunt-cloud")


def test_vuln_call_binding():
    # round 4 pt 4: vulnerable DOMPurify + its output in an innerHTML sink -> vulnerable-call
    tri = Triaged(
        libs=[{"component": "dompurify", "version": "3.2.6", "cves": ["CVE-2024-X"], "cwe": ["79"]}],
        sinks=[{"kind": "innerHTML", "sink_class": "html", "sanitizer": "dompurify",
                "caller_chain": [], "occurrences": [{"file": "a.js", "line": 9,
                "source": "el.innerHTML = DOMPurify.sanitize(x)"}]}],
    )
    leads = [ld for ld, _ in _vuln_sink_leads(tri)]
    check("vulnerable-call lead emitted", any(l.cls == "vulnerable-call" for l in leads))
    check("vulnerable-call is high/hunt-xss",
          leads and leads[0].severity_hint == "high" and leads[0].suggested_skill == "hunt-xss")


def test_batch_and_multipart():
    # round 4 pt 3: Apollo batch array -> every op; multipart name="…" -> body keys
    _bk, gql = _json_keys_and_gql([{"query": "query A{x}", "operationName": "A"},
                                   {"query": "mutation B{y}", "operationName": "B"}])
    check("apollo batch yields all ops", gql == {"A", "B"})
    mp = (b"POST /u HTTP/1.1\r\nContent-Type: multipart/form-data; boundary=X\r\n\r\n"
          b'--X\r\nContent-Disposition: form-data; name="role"\r\n\r\nadmin\r\n--X--')
    _q, b, _g, _a = _parse_request_fields(mp)
    check("multipart name parsed as body key", "role" in b)


def test_round5_fp_tightening():
    # 1: a comparison is not an assignment
    lab, _ = backtrace("if (t == location.hash) {}", ["t"])
    check("`t == location.hash` is not tainted taint", lab is None)
    # 2: // inside https:// is not a comment
    comments, _strings = _scan('var u = "https://internal.corp.example.com/x"; // real note')
    check("https:// not seen as comment", all("internal.corp" not in c for _p, c in comments))
    check("real // note still a comment", any("real note" in c for _p, c in comments))
    # 3: credential needs : or =
    check("`password resetFlow` not a credential", not _CRED_RE.search("password resetFlow"))
    check("`password = hunter2xx` is a credential", bool(_CRED_RE.search('password = "hunter2xx"')))
    # 4: host prefix must be a full label
    check("device.company.com NOT internal", not _INTERNAL_HOST_RE.search("device.company.com"))
    check("testing.example.com NOT internal", not _INTERNAL_HOST_RE.search("testing.example.com"))
    check("dev.example.com IS internal", bool(_INTERNAL_HOST_RE.search("dev.example.com")))
    # 5: token words are whole-word
    check("author is not tokenish", not _TOKENISH.search("author"))
    check("sessionStorage is not tokenish", not _TOKENISH.search("sessionStorage"))
    check("authToken is tokenish", bool(_TOKENISH.search("authToken")))
    # 8: sanitizer must be a call
    check("bare 'marked' word not a sanitizer", _san_component("a marked item") is None)
    check("DOMPurify.sanitize(x) is a sanitizer", _san_component("el.innerHTML=DOMPurify.sanitize(x)") == "dompurify")
    # 10: lodash .set is not proto-pollution
    check("_.set( not proto-pollution", not _PROTO_LODASH_RE.search("_.set(obj, p, v)"))
    check("_.merge( is proto-pollution", bool(_PROTO_LODASH_RE.search("_.merge(a, b)")))
    # 11: version2 is not an id segment
    check("version2 not {id}", _np("/api/version2/users") == "/api/version2/users")
    check("2-digit opaque id -> {id}", _np("/u/a1b2c3d4") == "/u/{id}")


def test_round5_origin():
    # 6 + 14: only a recognised strong check demotes; weak origin.includes stays a lead
    check("allowlist.includes(e.origin) is strong",
          _origin_strength("", None, "if(allowlist.includes(e.origin)){}") == "strong")
    check("e.origin === literal is strong",
          _origin_strength("", None, 'if(e.origin === "https://trusted.example"){}') == "strong")
    check("e.origin.includes('x') is weak",
          _origin_strength("", None, 'if(e.origin.includes("trusted")){}') == "weak")
    check("unrelated path.startsWith not an origin check",
          _origin_strength("", None, 'if(path.startsWith("/api")){}') == "none")


def test_round5_crossfile_and_body():
    # 15: arrow / assigned function is seen by the enclosing-fn resolver
    txt = "const ye = (e) => { node.innerHTML = e; };"
    pos = txt.index("innerHTML")
    enc = _enclosing_fn(txt, pos)
    check("arrow fn enclosing resolved", enc is not None and enc[0] == "ye" and "e" in enc[1])
    # 16: body: payload resolves to the object literal in the same file
    rs = request_shape("const payload = { role, name };\nfetch(u, { body: JSON.stringify(payload) });", 2)
    check("body var resolved to its object keys", sorted(rs["body_keys"]) == ["name", "role"])


def test_round5_persisted_and_response():
    # 19: a persisted-query send is tagged, not matched by name
    _b, g = _json_keys_and_gql({"extensions": {"persistedQuery": {"sha256Hash": "abc"}}})
    check("persisted query tagged", "@persisted" in g)
    # 17: sensitive response fields detected (nested)
    keys = _flatten({"user": {"email": "a@b.c", "role": "admin"}, "token": "x", "page": 1})
    sens = {k for k in keys if _SENSITIVE_KEY_RE.match(k)}
    check("sensitive response fields found", {"email", "role", "token"} <= sens and "page" not in sens)


def test_round5_money_delta():
    # 18: a money field the client SENDS -> business-logic lead
    tri = Triaged(endpoints=[{"host": "", "norm_path": "/cart/checkout", "path": "/cart/checkout",
                              "method": "POST", "body_keys": ["price", "item"], "query": [],
                              "party": "first", "in_scope": True, "where_found": "a.js:1"}])
    hist = {"sent": {("", "/cart/checkout"): {"body": {"price", "item"}, "query": set(), "gql": set()}}}
    classes = {ld.cls for ld, _ in _body_delta_leads(tri, hist)}
    check("client-controlled money field -> business-logic", "client-controlled-value" in classes)


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


def test_round6_fixes():
    # 1) taint RHS is read with balanced brackets, so a comma INSIDE a call no longer truncates it
    check("rhs keeps comma-in-parens", _rhs_slice("foo(a, location.hash);", 0) == "foo(a, location.hash)")
    check("multi-declarator RHS split", _definition_rhs("var a = 1, b = location.hash;", "a")[0] == "1")
    lab, _c = backtrace("var t = foo(a, location.hash); x.innerHTML = t;", ["t"], before=40)
    check("taint via 2nd call arg traced", lab == "location.hash")

    # 2) mock-path keeps strong markers only; ordinary filenames are not leads
    check("sample.js is not a mock path", not _MOCK_PATH_RE.search("/data/sample.js"))
    check("seed/stub not mock paths",
          not _MOCK_PATH_RE.search("/x/seed.ts") and not _MOCK_PATH_RE.search("/x/stub.js"))
    check("mock/dummy/fixture still mock",
          bool(_MOCK_PATH_RE.search("/mockData/u.json")) and bool(_MOCK_PATH_RE.search("/fixtures/a.yml")))

    # 3) EXPR collapses to {id} only as a WHOLE segment; a real EXPRESSION/myEXPR must not merge
    check("whole EXPR -> {id}", normalize_path("/orders/EXPR") == "/orders/{id}")
    check("EXPRESSION stays distinct", normalize_path("/api/EXPRESSION/x") == "/api/expression/x")
    check("myEXPR stays distinct", normalize_path("/a/myEXPR") == "/a/myexpr")

    # 4) only a real client ctor binds a baseURL — a bare foo({uri}) does not
    check("foo({uri}) is not a client", not _CLIENT_DEF_RE.search('const c = foo({ uri: "/x" })'))
    check("axios.create is a client", bool(_CLIENT_DEF_RE.search('const c = axios.create({ baseURL:"/a" })')))
    check("new ApolloClient is a client", bool(_CLIENT_DEF_RE.search('const c = new ApolloClient({ uri:"/g" })')))

    # 5) GraphQL op regex: anonymous ops have no name; a field named `query` is not an op
    check("anonymous query{ has no name", _gql_op_names("query{ me }") == set())
    check("query($id){ anon has no name", _gql_op_names("query($id:ID!){ me }") == set())
    check("named op extracted", _gql_op_names("query GetX($id:ID!){ x }") == {"GetX"})
    check("field named query not an op", _gql_op_names("query GetX { user { query manual } }") == {"GetX"})

    # 6) multipart field names come ONLY from Content-Disposition headers, not file bytes
    mp = ('Content-Disposition: form-data; name="role"\r\n\r\n<b name="evil">\r\n'
          'Content-Disposition: form-data; name="file"; filename="x.html"\r\n')
    check("multipart reads only CD-header names", _multipart_field_names(mp) == {"role", "file"})

    # 7) wildcard postMessage target: backtick + options-object forms, no stray-"*" false hit
    check("backtick wildcard target", bool(_WILDCARD_TARGET.search("w.postMessage(d, `*`)")))
    check("object targetOrigin wildcard", bool(_WILDCARD_TARGET.search("w.postMessage(d, { targetOrigin: '*' })")))
    check("3-arg wildcard target", bool(_WILDCARD_TARGET.search('w.postMessage(d, "*", t)')))
    check("select(\"*\") is not a target", not _WILDCARD_TARGET.search('q.select("*")'))

    # 8) a persisted (APQ) send with an operationName matches by NAME, not the @persisted sentinel
    _b, g = _json_keys_and_gql({"operationName": "GetUser", "variables": {"id": 1},
                                "extensions": {"persistedQuery": {"sha256Hash": "h"}}})
    check("persisted+name matched by name", g == {"GetUser"})
    _b, g2 = _json_keys_and_gql({"extensions": {"persistedQuery": {"sha256Hash": "h"}}})
    check("hash-only persisted still @persisted", g2 == {"@persisted"})
    # the delta is no longer silenced by a persisted send: a named mutation never sent is surfaced
    tri = Triaged(
        graphql=[{"operation": "mutation", "operationName": "DeleteUser", "variables": ["$id"],
                  "file": "a.js", "party": "first"}],
    )
    hist = {"sent": {("", "/graphql"): {"body": set(), "query": set(), "gql": {"@persisted", "GetUser"}}}}
    pairs = _body_delta_leads(tri, hist)
    gl = [ld for ld, _ in pairs if ld.cls == "graphql-unsent"]
    check("persisted no longer suppresses named-mutation delta", bool(gl))
    check("persisted caveat present on the lead", gl and "persisted queries" in gl[0].notes)

    # 9) a sink using an anonymous function's parameter is recorded (not silent)
    txt = "arr.forEach(function (e) { node.innerHTML = e });"
    check("anon-fn parameter detected", _anon_param_of_sink(txt, txt.index("innerHTML"), ["e"]) == "e")
    check("non-param not falsely anon", _anon_param_of_sink(txt, txt.index("innerHTML"), ["z"]) is None)
    anon_cl = {"sink_class": "html", "kind": "innerHTML", "party": "first", "untraced": True,
               "real_taint": False, "lead": False, "anon_param": "e", "crossfile_break": None,
               "caller_chain": ["e ⇐ parameter of an anonymous function (minify limit)"], "count": 1,
               "occurrences": [{"file": "app.js", "line": 10, "source": "node.innerHTML = e"}]}
    aut = [ld for ld, _ in _sink_leads(Triaged(sinks=[anon_cl]), set()) if ld.cls == "sink-untraced"]
    check("anon-fn sink surfaced, not silent", bool(aut))
    check("anon-fn sink note explains the break", aut and "ANONYMOUS function" in aut[0].notes)


def test_round7_direct_source():
    # a jsluice sink carries no arg_expr, so pass-2 recovers the RHS and checks it for a source
    # BEFORE reducing to root idents — a property-tailed source like `e.data` is no longer dropped
    # to the bare `e` (round 7). `addEventListener("message", e => innerHTML = e.data)` is a real
    # DOM-XSS, not an untraced/anonymous break.
    def direct(src):                                    # mirrors the pass-2 direct check exactly
        return source_label(_STRLIT_RE.sub(" ", _arg_expr("innerHTML", src)))
    check("e.data recovered as a source", direct('q.innerHTML = e.data') == "e.data")
    check("location.hash still direct", direct('el.innerHTML = location.hash') == "location.hash")
    # a plain-string literal containing a source token is NOT a source (stripped first)
    check("source token inside a string is not a source",
          direct('q.innerHTML = "please visit location.href now"') is None)
    # a template literal INTERPOLATING a source still counts (backticks are not stripped)
    check("templated source still detected",
          direct('q.innerHTML = `pre ${location.hash} post`') == "location.hash")
    # a genuinely sourceless value stays untraced (so panel.js-style sinks remain audit, not leads)
    check("sourceless value not a direct source", direct('q.innerHTML = props.body') is None)


def main() -> int:
    for fn in (test_normalize, test_callsites, test_taint, test_taint_minified,
               test_source_tightened, test_new_sinks, test_atob, test_chunk_runtime_missing,
               test_firebase_config, test_string_fold, test_request_body_parse,
               test_body_delta, test_untraced_cap, test_baseurl_join_and_guard,
               test_supabase_gadget, test_vuln_call_binding, test_batch_and_multipart,
               test_round5_fp_tightening, test_round5_origin, test_round5_crossfile_and_body,
               test_round5_persisted_and_response, test_round5_money_delta, test_scoring,
               test_round6_fixes, test_round7_direct_source):
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

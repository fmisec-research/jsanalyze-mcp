#!/usr/bin/env python3
"""Regression test that LOCKS the real-run failure shapes (critique point 12).

    PYTHONPATH=src python3 tests/test_regression.py

The old tests rode one synthetic happy-path fixture, so the shapes that actually bit
on real bundles were never regressions. This builds an ANONYMISED synthetic Burp XML
(no target data) exercising each failure and asserts the v2 behaviour:

  1. multi-hop taint:  var t = location.hash; … innerHTML = t   -> xss-sink lead w/ chain
     and dangerouslySetInnerHTML = f(t)                          -> discovered + traced
  2. webpack-4 webpackJsonp (no static/js/ template)             -> chunks w/ reconstructed URL
  3. SPA route /register vs API /api/v1/auth/login               -> route NOT auth; login IS auth
  4. postMessage listener without a sink                         -> demoted (severity low)
     postMessage listener whose handler flows data to innerHTML  -> high
  5. cookie *_token / localStorage access_token                  -> token-storage lead
  6. same key via two detectors + a public pk_ key               -> deduped; pk_ = public/info
  7. CSP connect-src internal host                               -> csp-endpoint lead
  8. request actually in traffic                                 -> seen_in_history True (vs False)
"""
from __future__ import annotations

import base64
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from jsanalyze.analyzers.chunks import map_chunks
from jsanalyze.analyzers.endpoints import decode_atob_endpoints, normalize_endpoints
from jsanalyze.analyzers.framework import detect_framework
from jsanalyze.analyzers.jsluice_wrapper import resolve_jsluice, run_jsluice
from jsanalyze.analyzers.postmessage import classify_postmessage
from jsanalyze.analyzers.routes import extract_routes
from jsanalyze.analyzers.sinks import triage_sinks
from jsanalyze.analyzers.strings import resolve_string_endpoints
from jsanalyze.analyzers.storage import scan_storage
from jsanalyze.enrichers.secret_classify import classify_secrets
from jsanalyze.leads.lead_engine import build_leads
from jsanalyze.models import Triaged
from jsanalyze.parsers.csp import collect_csp
from jsanalyze.parsers.history import collect_history
from jsanalyze.parsers.inputs import load_input
from jsanalyze.utils import workspace as W

SCOPE = ["target.tld"]

APP_JS = r"""
var t = location.hash.slice(1);
function render(x){ return {__html: x}; }
var node = document.getElementById("v");
node.dangerouslySetInnerHTML = render(t);
node.innerHTML = t;

window.addEventListener("message", function(e){ document.getElementById("o").innerHTML = e.data.body; });
window.addEventListener("message", function(ev){ track(ev.data); });

document.cookie = "rc_token=" + getJwt();
localStorage.setItem("access_token", tok);

function login(u,p){ return fetch("/api/v1/auth/login", {method:"POST", body: JSON.stringify({username:u, password:p})}); }
fetch("/api/v1/users/42/orders", {method:"GET"});
var routes = [{ path: "/register", component: Register }, { path: "/admin/users", component: AdminUsers }];
var apiKeyPublic = "pk_live_ABCDEFGHIJKLMNOP1234";
var stripeSecret = "sk_live_51ABCDEFGHIJKLMNOPQRSTUV";

// round 2: a base64-hidden endpoint, a new DOM sink, and a Firebase web config
var secretUrl = atob("L2FwaS92MS9zZWNyZXQ");
new DOMParser().parseFromString(location.search, "text/html");
var fb = {apiKey:"AIzaSyFAKE0000000000000000000000000000", authDomain:"demo.firebaseapp.com", projectId:"demo-1", databaseURL:"https://demo.firebaseio.com"};

// round 3: body-field the operator never sent, and a const+concat endpoint jsluice fragments
fetch("/api/v1/users/42", {method:"PATCH", body: JSON.stringify({role: newRole, locale: "en"})});
const ADMIN_API = "/api/v2";
fetch(ADMIN_API + "/admin/settings", {method:"GET"});
"""

RUNTIME_JS = r"""
(window.webpackJsonp=window.webpackJsonp||[]).push([[4],{}]);
n.p="https://cdn.target.tld/app/";
function jsonpScriptSrc(e){return n.p+e+"."+{3:"aaaa1111",4:"bbbb2222",8:"cccc3333"}[e]+".js"}
"""

INDEX_HTML = """<!doctype html><html><head>
<script src="/app/main.js"></script>
<script src="/app/3.aaaa1111.js"></script>
</head><body>hello</body></html>"""

CSP = ("default-src 'self'; connect-src 'self' https://internal-api.target.tld https://sentry.io; "
       "frame-src https://console.target.tld")


def _http(body: str, ctype: str, extra_headers: str = "") -> bytes:
    hdr = f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n{extra_headers}"
    return (hdr + "\r\n").encode() + b"\r\n" + body.encode()


def _item(url, host, method, mimetype, ext, body, ctype, extra_headers="", req_body=None):
    resp = base64.b64encode(_http(body, ctype, extra_headers)).decode()
    if req_body is not None:
        target = urlsplit(url).path or "/"
        req = (f"{method} {target} HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{req_body}")
        request_el = f'<request base64="true">{base64.b64encode(req.encode()).decode()}</request>'
    else:
        request_el = f'<request base64="false">{method} / HTTP/1.1</request>'
    return f"""  <item>
    <url>{url}</url>
    <host ip="10.0.0.1">{host}</host>
    <method>{method}</method>
    <status>200</status>
    <mimetype>{mimetype}</mimetype>
    <extension>{ext}</extension>
    {request_el}
    <response base64="true">{resp}</response>
  </item>"""


def _build_xml(path: Path) -> None:
    items = [
        _item("https://target.tld/app/main.js", "target.tld", "GET", "script", "js", APP_JS, "application/javascript"),
        _item("https://cdn.target.tld/app/runtime.js", "cdn.target.tld", "GET", "script", "js", RUNTIME_JS, "application/javascript"),
        _item("https://target.tld/", "target.tld", "GET", "HTML", "html", INDEX_HTML, "text/html",
              extra_headers=f"Content-Security-Policy: {CSP}\r\n"),
        # real API traffic the operator DID send (establishes history):
        _item("https://target.tld/api/v1/users/42/orders", "target.tld", "GET", "JSON", "", '{"ok":1}', "application/json"),
        # a GET to /api/v1/profile and a POST to /graphql — used to prove PATH-FIRST
        # matching (the JS rows for these carry NO / a different method).
        _item("https://target.tld/api/v1/profile", "target.tld", "GET", "JSON", "", '{"ok":1}', "application/json"),
        _item("https://target.tld/graphql", "target.tld", "POST", "JSON", "", '{"data":{}}', "application/json"),
        # the operator PATCHed /api/v1/users/42 but sent ONLY {locale} — never the {role}
        # field the bundle can also send (body-delta -> body-field-unsent on `role`).
        _item("https://target.tld/api/v1/users/42", "target.tld", "PATCH", "JSON", "", '{"ok":1}',
              "application/json", req_body='{"locale":"en"}'),
    ]
    xml = '<?xml version="1.0"?>\n<items burpVersion="2024">\n' + "\n".join(items) + "\n</items>\n"
    path.write_text(xml, encoding="utf-8")


def _run(xml: Path, run):
    cfg = W.load_config()
    js_items, map_items, chunk_refs = load_input(xml, scope_hosts=SCOPE, out_dir=run.js_dir)
    history = collect_history(xml, SCOPE)
    csp = collect_csp(xml, SCOPE)
    routes = extract_routes(js_items, cfg=cfg)
    a = run_jsluice(js_items, cfg=cfg)
    # simulate a LinkFinder hit on the SPA route /register: it must NOT override the route
    # classification (regression for the real-pipeline bug where a linkfinder-typed row
    # upgraded the /register route to an `api` auth-endpoint).
    extra_urls = [{"url": "/register", "type": "linkfinder", "method": "", "detector": "linkfinder",
                   "filename": "main.js", "source_file": "main.js"},
                  # these carry NO method (jsluice urls rows don't) — PATH-FIRST must still
                  # match them to the GET /api/v1/profile and POST /graphql in history.
                  {"url": "/api/v1/profile", "type": "stringLiteral", "method": "",
                   "detector": "jsluice", "filename": "main.js", "source_file": "main.js"},
                  {"url": "/graphql", "type": "stringLiteral", "method": "",
                   "detector": "jsluice", "filename": "main.js", "source_file": "main.js"}]
    extra_urls += decode_atob_endpoints(js_items)        # base64-hidden endpoints
    extra_urls += resolve_string_endpoints(js_items)     # const+concat folding (round 3 pt 3)
    tri = Triaged(
        endpoints=normalize_endpoints(list(a.urls) + extra_urls, js_items, cfg, SCOPE,
                                      route_paths=[r["path"] for r in routes], history=history),
        sinks=triage_sinks(a.sinks, js_items, cfg, SCOPE),
        postmessage=classify_postmessage(a.postmessage, js_items, cfg, SCOPE),
        secrets=classify_secrets(list(a.secrets)),
        routes=routes,
        storage=scan_storage(js_items, cfg),
        chunks=map_chunks(js_items, cfg=cfg),
        framework=detect_framework(js_items, cfg=cfg),
        csp=csp.get("directives", []),
    )
    leads = build_leads(tri, cfg=cfg, history=history, scope_hosts=SCOPE)
    return tri, leads, history, csp


def main() -> int:
    assert resolve_jsluice(), "jsluice not resolvable — run setup"
    run = W.new_run("regression")
    with tempfile.TemporaryDirectory() as td:
        xml = Path(td) / "synthetic.xml"
        _build_xml(xml)
        try:
            tri, leads, history, csp = _run(xml, run)
            checks = _assert_all(tri, leads, history, csp)
        finally:
            import shutil
            shutil.rmtree(run.dir, ignore_errors=True)
    for name in checks:
        print(f"  ✓ {name}")
    print("\n✅ REGRESSION (real-run failure shapes) LOCKED")
    return 0


def _assert_secret_classifier() -> None:
    """Unit: dedupe the same value across detectors into one record w/ both detectors,
    and classify public (pk_/DSN/analytics=info) vs private (sk_live=high) vs unknown
    (AIza Google key = medium, 'check restriction' — not auto-high)."""
    recs = [
        {"detector": "jsluice", "kind": "stripe", "data": {"key": "pk_live_ABC1234567890DEF"}},
        {"detector": "jsluice", "kind": "aws", "data": {"key": "AKIAIOSFODNN7EXAMPLE"}},
        {"detector": "gitleaks", "kind": "aws", "data": {"secret": "AKIAIOSFODNN7EXAMPLE"}},  # dup value
        {"detector": "jsluice", "kind": "google", "data": {"key": "AIzaSyA1234567890abcdefghijklmnopqrstuvZ"}},
        {"detector": "jsluice", "kind": "stripe", "data": {"key": "sk_live_51ABCDEFGHIJKLMNOP"}},
    ]
    out = classify_secrets(recs)
    assert len(out) == 4, f"dedup by value failed (expected 4, got {len(out)})"
    aws = [r for r in out if "AKIA" in str(r.get("data"))][0]
    assert set(aws["detectors"]) == {"jsluice", "gitleaks"}, f"detectors not merged: {aws['detectors']}"
    assert aws["severity"] == "high" and aws["visibility"] == "private"
    pk = [r for r in out if "pk_live" in str(r.get("data"))][0]
    assert pk["visibility"] == "public" and pk["severity"] == "info", f"pk_ not public/info: {pk}"
    aiza = [r for r in out if "AIza" in str(r.get("data"))][0]
    assert aiza["visibility"] == "unknown" and aiza["severity"] == "medium", f"AIza not unknown/medium: {aiza}"
    sk = [r for r in out if "sk_live" in str(r.get("data"))][0]
    assert sk["visibility"] == "private" and sk["severity"] == "high"


def _assert_all(tri, leads, history, csp) -> list:
    by_cls = {}
    for ld in leads:
        by_cls.setdefault(ld["class"], []).append(ld)
    done = []

    # 1) multi-hop taint -> xss-sink with a chain that reaches location.hash
    xss = by_cls.get("xss-sink", [])
    assert xss, "no xss-sink lead from multi-hop taint"
    assert any("location.hash" in " ".join(l.get("caller_chain") or []) or
               "location.hash" in (l.get("title") or "") for l in xss), \
        f"multi-hop chain to location.hash missing: {[l.get('caller_chain') for l in xss]}"
    assert any(l["class"] == "xss-sink" and "dangerouslySetInnerHTML" in (l.get("title") or "")
               for l in leads), "dangerouslySetInnerHTML sink (jsluice-invisible) not discovered"
    done.append("multi-hop taint innerHTML=t AND dangerouslySetInnerHTML=f(t) traced to location.hash")

    # 2) webpack-4 webpackJsonp chunk map with reconstructed URLs
    miss = [c for c in tri.chunks if c.get("present") is False and c.get("url")]
    assert any("cdn.target.tld/app/" in (c.get("url") or "") for c in miss), \
        f"webpack-4 chunk URLs not reconstructed: {tri.chunks}"
    done.append(f"webpack-4 webpackJsonp -> {len(miss)} missing chunks w/ reconstructed URL")

    # 3) /register is a route (NOT auth-endpoint); /api/v1/auth/login IS auth
    auth_paths = {l.get("evidence", "") for l in by_cls.get("auth-endpoint", [])}
    assert any("/api/v1/auth/login" in e for e in auth_paths), f"login not auth-endpoint: {auth_paths}"
    assert not any("/register" in e for e in auth_paths), f"/register wrongly classified as auth: {auth_paths}"
    done.append("/register = SPA route (not auth); /api/v1/auth/login = auth-endpoint")

    # 4) listener without sink demoted; listener with data->innerHTML high
    pml = by_cls.get("postmessage-listener", [])
    sev = sorted(l.get("severity_hint") for l in pml)
    assert "high" in [l.get("severity_hint") for l in pml], f"sink-reaching listener not high: {pml}"
    assert "low" in [l.get("severity_hint") for l in pml], f"no-sink listener not demoted to low: {pml}"
    done.append("postMessage: data->innerHTML listener=high, no-sink listener=low (demoted)")

    # 5) cookie *_token / access_token -> token-storage lead
    ts = by_cls.get("token-storage", [])
    assert any("rc_token" in (l.get("evidence") or l.get("title") or "") for l in ts) or \
           any("access_token" in (l.get("title") or "") for l in ts), f"token storage not a lead: {ts}"
    done.append("client-stored *_token / access_token -> token-storage lead (hunt-auth-bypass)")

    # 6) sk_live surfaced as a HIGH private secret (scanners don't flag pk_ publishable
    #    keys at all — correctly — so the public/private split is unit-tested below)
    secs = by_cls.get("secret-location", [])
    assert any(l.get("severity_hint") == "high" for l in secs), f"sk_live not high: {secs}"
    _assert_secret_classifier()
    done.append("sk_live=high; classifier: dedup-across-detectors + public/private (unit)")

    # 7) CSP connect-src internal host -> csp-endpoint lead
    cspl = by_cls.get("csp-endpoint", [])
    assert any("internal-api.target.tld" in (l.get("evidence") or "") for l in cspl), \
        f"CSP internal host not surfaced: {cspl}"
    assert not any("sentry.io" in (l.get("evidence") or "") for l in cspl), "benign sentry.io wrongly surfaced"
    done.append("CSP connect-src internal-api.target.tld -> csp-endpoint (sentry.io filtered)")

    # 8) history delta: the GET /api/v1/users/42/orders WAS in traffic
    assert history.get("known"), "history not detected from XML items"
    orders = [n for n in tri.endpoints if "/orders" in n.get("path", "")]
    assert any(n.get("seen_in_history") is True for n in orders), \
        f"endpoint exercised in traffic not flagged seen_in_history: {[(n['path'], n.get('seen_in_history')) for n in orders]}"
    done.append("history delta: /api/v1/users/{id}/orders seen_in_history=True")

    # 9) PATH-FIRST history (round 2 pt 1): a bundle endpoint with NO method still matches a
    #    GET request to the same path; a different method (POST /graphql) matches too.
    profile = [n for n in tri.endpoints if n.get("norm_path") == "/api/v1/profile"]
    assert profile, "profile endpoint missing"
    assert not profile[0].get("method"), "profile should have empty method (the whole point)"
    assert profile[0].get("seen_in_history") is True, \
        f"empty-method endpoint not matched to GET history (method-mismatch bug): {profile[0]}"
    gq = [n for n in tri.endpoints if n.get("norm_path") == "/graphql"]
    assert gq and gq[0].get("seen_in_history") is True, \
        f"/graphql not matched to POST /graphql history: {gq}"
    done.append("path-first history: no-method /api/v1/profile & /graphql match GET/POST traffic")

    # 10) atob("…") base64-hidden endpoint surfaced
    secret_eps = [n for n in tri.endpoints if n.get("norm_path") == "/api/v1/secret"]
    assert secret_eps and secret_eps[0].get("detector") == "atob", \
        f"base64-hidden endpoint (atob) not surfaced: {secret_eps}"
    done.append("atob(\"…\") decoded -> /api/v1/secret endpoint (detector=atob)")

    # 11) new DOM sink traced: DOMParser.parseFromString(location.search) -> xss-sink
    assert any("parseFromString" in (l.get("title") or "") for l in by_cls.get("xss-sink", [])), \
        f"parseFromString(location.search) not traced to an xss-sink: {by_cls.get('xss-sink')}"
    done.append("new sink parseFromString(location.search) -> xss-sink")

    # 12) Firebase config -> ONE hunt-cloud lead; the lone AIza is folded, not a 2nd secret
    cloud = by_cls.get("cloud-config", [])
    assert cloud and cloud[0]["suggested_skill"] == "hunt-cloud", \
        f"firebase config not a hunt-cloud cloud-config lead: {cloud}"
    assert not any("AIzaSyFAKE" in (l.get("evidence") or "") for l in by_cls.get("secret-location", [])), \
        "firebase AIza key NOT folded — still a lone secret-location lead"
    done.append("Firebase config -> 1 hunt-cloud lead; lone AIza folded (not duplicated)")

    # 13) a JS-only capture must NOT look like exercised API surface
    _assert_js_only_history()
    done.append("JS-only capture: known=True but api_known=False (no false 'untested API')")

    # 14) body delta (round 3 pt 1): the bundle can PATCH {role} but the operator sent only
    #     {locale} -> body-field-unsent on `role` (authz field), locale stays silent
    bf = by_cls.get("body-field-unsent", [])
    assert any("role" in (l.get("body_keys") or []) for l in bf), \
        f"authz field the bundle sends but operator never did not flagged: {bf}"
    assert not any("locale" in (l.get("body_keys") or []) for l in bf), \
        "benign field `locale` wrongly promoted"
    done.append("body delta: bundle sends {role} never in traffic -> body-field-unsent (locale ignored)")

    # 15) string-const folding (round 3 pt 3): const ADMIN_API='/api/v2'; fetch(ADMIN_API+'/admin/settings')
    folded = [n for n in tri.endpoints if n.get("norm_path") == "/api/v2/admin/settings"]
    assert folded, f"const+concat endpoint not folded into one path: {[n['norm_path'] for n in tri.endpoints]}"
    done.append("string folding: ADMIN_API + '/admin/settings' -> /api/v2/admin/settings (one endpoint)")

    # scoring sanity: the top lead is not a postMessage listener
    top = sorted(leads, key=lambda l: -float(l.get("score") or 0))[0]
    assert not top["class"].startswith("postmessage"), f"a postMessage lead is top of queue: {top}"
    done.append(f"composite score: top lead is {top['class']} (score={top['score']}), not a listener")
    return done


def _assert_js_only_history() -> None:
    """round 2 pt 1: a Burp export of only .js responses records traffic (known=True) but
    is NOT evidence the API was exercised (api_known=False) — so bundle endpoints must not
    be minted as endpoint-unverified 'untested surface'."""
    with tempfile.TemporaryDirectory() as td:
        # a passive page load: the HTML root + its static JS — NO backend API call
        xml = Path(td) / "jsonly.xml"
        items = [
            _item("https://target.tld/", "target.tld", "GET", "HTML", "html", "<html></html>", "text/html"),
            _item("https://target.tld/static/js/app.js", "target.tld", "GET", "script", "js",
                  'fetch("/api/v1/widget",{method:"GET"});', "application/javascript"),
        ]
        xml.write_text('<?xml version="1.0"?>\n<items>\n' + "\n".join(items) + '\n</items>\n',
                       encoding="utf-8")
        h = collect_history(xml, SCOPE)
        assert h["known"] is True, "the GETs are still traffic"
        assert h["api_known"] is False, f"a page-load (HTML+JS, no API) must not be api_known: {h}"
        # add one real API call -> now api_known flips True
        xml2 = Path(td) / "withapi.xml"
        items.append(_item("https://target.tld/api/v1/thing", "target.tld", "GET", "JSON", "",
                           '{"ok":1}', "application/json"))
        xml2.write_text('<?xml version="1.0"?>\n<items>\n' + "\n".join(items) + '\n</items>\n',
                        encoding="utf-8")
        assert collect_history(xml2, SCOPE)["api_known"] is True, "a real API call must set api_known"


if __name__ == "__main__":
    try:
        sys.exit(main())
    except AssertionError as e:
        print(f"\n❌ REGRESSION ASSERTION FAILED: {e}")
        sys.exit(1)

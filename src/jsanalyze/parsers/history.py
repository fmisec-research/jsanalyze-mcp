"""Capture the REQUEST history already present in the input (critique point 2).

A Burp XML export does not only contain the JS — every ``<item>`` records a
request the operator actually sent (``<method>`` + ``<url>``, and the full
``<request>`` blob). A HAR likewise lists every request. That captured traffic is
the ground truth of "what has already been exercised". Comparing it against the
endpoints we extract from the JS yields the single most valuable lead class: a
first-party, in-scope endpoint that lives in the bundle but was NEVER requested —
untested surface.

This module reads that history with ZERO network (it only re-reads the same local
file) and returns a membership set of normalized keys plus a transparent entry
list (written to ``history.json``). For a plain directory of ``.js`` there is no
traffic, so ``known=False`` and the delta is simply not claimed.

Contract: ``collect_history(path, scope_hosts=None) -> dict`` with::

    {"known": bool, "api_known": bool, "count": int,
     "keys": set[(method, host, norm_path)],          # method-sensitive (legacy)
     "path_keys": set[(host, norm_path)],             # method-AGNOSTIC (primary)
     "api_path_keys": set[(host, norm_path)],         # non-asset requests only
     "methods": {(host, norm_path): set(method)},     # method booster
     "entries": [{"method","host","path","norm","asset"}], "hosts": [..]}

Matching is PATH-FIRST (critique round 2, point 1): an endpoint extracted from JS
usually has no method (jsluice ``urls`` rows carry none), so a method-sensitive key
can never meet a ``GET`` request and every path would look untested. We therefore
compare on ``(host, norm_path)`` and treat the method only as a confirmation. And a
Burp export that holds nothing but ``.js`` responses is NOT evidence the API was
exercised — ``api_known`` is true only when at least one NON-asset request exists; we
do not claim ``seen_in_history`` (or emit ``endpoint-unverified``) without it.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

from jsanalyze.parsers.burp_parser import (
    _decode_body, _header_value, _maybe_b64, _split_http,
)
from jsanalyze.utils.normalize import history_key, looks_like_asset_path, normalize_path

__all__ = ["collect_history"]

_GQL_OP_RE = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_]\w*)")
_MULTIPART_NAME_RE = re.compile(r"""name\s*=\s*["']([^"'\r\n]{1,80})["']""")
# request headers that are the replay recipe for an endpoint lead (names only; values masked)
_AUTH_HEADERS = frozenset({
    "authorization", "x-api-key", "x-auth-token", "x-access-token", "x-csrf-token",
    "x-xsrf-token", "api-key", "authentication", "x-amz-security-token", "x-auth",
})


def _in_scope(host: str, scope_hosts) -> bool:
    if not host:
        return True
    if not scope_hosts:
        return True
    scope = {h.lower().lstrip("*.") for h in scope_hosts}
    return any(host == s or host.endswith("." + s) for s in scope)


def _entry(method: str, url: str):
    parts = urlsplit(url or "")
    host = parts.netloc.split("@")[-1].split(":")[0].lower()
    path = parts.path or "/"
    is_ws = parts.scheme in ("ws", "wss")
    return {
        "method": (method or "").upper(),
        "host": host,
        "path": path,
        "norm": path if is_ws else normalize_path(path),
        "asset": (not is_ws) and looks_like_asset_path(path),
    }


def _json_keys_and_gql(obj, depth: int = 2) -> "tuple[set, set]":
    """Body keys (NESTED, flattened to ``depth``) and GraphQL operation names.

    Handles the three shapes operators actually send (round 4, point 3): a plain object
    (``{user:{role}}`` yields ``user`` AND ``role``), a GraphQL body
    (``{query,operationName,variables}`` → the op name + variable keys), and an Apollo
    BATCH array ``[{query,…},{query,…}]`` → every operation in the batch.
    """
    bkeys: set = set()
    gql: set = set()

    def walk(o, d):
        if isinstance(o, dict):
            # Apollo persisted query: a POST with only a hash, no operationName — mark it so
            # the bundle's named ops are NOT falsely reported as "never sent" (round 5 pt 19).
            if isinstance(o.get("extensions"), dict) and "persistedQuery" in o["extensions"]:
                gql.add("@persisted")
            if isinstance(o.get("query"), str) and (
                    "operationName" in o or "variables" in o or _GQL_OP_RE.search(o["query"])):
                op = o.get("operationName")
                if isinstance(op, str) and op:
                    gql.add(op)
                else:
                    gql.update(_GQL_OP_RE.findall(o["query"]))
                if isinstance(o.get("variables"), dict):
                    for k, v in o["variables"].items():
                        bkeys.add(str(k))
                        if d > 0:
                            walk(v, d - 1)
                return
            for k, v in o.items():
                bkeys.add(str(k))
                if d > 0:
                    walk(v, d - 1)
        elif isinstance(o, list):
            for item in o[:25]:                          # Apollo batch: each element
                walk(item, d)

    walk(obj, depth)
    return bkeys, gql


def _collect_auth(headers) -> dict:
    auth = {"headers": set(), "cookies": set()}
    for n, v in headers:
        nl = n.lower()
        if nl in _AUTH_HEADERS:
            auth["headers"].add(n)
        elif nl == "cookie":
            for c in (v or "").split(";"):
                name = c.split("=", 1)[0].strip()
                if name:
                    auth["cookies"].add(name)
    return auth


def _parse_request_fields(req_bytes: bytes):
    """(query_keys, body_keys, gql_ops, auth) actually present in a captured request — zero
    network, reusing the same HTTP decoder as the response path. ``auth`` carries the names
    (never values) of auth headers / session cookies — the replay recipe (point 5)."""
    qkeys: set = set()
    bkeys: set = set()
    gql: set = set()
    auth = {"headers": set(), "cookies": set()}
    if not req_bytes:
        return qkeys, bkeys, gql, auth
    try:
        line, headers, body = _split_http(req_bytes)
        body = _decode_body(body, headers)
        auth = _collect_auth(headers)
        target = line.split(" ", 2)[1] if " " in line else ""
        qs = urlsplit(target).query
        for kv in qs.split("&"):
            if kv:
                qkeys.add(kv.split("=", 1)[0])
        if "query=" in qs:                               # GraphQL over GET
            qd = parse_qs(qs)
            for qv in qd.get("query", []):
                gql.update(_GQL_OP_RE.findall(unquote(qv)))
            for ov in qd.get("operationName", []):
                if ov:
                    gql.add(ov)
        text = body.decode("utf-8", "replace").strip() if body else ""
        ctype = (_header_value(headers, "Content-Type") or "").lower()
        if text and ("json" in ctype or text[:1] in "{["):
            try:
                bkeys, g2 = _json_keys_and_gql(json.loads(text))
                gql |= g2
            except (ValueError, TypeError):
                pass
        elif "multipart/form-data" in ctype and text:
            bkeys.update(_MULTIPART_NAME_RE.findall(text))
        elif text and ("form-urlencoded" in ctype or ("=" in text and "{" not in text)):
            for kv in text.split("&"):
                if "=" in kv:
                    bkeys.add(kv.split("=", 1)[0])
    except Exception:
        pass
    return qkeys, bkeys, gql, auth


def _add_sent(out, host, norm, qkeys, bkeys, gql, auth=None) -> None:
    for h in (host, ""):
        e = out["sent"].setdefault(
            (h, norm), {"query": set(), "body": set(), "gql": set(),
                        "auth_headers": set(), "cookies": set()})
        e["query"].update(qkeys)
        e["body"].update(bkeys)
        e["gql"].update(gql)
        if auth:
            e["auth_headers"].update(auth.get("headers", ()))
            e["cookies"].update(auth.get("cookies", ()))
            out["auth_headers"].update(auth.get("headers", ()))
            out["auth_cookies"].update(auth.get("cookies", ()))


def collect_history(path, scope_hosts=None) -> dict:
    p = Path(path)
    out = {"known": False, "api_known": False, "count": 0, "keys": set(),
           "path_keys": set(), "api_path_keys": set(), "methods": {},
           "sent": {}, "auth_headers": set(), "auth_cookies": set(),
           "entries": [], "hosts": []}
    try:
        suf = p.suffix.lower()
        if p.is_dir():
            return out                                   # no traffic in a dir of .js
        if suf == ".har":
            _from_har(p, scope_hosts, out)
        elif suf in (".xml", ".burp") or _looks_like_xml(p):
            _from_xml(p, scope_hosts, out)
        else:
            return out                                   # single .js: no traffic
    except Exception:
        # history is best-effort; a parse failure just means "unknown", not an error
        return out
    out["hosts"] = sorted({e["host"] for e in out["entries"] if e["host"]})
    out["count"] = len(out["entries"])
    out["known"] = out["count"] > 0
    # "the API was exercised" requires at least one non-asset request — a capture of
    # only .js/.css responses does NOT make bundle endpoints 'untested surface'.
    out["api_known"] = bool(out["api_path_keys"])
    return out


def _record(out, method, url, scope_hosts):
    if not url:
        return None
    e = _entry(method, url)
    if not _in_scope(e["host"], scope_hosts):
        return None
    out["entries"].append(e)
    m, host, norm = e["method"], e["host"], e["norm"]
    key = history_key(method, url)
    out["keys"].add(key)
    # a rooted endpoint extracted from JS carries no host (``/api/x``); add a hostless
    # variant so it still matches this host-qualified request within the same scope.
    out["keys"].add((key[0], "", key[2]))
    # "exercised the API" means a real backend call — NOT an asset, NOT the site root,
    # NOT a static HTML document. A capture of just {GET /, GET /static/*.js} is a passive
    # page load; it must not make every bundle endpoint look like untested surface.
    is_api = (not e["asset"] and norm != "/"
              and not norm.lower().endswith((".html", ".htm")))
    # PATH-FIRST membership: method-agnostic (host, norm) + hostless, and the set of
    # methods actually seen on that path (a booster, not a gate).
    for h in (host, ""):
        out["path_keys"].add((h, norm))
        out["methods"].setdefault((h, norm), set()).add(m)
        if is_api:
            out["api_path_keys"].add((h, norm))
    return e


def _from_xml(xml_path, scope_hosts, out) -> None:
    for _ev, el in ET.iterparse(str(xml_path), events=("end",)):
        if el.tag != "item":
            continue
        method = (el.findtext("method") or "").strip()
        url = (el.findtext("url") or "").strip()
        # the <request> blob carries the body the operator ACTUALLY sent — jsluice/jxscout
        # never see authenticated traffic; we do. Parse it before clearing the element.
        req_bytes = _maybe_b64(el.find("request"))
        el.clear()
        e = _record(out, method, url, scope_hosts)
        if e is not None and req_bytes:
            q, b, g, auth = _parse_request_fields(req_bytes)
            if q or b or g or auth["headers"] or auth["cookies"]:
                _add_sent(out, e["host"], e["norm"], q, b, g, auth)


def _har_postdata_fields(req):
    qkeys: set = set()
    bkeys: set = set()
    gql: set = set()
    auth = {"headers": set(), "cookies": set()}
    if not isinstance(req, dict):
        return qkeys, bkeys, gql, auth
    for kv in urlsplit(req.get("url", "")).query.split("&"):
        if kv:
            qkeys.add(kv.split("=", 1)[0])
    # auth headers / cookies from the HAR request
    auth = _collect_auth([(h.get("name", ""), h.get("value", ""))
                          for h in (req.get("headers") or []) if isinstance(h, dict)])
    for c in (req.get("cookies") or []):
        if isinstance(c, dict) and c.get("name"):
            auth["cookies"].add(str(c["name"]))
    pd = req.get("postData") if isinstance(req, dict) else None
    if isinstance(pd, dict):
        params = pd.get("params")
        if isinstance(params, list):
            bkeys.update(str(p.get("name")) for p in params if isinstance(p, dict) and p.get("name"))
        text = pd.get("text")
        mime = (pd.get("mimeType") or "").lower()
        if isinstance(text, str) and text.strip():
            t = text.strip()
            if "json" in mime or t[:1] in "{[":
                try:
                    bkeys2, gql = _json_keys_and_gql(json.loads(t))
                    bkeys.update(bkeys2)
                except (ValueError, TypeError):
                    pass
            elif "multipart/form-data" in mime:
                bkeys.update(_MULTIPART_NAME_RE.findall(t))
            elif "form-urlencoded" in mime or ("=" in t and "{" not in t):
                for kv in t.split("&"):
                    if "=" in kv:
                        bkeys.add(kv.split("=", 1)[0])
    return qkeys, bkeys, gql, auth


def _from_har(har_path, scope_hosts, out) -> None:
    with open(har_path, encoding="utf-8", errors="replace") as fh:
        har = json.load(fh)
    for ent in har.get("log", {}).get("entries", []) or []:
        req = ent.get("request", {}) if isinstance(ent, dict) else {}
        e = _record(out, req.get("method", ""), req.get("url", ""), scope_hosts)
        if e is not None:
            q, b, g, auth = _har_postdata_fields(req)
            if q or b or g or auth["headers"] or auth["cookies"]:
                _add_sent(out, e["host"], e["norm"], q, b, g, auth)


def _looks_like_xml(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(256).lstrip()[:1] == b"<"
    except OSError:
        return False

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
from urllib.parse import urlsplit

from jsanalyze.parsers.burp_parser import (
    _decode_body, _header_value, _maybe_b64, _split_http,
)
from jsanalyze.utils.normalize import history_key, looks_like_asset_path, normalize_path

__all__ = ["collect_history"]

_GQL_OP_RE = re.compile(r"\b(?:query|mutation|subscription)\s+([A-Za-z_]\w*)")


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


def _json_keys_and_gql(obj) -> "tuple[set, set]":
    """Top-level body keys, and GraphQL operation names if this is a GraphQL POST.

    A GraphQL body is ``{"query":"…","operationName":"X","variables":{…}}`` — its real
    'fields' are the variables + the operation name, not the literal keys query/variables.
    """
    bkeys: set = set()
    gql: set = set()
    if isinstance(obj, dict):
        if "query" in obj and isinstance(obj.get("query"), str) and (
                "operationName" in obj or "variables" in obj or _GQL_OP_RE.search(obj["query"])):
            op = obj.get("operationName")
            if isinstance(op, str) and op:
                gql.add(op)
            else:
                gql.update(_GQL_OP_RE.findall(obj["query"]))
            if isinstance(obj.get("variables"), dict):
                bkeys.update(str(k) for k in obj["variables"].keys())
        else:
            bkeys.update(str(k) for k in obj.keys())
    elif isinstance(obj, list) and obj and isinstance(obj[0], dict):
        bkeys.update(str(k) for k in obj[0].keys())
    return bkeys, gql


def _parse_request_fields(req_bytes: bytes) -> "tuple[set, set, set]":
    """(query_keys, body_keys, gql_ops) actually present in a captured request — zero
    network, reusing the same HTTP decoder as the response path."""
    qkeys: set = set()
    bkeys: set = set()
    gql: set = set()
    if not req_bytes:
        return qkeys, bkeys, gql
    try:
        line, headers, body = _split_http(req_bytes)
        body = _decode_body(body, headers)
        target = line.split(" ", 2)[1] if " " in line else ""
        for kv in urlsplit(target).query.split("&"):
            if kv:
                qkeys.add(kv.split("=", 1)[0])
        text = body.decode("utf-8", "replace").strip() if body else ""
        ctype = (_header_value(headers, "Content-Type") or "").lower()
        if text and ("json" in ctype or text[:1] in "{["):
            try:
                bkeys, gql = _json_keys_and_gql(json.loads(text))
            except (ValueError, TypeError):
                pass
        elif text and ("form-urlencoded" in ctype or ("=" in text and "{" not in text)):
            for kv in text.split("&"):
                if "=" in kv:
                    bkeys.add(kv.split("=", 1)[0])
    except Exception:
        pass
    return qkeys, bkeys, gql


def _add_sent(out, host, norm, qkeys, bkeys, gql) -> None:
    for h in (host, ""):
        e = out["sent"].setdefault((h, norm), {"query": set(), "body": set(), "gql": set()})
        e["query"].update(qkeys)
        e["body"].update(bkeys)
        e["gql"].update(gql)


def collect_history(path, scope_hosts=None) -> dict:
    p = Path(path)
    out = {"known": False, "api_known": False, "count": 0, "keys": set(),
           "path_keys": set(), "api_path_keys": set(), "methods": {},
           "sent": {}, "entries": [], "hosts": []}
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
            q, b, g = _parse_request_fields(req_bytes)
            if q or b or g:
                _add_sent(out, e["host"], e["norm"], q, b, g)


def _har_postdata_fields(req) -> "tuple[set, set, set]":
    pd = req.get("postData") if isinstance(req, dict) else None
    if not isinstance(pd, dict):
        return set(), set(), set()
    qkeys: set = set()
    for kv in urlsplit(req.get("url", "")).query.split("&"):
        if kv:
            qkeys.add(kv.split("=", 1)[0])
    bkeys: set = set()
    gql: set = set()
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
        elif "form-urlencoded" in mime or ("=" in t and "{" not in t):
            for kv in t.split("&"):
                if "=" in kv:
                    bkeys.add(kv.split("=", 1)[0])
    return qkeys, bkeys, gql


def _from_har(har_path, scope_hosts, out) -> None:
    with open(har_path, encoding="utf-8", errors="replace") as fh:
        har = json.load(fh)
    for ent in har.get("log", {}).get("entries", []) or []:
        req = ent.get("request", {}) if isinstance(ent, dict) else {}
        e = _record(out, req.get("method", ""), req.get("url", ""), scope_hosts)
        if e is not None:
            q, b, g = _har_postdata_fields(req)
            if q or b or g:
                _add_sent(out, e["host"], e["norm"], q, b, g)


def _looks_like_xml(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(256).lstrip()[:1] == b"<"
    except OSError:
        return False

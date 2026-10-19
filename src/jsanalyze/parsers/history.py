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
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

from jsanalyze.utils.normalize import history_key, looks_like_asset_path, normalize_path

__all__ = ["collect_history"]


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


def collect_history(path, scope_hosts=None) -> dict:
    p = Path(path)
    out = {"known": False, "api_known": False, "count": 0, "keys": set(),
           "path_keys": set(), "api_path_keys": set(), "methods": {},
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
        return
    e = _entry(method, url)
    if not _in_scope(e["host"], scope_hosts):
        return
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


def _from_xml(xml_path, scope_hosts, out) -> None:
    for _ev, el in ET.iterparse(str(xml_path), events=("end",)):
        if el.tag != "item":
            continue
        method = (el.findtext("method") or "").strip()
        url = (el.findtext("url") or "").strip()
        el.clear()
        _record(out, method, url, scope_hosts)


def _from_har(har_path, scope_hosts, out) -> None:
    with open(har_path, encoding="utf-8", errors="replace") as fh:
        har = json.load(fh)
    for ent in har.get("log", {}).get("entries", []) or []:
        req = ent.get("request", {}) if isinstance(ent, dict) else {}
        _record(out, req.get("method", ""), req.get("url", ""), scope_hosts)


def _looks_like_xml(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(256).lstrip()[:1] == b"<"
    except OSError:
        return False

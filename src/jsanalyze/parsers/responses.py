"""Read what the operator's requests RETURNED (critique round 5, points 17 & 20).

jsluice and crawlers never see authenticated RESPONSES; a Burp/HAR export does. Two
signals live there and nowhere else, at zero network cost:

  * JSON responses whose keys include sensitive fields (``token``/``secret``/``email``/
    ``role``/``ssn``/…) — excessive data exposure (API3 / over-fetch) and token leakage,
    and a pivot to IDOR on the object's id fields.
  * Captured HTML whose markup carries inline event handlers (``onclick=``/``onerror=``…)
    or ``href="javascript:…"`` — DOM-ish sinks jsluice (which only reads ``<script>`` JS)
    never reports.

``collect_responses(path, scope_hosts) -> {"overfetch": [...], "html_sinks": [...]}``.
Pure, stdlib-only, decodes with the same HTTP helpers as the JS path, never fetches.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

from jsanalyze.parsers.burp_parser import _decode_body, _maybe_b64, _split_http
from jsanalyze.utils.normalize import looks_like_asset_path, normalize_path

__all__ = ["collect_responses"]

# sensitive response field names (whole-word-ish; values are NEVER stored)
_SENSITIVE_KEY_RE = re.compile(
    r"^(?:access_?token|id_?token|refresh_?token|token|secret|api_?key|apikey|client_?secret"
    r"|password|passwd|pwd|ssn|credit_?card|card_?number|cvv|private_?key|session|jwt|bearer"
    r"|email|phone|dob|address|salary|balance|role|roles|is_?admin|permissions|scopes?)$", re.I)
_ID_KEY_RE = re.compile(r"(?:^id$|_id$|^uuid$|^guid$|Id$)")
_MAX_ITEMS = 4000
_MAX_LEADS = 60

_ON_HANDLER_RE = re.compile(r"""\bon[a-z]{3,20}\s*=\s*["'][^"']{1,200}["']""", re.I)
_JS_HREF_RE = re.compile(r"""\b(?:href|src|action|formaction)\s*=\s*["']\s*javascript:[^"']{0,200}["']""", re.I)


def _flatten(obj, depth=3):
    """Collect key names from a JSON value, descending a few levels (into list items too)."""
    keys: set = set()

    def walk(o, d):
        if isinstance(o, dict):
            for k, v in o.items():
                keys.add(str(k))
                if d > 0:
                    walk(v, d - 1)
        elif isinstance(o, list):
            for item in o[:20]:
                if d > 0:
                    walk(item, d)

    walk(obj, depth)
    return keys


def _in_scope(host, scope_hosts):
    if not host or not scope_hosts:
        return True
    scope = {h.lower().lstrip("*.") for h in scope_hosts}
    return any(host == s or host.endswith("." + s) for s in scope)


def collect_responses(path, scope_hosts=None) -> dict:
    out = {"overfetch": [], "html_sinks": []}
    try:
        p = Path(path)
        suf = p.suffix.lower()
        if p.is_dir():
            return out
        if suf == ".har":
            _from_har(p, scope_hosts, out)
        elif suf in (".xml", ".burp") or _looks_xml(p):
            _from_xml(p, scope_hosts, out)
    except Exception:
        return out
    out["overfetch"] = out["overfetch"][:_MAX_LEADS]
    out["html_sinks"] = out["html_sinks"][:_MAX_LEADS]
    return out


def _record(out, method, url, ctype, body_text, seen):
    host = urlsplit(url or "").netloc.split("@")[-1].split(":")[0].lower()
    path = urlsplit(url or "").path or "/"
    if not _in_scope(host, scope_hosts=getattr(_record, "_scope", None)):
        return
    low_ct = (ctype or "").lower()
    text = (body_text or "").strip()
    if not text:
        return
    if ("json" in low_ct or text[:1] in "{[") and not looks_like_asset_path(path):
        try:
            obj = json.loads(text)
        except (ValueError, TypeError):
            return
        keys = _flatten(obj)
        sensitive = sorted({k for k in keys if _SENSITIVE_KEY_RE.match(k)})
        if not sensitive:
            return
        key = (host, normalize_path(path))
        if key in seen:
            return
        seen.add(key)
        ids = sorted({k for k in keys if _ID_KEY_RE.search(k)})
        out["overfetch"].append({
            "method": (method or "").upper(), "host": host, "path": path,
            "norm_path": normalize_path(path), "sensitive": sensitive[:12], "ids": ids[:8],
        })
    elif "html" in low_ct:
        for rx, kind in ((_ON_HANDLER_RE, "inline-handler"), (_JS_HREF_RE, "javascript-uri")):
            m = rx.search(text)
            if not m:
                continue
            key = (host, path, kind)
            if key in seen:
                continue
            seen.add(key)
            out["html_sinks"].append({
                "host": host, "path": path, "url": url, "kind": kind,
                "evidence": " ".join(m.group(0).split())[:160],
            })


def _from_xml(xml_path, scope_hosts, out):
    _record._scope = scope_hosts
    seen = set()
    count = 0
    for _ev, el in ET.iterparse(str(xml_path), events=("end",)):
        if el.tag != "item":
            continue
        count += 1
        method = (el.findtext("method") or "").strip()
        url = (el.findtext("url") or "").strip()
        resp = _maybe_b64(el.find("response"))
        el.clear()
        if count > _MAX_ITEMS or not resp:
            continue
        _line, headers, body = _split_http(resp)
        ctype = ""
        for n, v in headers:
            if n.lower() == "content-type":
                ctype = v
        body = _decode_body(body, headers)
        _record(out, method, url, ctype, body.decode("utf-8", "replace"), seen)


def _from_har(har_path, scope_hosts, out):
    _record._scope = scope_hosts
    seen = set()
    with open(har_path, encoding="utf-8", errors="replace") as fh:
        har = json.load(fh)
    for ent in (har.get("log", {}).get("entries", []) or [])[:_MAX_ITEMS]:
        if not isinstance(ent, dict):
            continue
        req = ent.get("request", {})
        resp = ent.get("response", {})
        content = resp.get("content", {}) if isinstance(resp, dict) else {}
        ctype = content.get("mimeType", "")
        text = content.get("text", "") or ""
        _record(out, req.get("method", ""), req.get("url", ""), ctype, text, seen)


def _looks_xml(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            return fh.read(256).lstrip()[:1] == b"<"
    except OSError:
        return False

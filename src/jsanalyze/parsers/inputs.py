"""Multi-source local input loader (critique point 7).

Accepts three LOCAL sources and never crawls:

  * a Burp Suite XML export — JS items as before, PLUS every HTML item's inline
    `<script>` bodies and its `<script src=...>` references (recorded present/missing);
  * a directory of already-saved `.js` / `.map` files;
  * a HAR file — JS and HTML response bodies.

Returns `(js_items, map_items, chunk_refs)`:
  js_items    — list[Item] of JavaScript to analyze (bodies staged under out_dir)
  map_items   — list[Item] of `.map` files (for local sourcemap reconstruction)
  chunk_refs  — [{"src","present","from"}] from HTML <script src> (missing = operator's job)
"""

from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlsplit

from jsanalyze.models import Item
from jsanalyze.parsers.burp_parser import (
    _decode_body, _is_javascript, _js_name, _maybe_b64, _looks_binary,
    _split_http, parse_burp_xml,
)
from jsanalyze.utils import workspace as W

_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*['\"]([^'\"]+)['\"]", re.I)
_SCRIPT_INLINE_RE = re.compile(r"<script\b(?![^>]*\bsrc\s*=)[^>]*>(.*?)</script>", re.I | re.S)


def _mk_item(url, host, js_body, out_dir, issues, cap) -> "Item | None":
    if not js_body or not js_body.strip():
        return None
    if cap and len(js_body) > cap:
        issues.append(f"skipped oversize inline/dir JS (> {cap} bytes): {url}")
        return None
    sha1 = W.sha1_short(js_body)
    saved = None
    if out_dir is not None:
        dest = (Path(out_dir) / _js_name(url, sha1)).resolve()
        dest.write_text(js_body, encoding="utf-8")
        saved = str(dest)
    return Item(url=url, host=host, method="GET", status=200, mimetype="script",
                is_javascript=True, js_body=js_body, saved_path=saved, sha1=sha1)


def _present(src, js_items) -> bool:
    base = Path(urlsplit(src).path).name
    return bool(base) and any(base and base in (it.url or "") for it in js_items)


def _scan_html(html, page_url, out_dir, issues, cap):
    """Extract inline <script> bodies (as JS items) and <script src> refs from one HTML page."""
    items, refs = [], []
    for i, body in enumerate(_SCRIPT_INLINE_RE.findall(html or "")):
        it = _mk_item(f"{page_url}#inline-{i+1}", urlsplit(page_url).netloc, body, out_dir, issues, cap)
        if it:
            items.append(it)
    for src in _SCRIPT_SRC_RE.findall(html or ""):
        refs.append({"src": src, "from": page_url})
    return items, refs


def _from_xml(xml_path, scope_hosts, out_dir, cap, issues):
    js_items = parse_burp_xml(xml_path, scope_hosts=scope_hosts, out_dir=out_dir,
                              max_bytes=cap, issues=issues)
    html_items, refs = [], []
    try:
        for _ev, el in ET.iterparse(str(xml_path), events=("end",)):
            if el.tag != "item":
                continue
            mimetype = (el.findtext("mimetype") or "").strip().lower()
            url = (el.findtext("url") or "").strip()
            resp = _maybe_b64(el.find("response"))
            el.clear()
            _line, headers, body = _split_http(resp)
            ctype = ""
            for n, v in headers:
                if n.lower() == "content-type":
                    ctype = v.lower()
            if "html" not in mimetype and "text/html" not in ctype:
                continue
            raw = _decode_body(body, headers)
            if _looks_binary(raw):
                continue
            hi, hr = _scan_html(raw.decode("utf-8", "replace"), url, out_dir, issues, cap)
            html_items += hi
            refs += hr
    except (ET.ParseError, OSError) as e:
        issues.append(f"HTML pass over XML failed: {e}")
    chunk_refs = [{"src": r["src"], "from": r["from"], "present": _present(r["src"], js_items + html_items)}
                  for r in refs]
    return js_items + html_items, [], chunk_refs


def _from_dir(root, out_dir, cap, issues):
    js_items, map_items = [], []
    root = Path(root)
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        suf = p.suffix.lower()
        if suf in (".js", ".mjs", ".cjs"):
            try:
                it = _mk_item(f"file://{p}", "", p.read_text(encoding="utf-8", errors="replace"),
                              out_dir, issues, cap)
                if it:
                    js_items.append(it)
            except OSError as e:
                issues.append(f"read {p} failed: {e}")
        elif suf == ".map":
            map_items.append(Item(url=f"file://{p}", saved_path=str(p), mimetype="map"))
    return js_items, map_items, []


def _from_har(har_path, scope_hosts, out_dir, cap, issues):
    js_items, refs = [], []
    try:
        with open(har_path, encoding="utf-8", errors="replace") as fh:
            har = json.load(fh)
        entries = har.get("log", {}).get("entries", [])
    except (OSError, ValueError, AttributeError) as e:
        issues.append(f"HAR parse failed: {e}")
        return [], [], []
    for ent in entries:
        try:
            url = ent.get("request", {}).get("url", "")
            resp = ent.get("response", {})
            content = resp.get("content", {})
            text = content.get("text") or ""
            if content.get("encoding") == "base64":
                import base64
                text = base64.b64decode(text).decode("utf-8", "replace")
            mime = (content.get("mimeType") or "").lower()
            ext = Path(urlsplit(url).path).suffix.lower()
            if "javascript" in mime or "ecmascript" in mime or ext in (".js", ".mjs"):
                it = _mk_item(url, urlsplit(url).netloc, text, out_dir, issues, cap)
                if it:
                    js_items.append(it)
            elif "html" in mime:
                hi, hr = _scan_html(text, url, out_dir, issues, cap)
                js_items += hi
                refs += hr
        except Exception as e:  # one bad entry must not sink the HAR
            issues.append(f"HAR entry skipped: {e}")
    chunk_refs = [{"src": r["src"], "from": r["from"], "present": _present(r["src"], js_items)} for r in refs]
    return js_items, [], chunk_refs


def load_input(path, scope_hosts=None, out_dir=None, cfg=None, issues=None):
    """Dispatch on the input kind. Returns (js_items, map_items, chunk_refs)."""
    issues = issues if issues is not None else []
    cfg = cfg or W.load_config()
    cap = int(cfg.get("max_js_bytes") or 5_242_880)
    p = Path(path).expanduser()
    if not p.exists():
        raise ValueError(f"input not found: {path}")
    if p.is_dir():
        return _from_dir(p, out_dir, cap, issues)
    suf = p.suffix.lower()
    if suf == ".har":
        return _from_har(p, scope_hosts, out_dir, cap, issues)
    if suf in (".xml", ".burp") or _looks_like_xml(p):
        return _from_xml(p, scope_hosts, out_dir, cap, issues)
    # single .js file
    if suf in (".js", ".mjs", ".cjs"):
        return _from_dir(p.parent, out_dir, cap, issues) if False else (
            [it for it in [_mk_item(f"file://{p}", "", p.read_text(encoding="utf-8", errors="replace"),
                                    out_dir, issues, cap)] if it], [], [])
    raise ValueError(f"unsupported input (expected .xml / dir / .har / .js): {path}")


def _looks_like_xml(p: Path) -> bool:
    try:
        with open(p, "rb") as fh:
            head = fh.read(256).lstrip()
        return head[:1] == b"<"
    except OSError:
        return False

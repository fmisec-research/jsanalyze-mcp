"""Normalize jsluice/linkfinder URL rows into real endpoints (critique point 2).

The old `_is_fetchable` trusted any `type != stringLiteral` (so LinkFinder's `type:
"linkfinder"` let `MM/dd/yyyy` and `audio/mpeg` through) and any string with a `/`.
Here `fetchable` is purely SHAPE-based: an absolute http(s)/ws(s) URL with a real host,
or a rooted path (`/api/...`) that is not an asset. MIME types, date formats, regexes,
XML namespaces, library-comment URLs, truncated URLs and asset/module files are dropped.
Each kept row is one normalized endpoint; `EXPR` is kept with `dynamic:true`.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from jsanalyze.party import is_library_comment_url, party_of

_MIME_RE = re.compile(r"^[a-z]+/[a-z0-9][a-z0-9.+\-]*\*?$", re.I)      # audio/mpeg, application/json
_DATE_RE = re.compile(r"(?i)\b(MM|DD|YYYY|HH|SS|yyyy|dd)\b|^\d{1,4}[/-]\d{1,2}[/-]\d{1,4}$")
_REGEXISH = (".*", "(?", "[^", "\\d", "\\w", "\\s", "]+", "]*", ")$", "(?:", "|", "\\/")
_ASSET_EXT = (
    ".js", ".mjs", ".cjs", ".ts", ".css", ".scss", ".map", ".png", ".jpg", ".jpeg",
    ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp3", ".mp4", ".webm", ".wasm", ".pdf", ".md", ".txt",
)
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_ID_PARAMS = {"id", "user_id", "userid", "account_id", "accountid", "order_id",
              "orderid", "uuid", "guid", "customer_id", "customerid", "pid"}
_AUTH_SEGS = {"auth", "oauth", "oauth2", "login", "logout", "token", "sso", "saml",
              "mfa", "otp", "register", "signup", "verify", "reset", "password",
              "forgot", "session", "refresh", "authorize", "authenticate"}
_BFLA_SEGS = {"admin", "internal", "manage", "management", "superuser", "sudo", "root"}
_VER_SEGS = re.compile(r"^(v0|beta|legacy|internal|deprecated|alpha|canary|staging)$", re.I)


def _host(url: str) -> str:
    try:
        return urlsplit(url).netloc.split("@")[-1].split(":")[0].lower()
    except ValueError:
        return ""


def _is_asset(path: str) -> bool:
    p = path.split("?", 1)[0].split("#", 1)[0].lower()
    return p.endswith(_ASSET_EXT)


def _shape(url: str):
    """Return ('absolute'|'rooted'|'relative', is_asset) or None to DROP as non-endpoint."""
    u = (url or "").strip()
    if not u or " " in u or "\t" in u:
        return None
    low = u.lower()
    if is_library_comment_url(u):
        return None
    if _MIME_RE.match(u) or _DATE_RE.search(u):
        return None
    if any(t in u for t in _REGEXISH):
        return None
    if low.startswith(("http://", "https://", "ws://", "wss://", "//")):
        host = _host(u if "//" != u[:2] else "http:" + u)
        if not host or "." not in host or "w3.org" in host:
            return None
        if u.endswith(("-", "_", "+", "=", "&", ":")):   # truncated
            return None
        return ("absolute", _is_asset(urlsplit(u).path))
    if u.startswith("/") and not u.startswith("//"):
        return ("rooted", _is_asset(u))
    if u.startswith(("./", "../")):
        return None                                      # relative module specifier
    if "EXPR" in u and "/" in u:
        return ("relative", False)                       # dynamic path candidate
    if "/" in u and not _is_asset(u):
        return ("relative", False)
    return None


def _method_of(rec: dict) -> str:
    m = (rec.get("method") or "").upper()
    if m:
        return m
    t = (rec.get("type") or "").lower()
    for verb in ("post", "put", "patch", "delete", "get", "head"):
        if verb in t:
            return verb.upper()
    return ""


def _in_scope(host: str, scope_hosts) -> bool:
    if not host:
        return True                                      # app's own surface
    if not scope_hosts:
        return True                                      # unknown -> don't exclude
    scope = {h.lower().lstrip("*.") for h in scope_hosts}
    return any(host == s or host.endswith("." + s) for s in scope)


def normalize_endpoints(url_records, items, cfg=None, scope_hosts=None) -> list[dict]:
    path_to_url = {it.saved_path: it.url for it in (items or []) if getattr(it, "saved_path", None)}
    by_key, order = {}, []
    for rec in url_records or []:
        if not isinstance(rec, dict):
            continue
        url = rec.get("url") or ""
        shape = _shape(url)
        if shape is None:
            continue
        kind, is_asset = shape
        if is_asset:
            continue                                     # asset/module file, not an endpoint

        parts = urlsplit(url) if kind == "absolute" else urlsplit("//h" + url if url.startswith("/") else "//h/" + url)
        host = _host(url) if kind == "absolute" else ""
        path = (parts.path if kind == "absolute" else url.split("?", 1)[0]) or "/"
        query = sorted({q for q in (rec.get("queryParams") or []) if isinstance(q, str)}
                       | {kv.split("=", 1)[0] for kv in parts.query.split("&") if kv})
        filename = rec.get("filename") or ""
        src_file = rec.get("source_file") or (filename.rsplit("/", 1)[-1] if filename else "")
        origin = rec.get("origin_url") or path_to_url.get(filename)

        norm = {
            "method": _method_of(rec),
            "path": path,
            "host": host,
            "query": query,
            "body_keys": [b for b in (rec.get("bodyParams") or []) if isinstance(b, str)],
            "call_type": rec.get("type") or "",
            "where_found": f"{src_file}:{rec.get('line')}" if rec.get("line") else src_file,
            "party": party_of(src_file, origin or "", scope_hosts),
            "in_scope": _in_scope(host, scope_hosts),
            "dynamic": "EXPR" in url,
            "fetchable": kind in ("absolute", "rooted"),
            "detector": rec.get("detector") or "jsluice",
            "url": url,
        }
        # collapse method/type variants of the same endpoint into ONE row, preferring
        # the variant that carries an HTTP method / body (critique point 1/2 dedupe).
        key = (norm["host"], norm["path"])
        prev = by_key.get(key)
        if prev is None:
            by_key[key] = norm
            order.append(key)
        elif not prev.get("method") and norm.get("method"):
            prev["method"] = norm["method"]
            prev["call_type"] = norm["call_type"] or prev["call_type"]
            prev["body_keys"] = norm["body_keys"] or prev["body_keys"]
    return [by_key[k] for k in order]


def classify_endpoint(norm: dict):
    """Lead class for a normalized endpoint, or None. Segment-based (no substrings);
    IDOR only for a real resource/{id} position or id-ish param (not just 'a number')."""
    path = (norm.get("path") or "")
    segs = [s for s in path.lower().split("/") if s]
    params = {p.lower() for p in (norm.get("query") or []) + (norm.get("body_keys") or [])}

    if any(s in _BFLA_SEGS for s in segs):
        return ("bfla-candidate", "hunt-api", "medium", "high", "privileged path segment")
    if "graphql" in segs:
        return ("graphql-candidate", "hunt-graphql", "medium", "medium", "graphql endpoint")
    if any(s in _AUTH_SEGS for s in segs):
        return ("auth-endpoint", "hunt-auth-bypass", "medium", "medium", "auth surface")
    if params & _ID_PARAMS:
        return ("idor-candidate", "hunt-idor", "medium", "medium", "id-ish parameter")
    for i, s in enumerate(segs):
        is_id = s.isdigit() or bool(_UUID_RE.match(s)) or s == "expr"
        if is_id and i > 0 and re.fullmatch(r"[a-z][a-z0-9_-]{2,}", segs[i - 1]):
            return ("idor-candidate", "hunt-idor", "medium", "medium",
                    f"resource id ({segs[i-1]}/{s})")
    for s in segs:
        if _VER_SEGS.match(s):
            return ("api-version", "hunt-api", "low", "low", f"old/internal version ({s})")
    return None

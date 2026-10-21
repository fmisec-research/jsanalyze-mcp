"""Normalize jsluice/linkfinder URL rows into real endpoints (critique point 2).

The old `_is_fetchable` trusted any `type != stringLiteral` (so LinkFinder's `type:
"linkfinder"` let `MM/dd/yyyy` and `audio/mpeg` through) and any string with a `/`.
Here `fetchable` is purely SHAPE-based: an absolute http(s)/ws(s) URL with a real host,
or a rooted path (`/api/...`) that is not an asset. MIME types, date formats, regexes,
XML namespaces, library-comment URLs, truncated URLs and asset/module files are dropped.
Each kept row is one normalized endpoint; `EXPR` is kept with `dynamic:true`.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
from urllib.parse import urlsplit

from jsanalyze.analyzers.callsites import request_shape
from jsanalyze.party import is_library_comment_url, party_of
from jsanalyze.utils.normalize import (
    ASSET_PREFIX, SPA_ROUTE, classify_string_kind, normalize_path,
)

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


def normalize_endpoints(url_records, items, cfg=None, scope_hosts=None, *,
                        route_paths=None, history=None) -> list[dict]:
    """Normalize jsluice/linkfinder url rows into endpoints.

    ``route_paths`` (normalized SPA route paths) lets a string that is really a
    client route be tagged ``string_kind=route`` instead of a bogus API endpoint
    (critique point 3). ``history`` (from :func:`collect_history`) lets each endpoint
    carry ``seen_in_history`` — the untested-surface signal (critique point 2).
    """
    path_to_url = {it.saved_path: it.url for it in (items or []) if getattr(it, "saved_path", None)}
    text_by_base = _text_index(items)
    route_set = {normalize_path(p) for p in (route_paths or [])}
    # path-first membership (critique round 2, point 1): compare on (host, norm_path),
    # not a method-sensitive tuple, and only claim seen/unseen when real API traffic
    # exists to compare against (``api_known``).
    hist_path_keys = (history or {}).get("path_keys") if isinstance(history, dict) else None
    hist_methods = (history or {}).get("methods") if isinstance(history, dict) else None
    api_known = bool((history or {}).get("api_known")) if isinstance(history, dict) else False
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
        call_type = rec.get("type") or ""
        method = _method_of(rec)
        body_keys = [b for b in (rec.get("bodyParams") or []) if isinstance(b, str)]

        # augment the request shape jsluice missed (JSON.stringify bodies etc.).
        # jsluice `urls` rows carry NO line, so locate the call site by the URL literal
        # in the file text, then read the options/body object there (critique point 3).
        line = rec.get("line")
        if (not body_keys or not method) and src_file in text_by_base:
            text = text_by_base[src_file]
            loc_line = line or _locate_line(text, url, path)
            if loc_line:
                line = line or loc_line                  # remember it for the lead (point 5)
                shape2 = request_shape(text, loc_line)
                method = method or shape2.get("method", "")
                if not body_keys:
                    body_keys = shape2.get("body_keys", [])

        npath = normalize_path(path)
        is_route = npath in route_set
        string_kind = classify_string_kind(url, call_type, is_route=is_route)

        norm = {
            "method": method,
            "path": path,
            "norm_path": npath,
            "host": host,
            "query": query,
            "body_keys": body_keys,
            "call_type": call_type,
            "string_kind": string_kind,
            "line": line,
            "where_found": f"{src_file}:{line}" if line else src_file,
            "party": party_of(src_file, origin or "", scope_hosts),
            "in_scope": _in_scope(host, scope_hosts),
            "dynamic": "EXPR" in url,
            "fold_partial": bool(rec.get("fold_partial")),
            "fetchable": kind in ("absolute", "rooted") and string_kind != SPA_ROUTE,
            "detector": rec.get("detector") or "jsluice",
            "url": url,
        }
        # seen_in_history is asserted ONLY against real API traffic, and PATH-FIRST: an
        # endpoint whose method we could not read still matches a GET to the same path.
        if api_known and isinstance(hist_path_keys, set):
            seen = (host, npath) in hist_path_keys or ("", npath) in hist_path_keys
            norm["seen_in_history"] = seen
            if seen and isinstance(hist_methods, dict) and method:
                ms = hist_methods.get((host, npath)) or hist_methods.get(("", npath)) or set()
                norm["method_in_history"] = method.upper() in ms
        # collapse method/type variants of the same endpoint into ONE row, preferring
        # the variant that carries an HTTP method / body (critique point 1/2 dedupe).
        key = (norm["host"], norm["norm_path"])
        prev = by_key.get(key)
        if prev is None:
            by_key[key] = norm
            order.append(key)
        else:
            if not prev.get("method") and norm.get("method"):
                prev["method"] = norm["method"]
            prev["call_type"] = prev["call_type"] or norm["call_type"]
            prev["body_keys"] = prev["body_keys"] or norm["body_keys"]
            # a real call site upgrades a bare string-literal row to API
            if norm["string_kind"] == "api" and prev["string_kind"] != "api":
                prev["string_kind"] = "api"
            prev["fetchable"] = prev["fetchable"] or norm["fetchable"]
            if norm.get("seen_in_history"):
                prev["seen_in_history"] = True
    return [by_key[k] for k in order]


def _locate_line(text: str, url: str, path: str) -> "int | None":
    """1-based line of the call that mentions this endpoint, found by the URL literal.

    Tries the full URL, then the path, then the static prefix before an ``EXPR``
    placeholder (``/orders/EXPR`` -> search ``/orders/``) — enough to land request_shape
    on the right call site when jsluice gave no line."""
    for needle in _locators(url, path):
        if not needle or len(needle) < 3:
            continue
        idx = text.find(needle)
        if idx != -1:
            return text.count("\n", 0, idx) + 1
    return None


def _locators(url: str, path: str):
    # try the COMPLETE quoted literal first ("…"/'…'/`…`) so a URL that is a PREFIX of a
    # longer one (``/users/42`` inside ``/users/42/orders``) lands on its OWN call site,
    # not the first substring match — otherwise request_shape reads the wrong body.
    out = []
    for lit in (url, path):
        if lit and lit != "/":
            out.extend([f'"{lit}"', f"'{lit}'", f"`{lit}`"])
    if url:
        out.append(url)
    if path and path != "/":
        out.append(path)
        if "EXPR" in path:
            out.append(path.split("EXPR", 1)[0])
    return out


def _text_index(items) -> dict:
    """basename -> file text, read once (for call-site body-shape recovery)."""
    out: dict = {}
    for it in (items or []):
        sp = getattr(it, "saved_path", None)
        if not sp:
            continue
        base = os.path.basename(sp)
        if base in out:
            continue
        try:
            with open(sp, "r", encoding="utf-8", errors="replace") as fh:
                out[base] = fh.read()
        except OSError:
            continue
    return out


_ATOB_RE = re.compile(r"""atob\s*\(\s*(['"])([A-Za-z0-9+/=_\-]{8,})\1\s*\)""")


def _b64decode(raw: str) -> str:
    """Decode a base64 (std or url-safe) literal to text, or '' if it isn't printable."""
    s = raw.replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        out = base64.b64decode(s, validate=False)
    except (binascii.Error, ValueError):
        return ""
    try:
        txt = out.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    # printable only — reject binary that happened to decode
    return txt if txt and all(32 <= ord(c) < 127 for c in txt) else ""


def _url_like(dec: str):
    """Yield the decoded string if it looks like a URL or a rooted API path."""
    d = dec.strip()
    if not d or " " in d or len(d) < 3:
        return
    low = d.lower()
    if low.startswith(("http://", "https://", "ws://", "wss://", "//")):
        yield d
    elif d.startswith("/") and not d.startswith("//") and not _is_asset(d):
        yield d


def decode_atob_endpoints(items) -> list:
    """Decode ``atob("…")`` literals and surface any that decode to a URL/rooted path as
    endpoint candidates (round 2: base64-hidden endpoints are otherwise invisible).

    Returns url-records shaped like linkfinder rows (``type:"atob"``); the normalizer
    treats a real call-type as a genuine site. Pure, never fetches, never raises."""
    out, seen = [], set()
    for it in items or []:
        sp = getattr(it, "saved_path", None)
        if not sp:
            continue
        try:
            with open(sp, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        base = os.path.basename(sp)
        for m in _ATOB_RE.finditer(text):
            dec = _b64decode(m.group(2))
            if not dec:
                continue
            for cand in _url_like(dec):
                key = (base, cand)
                if key in seen:
                    continue
                seen.add(key)
                out.append({"url": cand, "type": "atob", "detector": "atob",
                            "source_file": base, "filename": sp,
                            "line": text.count("\n", 0, m.start()) + 1})
    return out


def classify_endpoint(norm: dict):
    """Lead class for a normalized endpoint, or None. Segment-based (no substrings);
    IDOR only for a real resource/{id} position or id-ish param (not just 'a number').

    Gated by ``string_kind`` (critique point 3): a client-side SPA route or an asset
    prefix is NOT an API endpoint, so it never becomes an auth/bfla/idor lead here
    (a privileged route is surfaced as ``endpoint-hidden`` via the routes path instead)."""
    if norm.get("string_kind") in (ASSET_PREFIX, SPA_ROUTE):
        return None
    path = (norm.get("path") or "")
    url = (norm.get("url") or "")
    call_type = (norm.get("call_type") or "").lower()
    segs = [s for s in path.lower().split("/") if s]
    params = {p.lower() for p in (norm.get("query") or []) + (norm.get("body_keys") or [])}

    # realtime channel -> hunt-websocket (critique point 9)
    if url.lower().startswith(("ws://", "wss://")) or call_type in ("websocket", "eventsource") \
            or "websocket" in segs or "socket.io" in url.lower():
        return ("websocket", "hunt-websocket", "medium", "medium", "realtime channel (ws/sse)")

    if any(s in _BFLA_SEGS for s in segs):
        return ("bfla-candidate", "hunt-api", "medium", "high", "privileged path segment")
    if "graphql" in segs:
        return ("graphql-candidate", "hunt-graphql", "medium", "medium", "graphql endpoint")
    if any(s in _AUTH_SEGS for s in segs):
        return ("auth-endpoint", "hunt-auth-bypass", "medium", "medium", "auth surface")
    if params & _ID_PARAMS:
        return ("idor-candidate", "hunt-idor", "medium", "medium", "id-ish parameter")
    # a half-folded string endpoint (round 4 pt 1): its EXPR is a build gap, not proof of an
    # id segment — don't let a failed baseURL/concat fold masquerade as IDOR.
    fold_partial = bool(norm.get("fold_partial"))
    for i, s in enumerate(segs):
        is_id = s.isdigit() or bool(_UUID_RE.match(s)) or (s == "expr" and not fold_partial)
        if is_id and i > 0 and re.fullmatch(r"[a-z][a-z0-9_-]{2,}", segs[i - 1]):
            return ("idor-candidate", "hunt-idor", "medium", "medium",
                    f"resource id ({segs[i-1]}/{s})")
    for s in segs:
        if _VER_SEGS.match(s):
            return ("api-version", "hunt-api", "low", "low", f"old/internal version ({s})")
    return None

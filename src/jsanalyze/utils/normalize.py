"""Path / endpoint normalization shared by the endpoint analyzer and the Burp
history-delta (critique points 2 & 3). Pure, stdlib-only, never raises.

The point of normalization is a *comparable key*: an endpoint seen in the JS
bundle (``/orders/{id}``) and the same endpoint actually exercised in the captured
traffic (``/orders/123``) must collapse to ONE key so the delta "in JS but never
requested" is meaningful. Three shapes are normalized the same way on both sides:

  * REST path     — variable segments (digits / UUID / long hex / ``EXPR`` / id-ish
                    trailing token) become ``{id}``; ``/orders/123 -> /orders/{id}``.
  * GraphQL       — keyed per operation, not per path (``graphql#query:GetUser``).
  * WS / SSE      — keyed per channel/path (``wss://h/ws`` -> ``ws:/ws``).

``history_key`` / ``endpoint_key`` produce the ``(method, host, norm_path)`` tuple
used for set-membership; ``norm_path`` is also surfaced on each endpoint so the
report can show the collapsed form.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

__all__ = [
    "normalize_path", "endpoint_key", "history_key", "looks_like_asset_path",
    "SPA_ROUTE", "API_CALL", "ASSET_PREFIX", "classify_string_kind",
]

# variable-segment detectors (a path segment that is really an id/token)
_DIGITS_RE = re.compile(r"^\d+$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_LONGHEX_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
_B64ISH_RE = re.compile(r"^[A-Za-z0-9_\-]{20,}={0,2}$")       # token-ish opaque id
# an opaque id needs ≥2 digits — so a version/namespace label like `version2` is NOT an
# id segment and won't collapse to {id} (which would mint a false IDOR; round 5 pt 11).
_MIXED_ID_RE = re.compile(r"^(?=(?:\D*\d){2,})[A-Za-z0-9_\-]{8,}$")
# the string folder emits the literal ``EXPR`` for an unresolved dynamic segment. Match it ONLY
# as a WHOLE segment (round 6 pt 3): the old ``…|EXPR`` branch matched the substring anywhere, so
# a real segment ``EXPRESSION`` / ``myEXPR`` collapsed to ``{id}`` and two distinct paths merged.
# A segment that merely CONTAINS ``EXPR`` (e.g. a half-folded ``vEXPR``) falls through to the
# other id heuristics below instead of being force-collapsed. Case-sensitive: it is our token.
_EXPR_RE = re.compile(r"^EXPR$")

_ASSET_EXT = (
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".css", ".scss", ".map", ".png", ".jpg",
    ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".mp3", ".mp4", ".webm", ".wasm", ".pdf", ".md", ".txt", ".json",
)
_ASSET_PREFIXES = ("/static/", "/assets/", "/public/", "/dist/", "/build/", "/_next/static/",
                   "/img/", "/images/", "/fonts/", "/media/")

# the three string kinds a bundle literal can be (critique point 3)
API_CALL = "api"          # a real request site (fetch/axios/xhr/absolute/rooted API path)
SPA_ROUTE = "route"       # a client-side router path
ASSET_PREFIX = "asset"    # a static asset / module specifier

# jsluice/linkfinder `type`s that are NOT evidence of a real request call site: a bare
# string literal, a comment, or a LinkFinder regex hit are as weak as "found a string" —
# so a known SPA route must win over them (critique point 3; the /register-is-a-route case).
_NON_CALLSITE_TYPES = {"stringliteral", "comment", "linkfinder", "regex", ""}
# navigation, not an XHR. window.open("/records/expanded") and location = "/records?focus="
# are routes even when jsluice stamps them method=GET. A real fetch() of the same path
# still wins (it is not in this set).
_NAV_CALL_TYPES = {
    "locationassignment", "window.open", "location", "assign", "replace", "concat",
}


def looks_like_asset_path(path: str) -> bool:
    p = (path or "").split("?", 1)[0].split("#", 1)[0].lower()
    if p.endswith(_ASSET_EXT):
        return True
    return any(pre in p for pre in _ASSET_PREFIXES)


def _norm_segment(seg: str) -> str:
    """Collapse one path segment to ``{id}`` if it is a variable identifier."""
    if not seg:
        return seg
    if _EXPR_RE.search(seg):
        return "{id}"
    if _DIGITS_RE.match(seg) or _UUID_RE.match(seg) or _LONGHEX_RE.match(seg):
        return "{id}"
    if _B64ISH_RE.match(seg) or _MIXED_ID_RE.match(seg):
        return "{id}"
    return seg.lower()


def normalize_path(path: str) -> str:
    """Normalize a REST path to a comparable template.

    ``/orders/123/items`` -> ``/orders/{id}/items``; a trailing slash is dropped
    (except the root). Query and fragment are stripped by the caller.
    """
    if not path:
        return "/"
    path = path.split("?", 1)[0].split("#", 1)[0]
    if not path.startswith("/"):
        path = "/" + path
    segs = [s for s in path.split("/") if s != ""]
    norm = "/" + "/".join(_norm_segment(s) for s in segs)
    return norm or "/"


def _host_of(url: str) -> str:
    try:
        return urlsplit(url or "").netloc.split("@")[-1].split(":")[0].lower()
    except ValueError:
        return ""


def _ws_key(url: str) -> str:
    parts = urlsplit(url)
    return f"ws:{normalize_path(parts.path or '/')}"


def endpoint_key(method: str, host: str, path: str, *, call_type: str = "",
                 operation_name: str = "") -> tuple:
    """A comparable ``(method, host, norm)`` key for an endpoint extracted from JS."""
    m = (method or "").upper()
    h = (host or "").lower()
    low = (call_type or "").lower()
    if "graphql" in (path or "").lower() or operation_name:
        op = operation_name or "*"
        return (m or "POST", h, f"graphql#{op}")
    if low in ("websocket", "ws", "eventsource", "sse") or (path or "").startswith(("ws://", "wss://")):
        return (m or "GET", h, _ws_key(path))
    return (m or "", h, normalize_path(path))


def history_key(method: str, url: str) -> tuple:
    """A comparable key for a request actually seen in captured traffic."""
    m = (method or "").upper()
    parts = urlsplit(url or "")
    host = parts.netloc.split("@")[-1].split(":")[0].lower()
    path = parts.path or "/"
    if "graphql" in path.lower():
        # history can't cheaply name the operation; match any graphql on the host
        return (m or "POST", host, "graphql#*")
    if parts.scheme in ("ws", "wss"):
        return (m or "GET", host, _ws_key(url))
    return (m, host, normalize_path(path))


def classify_string_kind(url: str, call_type: str, *, is_route: bool = False) -> str:
    """Decide whether a bundle string is an API call, a SPA route, or an asset prefix.

    ``is_route`` is set by the caller when the same path was also found by the SPA
    route extractor (routes.json) — a strong signal it is a client route, not an API.
    """
    low_ct = (call_type or "").lower()
    u = (url or "")
    if looks_like_asset_path(u):
        return ASSET_PREFIX
    # a path the router also registers is a route, including when the bundle only
    # navigates there (window.open / location / a folded concat). fetch() is not
    # navigation and still counts as an API call below.
    if is_route and (low_ct in _NON_CALLSITE_TYPES or low_ct in _NAV_CALL_TYPES
                     or "router" in low_ct):
        return SPA_ROUTE
    # a GENUINE request site wins (fetch/axios/xhr/websocket/…) — but a LinkFinder/
    # stringLiteral hit is not a call site, so a known route beats it.
    if low_ct and low_ct not in _NON_CALLSITE_TYPES:
        return API_CALL
    if u.lower().startswith(("http://", "https://", "ws://", "wss://", "//")):
        return API_CALL
    if is_route:
        return SPA_ROUTE
    # a bare rooted string literal with no call site: ambiguous — treat as route-ish
    # only if it has no API-ish segment; otherwise a rooted API path.
    return API_CALL if u.startswith("/") else SPA_ROUTE

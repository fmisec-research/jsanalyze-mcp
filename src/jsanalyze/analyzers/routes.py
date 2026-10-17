"""Analyzer: client-side router route extraction (deterministic, best-effort).

Static, stdlib-only extraction of SPA route definitions from already-decoded bundle
text. It never contacts the target and never raises: on any trouble a file simply
contributes nothing. The patterns are heuristic — minified bundles vary wildly — so
this is a *lead* surface (where the router thinks the app's pages live), not ground
truth.

One record per ``(path, file)``::

    {"path": "/admin/users", "kind": "react-router|vue|angular|next|generic",
     "component": "<name or ''>", "file": <basename>, "line": <int>,
     "party": party_of(...)}

Acceptance is conservative to keep vendor/noise out: a ``path`` string is kept only
when it sits next to a real router key (``component``/``element``/``name``/``children``
/``loadChildren``/...) or inside a JSX ``<Route .../>`` — and only when the value is a
plausible route (starts with ``/`` or, for Angular, a bare word segment), never a URL
with a scheme, an asset path (``/static/...``, ``*.js``/``*.css``/``*.png`` ...), or a
relative module/filesystem specifier.
"""

from __future__ import annotations

import os
import re

from jsanalyze.party import party_of

__all__ = ["extract_routes"]


# --- patterns -----------------------------------------------------------------
# object form:  path: "/x"  |  'path': '/x'  |  "path":"/x"
_PATH_OBJ_RE = re.compile(
    r"""(?:["']?)\bpath\b(?:["']?)\s*:\s*(["'])((?:\\.|(?!\1).)*)\1"""
)

# JSX <Route ...>  (we scan a short window after each <Route for path/element/component)
_JSX_ROUTE_RE = re.compile(r"<Route\b", re.IGNORECASE)
_ATTR_PATH_RE = re.compile(r"""\bpath\s*=\s*(["'])((?:\\.|(?!\1).)*)\1""")
_ATTR_EL_RE = re.compile(r"""\belement\s*=\s*\{?\s*<?\s*([A-Za-z_$][\w$]*)""")
_ATTR_COMP_RE = re.compile(r"""\bcomponent\s*=\s*\{?\s*([A-Za-z_$][\w$]*)""")

# component/element/name *values* inside a route object (best-effort)
_COMP_OBJ_RE = re.compile(r"""(?:["']?)\bcomponent\b(?:["']?)\s*:\s*([A-Za-z_$][\w$]*)""")
_ELEM_OBJ_RE = re.compile(
    r"""(?:["']?)\belement\b(?:["']?)\s*:\s*(?:[A-Za-z_$.]*\(\s*)?<?\s*([A-Za-z_$][\w$]*)"""
)
_NAME_OBJ_RE = re.compile(r"""(?:["']?)\bname\b(?:["']?)\s*:\s*(["'])([^"']+)\1""")

# any sibling router key near a path: => evidence this path: is a route definition
_ADJ_KEY_RE = re.compile(
    r"""(?:["']?)\b(?:components?|element|Component|name|children|loader|action|lazy|handle|"""
    r"""index|errorElement|redirect(?:To)?|loadChildren|canActivate|canMatch|pathMatch|outlet|"""
    r"""title|meta|beforeEnter|props|exact|render|caseSensitive)\b(?:["']?)\s*[:=]"""
)

# plausibility filters
_ASSET_EXT_RE = re.compile(
    r"\.(?:js|mjs|cjs|jsx|ts|tsx|css|scss|sass|less|styl|png|jpe?g|gif|svg|webp|avif|ico|bmp|"
    r"woff2?|ttf|eot|otf|map|json|jsonp|wasm|mp4|webm|ogg|mp3|wav|flac|pdf|txt|xml|htm|html|"
    r"md|yml|yaml|toml|lock|zip|gz|tar|csv)(?:[?#].*)?$",
    re.IGNORECASE,
)
_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.\-]*:", re.IGNORECASE)
_BARE_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_\-:./~*]*$")


def extract_routes(items, cfg=None) -> list:
    """Extract client-side router route definitions from each item's JS text.

    Never raises; returns ``[]`` when nothing plausible is found.
    """
    out: list = []
    try:
        scope_hosts = cfg.get("scope_hosts") if isinstance(cfg, dict) else None
        seen: set = set()
        for item in items or []:
            try:
                _routes_from_item(item, scope_hosts, seen, out)
            except Exception:
                continue
    except Exception:
        return out if isinstance(out, list) else []
    return out


# --- per-item -----------------------------------------------------------------
def _routes_from_item(item, scope_hosts, seen, out) -> None:
    text = _read_text(item)
    if not text:
        return
    source_file = _basename(item)
    origin_url = getattr(item, "url", "") or ""
    try:
        party = party_of(source_file, origin_url, scope_hosts)
    except Exception:
        party = "first"
    hints = _hints(text)
    line_starts = _line_index(text)

    # 1) JSX  <Route path="/x" element={<Admin/>} />
    for rm in _JSX_ROUTE_RE.finditer(text):
        win = text[rm.start(): rm.start() + 500]
        pm = _ATTR_PATH_RE.search(win)
        if not pm:
            continue
        path = _clean_path(pm.group(2))
        if not _plausible(path):
            continue
        comp = ""
        em = _ATTR_EL_RE.search(win)
        if em:
            comp = em.group(1)
        else:
            cm = _ATTR_COMP_RE.search(win)
            if cm:
                comp = cm.group(1)
        off = rm.start() + pm.start()
        _emit(out, seen, source_file, party, line_starts, off, path, "react-router", comp)

    # 2) object form  { path: "/x", element: Foo }  (React Router array / Vue / Angular / generic)
    for m in _PATH_OBJ_RE.finditer(text):
        path = _clean_path(m.group(2))
        if not _plausible(path):
            continue
        lo = max(0, m.start() - 120)
        hi = min(len(text), m.end() + 160)
        fwd = text[m.end(): hi]
        bwd = text[lo: m.start()]
        has_adj = _ADJ_KEY_RE.search(fwd + bwd) is not None
        # A multi-char leading-slash path ("/gdpr") is a route on its own (React-Router
        # route arrays, incl. factory forms where the component is not a sibling key).
        # A bare segment ("reports") or a lone "/" (also a common cookie path) is kept
        # only when a sibling router key sits next to it — the noise guard.
        if not (path.startswith("/") and len(path) > 1) and not has_adj:
            continue
        comp_key, comp_val = _find_component(fwd, bwd)
        kind = _classify_kind(path, False, comp_key, hints)
        _emit(out, seen, source_file, party, line_starts, m.start(), path, kind, comp_val)


_KEY_SPECS = (("element", _ELEM_OBJ_RE, 1), ("component", _COMP_OBJ_RE, 1), ("name", _NAME_OBJ_RE, 2))


def _last_match(regex, segment):
    m = None
    for m in regex.finditer(segment):
        pass
    return m


def _scan_keys(segment: str, prefer_last: bool) -> list:
    found = []
    for key, rx, gi in _KEY_SPECS:
        m = _last_match(rx, segment) if prefer_last else rx.search(segment)
        if m:
            found.append((m.start(), key, m.group(gi)))
    return found


def _find_component(fwd: str, bwd: str):
    """Return ``(key, value)`` for the route's nearest component/element/name key.

    The sibling key *closest* to ``path`` wins — the forward window (keys after
    ``path``, i.e. the rest of the same object) is consulted first, then the backward
    one. This avoids binding a path to a key that actually belongs to a neighbour
    object in a route array. ``(None, "")`` when nothing sits nearby.
    """
    cands = _scan_keys(fwd, prefer_last=False)
    if cands:
        cands.sort(key=lambda t: t[0])       # nearest after path
        return cands[0][1], cands[0][2]
    cands = _scan_keys(bwd, prefer_last=True)
    if cands:
        cands.sort(key=lambda t: -t[0])      # nearest before path
        return cands[0][1], cands[0][2]
    return (None, "")


def _classify_kind(path: str, via_jsx: bool, comp_key, hints) -> str:
    if via_jsx or comp_key == "element":
        return "react-router"
    bare = not path.startswith("/")
    active = [k for k in ("react", "vue", "angular", "next") if hints.get(k)]
    if bare:
        # bare (no leading slash) segment is the Angular signature
        if hints.get("angular") or not (hints.get("vue") or hints.get("react") or hints.get("next")):
            return "angular"
        if hints.get("vue"):
            return "vue"
        return "angular"
    if len(active) == 1:
        return {"react": "react-router", "vue": "vue", "angular": "angular", "next": "next"}[active[0]]
    if hints.get("react"):
        return "react-router"
    if hints.get("vue"):
        return "vue"
    if hints.get("next"):
        return "next"
    if hints.get("angular"):
        return "angular"
    return "generic"


def _emit(out, seen, source_file, party, line_starts, offset, path, kind, comp) -> None:
    key = (path, source_file)
    if key in seen:
        return
    seen.add(key)
    out.append(
        {
            "path": path,
            "kind": kind,
            "component": comp or "",
            "file": source_file,
            "line": _line_of(line_starts, offset),
            "party": party,
        }
    )


# --- framework hints (for `kind` only; acceptance never depends on them) ------
def _hints(text: str) -> dict:
    low = text.lower()

    def any_in(toks):
        return any(tok in low for tok in toks)

    return {
        "react": any_in(
            (
                "react-router", "createbrowserrouter", "createhashrouter",
                "creatememoryrouter", "useroutes", "routerprovider",
                "react-router-dom", "<route",
            )
        ),
        "vue": any_in(
            (
                "vue-router", "createwebhistory", "createwebhashhistory",
                "<router-view", "$router", "vuerouter", "createrouter",
            )
        ),
        "angular": any_in(
            ("@angular/router", "routermodule", "loadchildren", "ɵ", "activatedroute", "router-outlet")
        ),
        "next": any_in(("next/router", "__next_data__", "next/link", "/_next/", "next/navigation")),
    }


# --- plausibility -------------------------------------------------------------
def _clean_path(raw) -> str:
    if raw is None:
        return ""
    return raw.strip().replace("\\/", "/")


def _plausible(p: str) -> bool:
    if not p:
        return False
    s = p.strip()
    if not s:
        return False
    low = s.lower()
    if "://" in low or s.startswith("//"):
        return False
    # scheme like mailto:/tel:/data:/javascript: (but not a bare "/path")
    if not s.startswith("/") and _SCHEME_RE.match(s) and ":" in s.split("/", 1)[0]:
        return False
    if s.startswith((".", "~", "\\")):
        return False
    if s.startswith(("/static/", "/assets/", "/public/", "/dist/", "/build/")) or "/node_modules/" in low:
        return False
    if _ASSET_EXT_RE.search(low):
        return False
    if s.startswith("/"):
        # a route path has no whitespace / JSX / quoting / list punctuation
        if any(c in s for c in (" ", "\t", "\n", "<", ">", "{", "}", "(", ")", "'", '"', "`", ",", ";")):
            return False
        return True
    # bare segment (Angular-style, no leading slash)
    if len(s) > 80:
        return False
    return bool(_BARE_RE.match(s))


# --- text / offsets -----------------------------------------------------------
def _read_text(item) -> str:
    sp = getattr(item, "saved_path", None)
    if sp:
        try:
            with open(sp, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except (OSError, ValueError):
            pass
    body = getattr(item, "js_body", None)
    return body if isinstance(body, str) else ""


def _basename(item) -> str:
    sp = getattr(item, "saved_path", None)
    if sp:
        return os.path.basename(sp)
    url = getattr(item, "url", "") or ""
    path = url.split("?", 1)[0].split("#", 1)[0]
    return path.rsplit("/", 1)[-1] or url or ""


def _line_index(text: str) -> list:
    """Offsets at which each line starts (``starts[0] == 0``)."""
    starts = [0]
    i = text.find("\n")
    while i != -1:
        starts.append(i + 1)
        i = text.find("\n", i + 1)
    return starts


def _line_of(starts: list, offset: int) -> int:
    """1-based line number for a character offset (manual bisect_right)."""
    lo, hi = 0, len(starts)
    while lo < hi:
        mid = (lo + hi) // 2
        if starts[mid] <= offset:
            lo = mid + 1
        else:
            hi = mid
    return lo or 1

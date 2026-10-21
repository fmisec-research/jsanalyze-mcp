"""Fold single-file string constants into whole endpoint paths (critique round 3, pt 3).

jsluice reports string *literals*, so ``const API = "/api/v2"; fetch(API + "/admin/users")``
comes back as two fragments — ``/api/v2`` and ``/admin/users`` — and the real endpoint
``/api/v2/admin/users`` is never seen. This is NOT a second URL extractor and NOT a JS
parser: it reuses the same idea as the taint walker — resolve a string-valued identifier
by its in-file assignment, a few hops — and folds ``IDENT + "literal"`` concatenations and
template literals like ``${IDENT}/x`` into one path. An identifier that does not resolve to a
string becomes ``EXPR`` (the endpoint normalizer already treats that as a dynamic segment).

``resolve_string_endpoints(items)`` returns url-records shaped like linkfinder rows
(``type:"concat"``, ``detector:"strings"``). Pure, stdlib-only, never fetches, never raises.
"""

from __future__ import annotations

import os
import re

__all__ = ["resolve_string_endpoints", "fold_expr"]

# a client bound to a baseURL:  const c = axios.create({ baseURL: "/api/v2" })  |
# new ApolloClient({ uri: BASE })  |  const cfg = { baseURL: "…" }
_CLIENT_DEF_RE = re.compile(
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
    r"(?:[A-Za-z_$][\w$.]*\s*\.\s*create|new\s+[A-Za-z_$][\w$.]*)?\s*\(\s*\{([^{}]{0,600})\}")
_BASEURL_RE = re.compile(
    r"""\b(?:baseURL|baseUrl|basePath|apiHost|apiBase|apiUrl|uri|endpoint|host)\s*:\s*"""
    r"""("[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[A-Za-z_$][\w$.]*)""")
# a method call on a known client:  c.get("/admin/users")  |  c.post(PATH + "/x")
_CLIENT_CALL_RE = re.compile(
    r"\b([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|head|options|request)\s*\(\s*"
    r"""((?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[A-Za-z_$][\w$.]*)"""
    r"""(?:\s*\+\s*(?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`|[A-Za-z_$][\w$.]*)){0,5})""")

# a run of (string | identifier) joined by `+` — 2..7 operands (a URL built by concatenation)
_CONCAT_RE = re.compile(
    r"""((?:"[^"\n]*"|'[^'\n]*'|[A-Za-z_$][\w$.]*)(?:\s*\+\s*(?:"[^"\n]*"|'[^'\n]*'|[A-Za-z_$][\w$.]*)){1,6})"""
)
# a `const|let|var NAME = <string-concat>` declaration (RHS captured, resolved iteratively)
_STR_DECL_RE = re.compile(
    r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"""
    r"""((?:"[^"\n]*"|'[^'\n]*'|`[^`\n]*`)(?:\s*\+\s*(?:"[^"\n]*"|'[^'\n]*'|[A-Za-z_$][\w$.]*))*)\s*[;,\n]"""
)
# a template literal with interpolation: `${X}/y/${Z}`
_TMPL_RE = re.compile(r"`([^`\n]*\$\{[^`\n]*)`")
_TMPL_VAR_RE = re.compile(r"\$\{\s*([A-Za-z_$][\w$.]*)\s*\}")
_IDENT_RE = re.compile(r"^[A-Za-z_$][\w$.]*$")
_ASSET_EXT = (".js", ".mjs", ".css", ".map", ".png", ".jpg", ".svg", ".woff", ".woff2",
              ".ttf", ".ico", ".gif", ".webp", ".json")


def _split_plus(expr: str) -> list:
    """Split on ``+`` that is NOT inside a quote."""
    parts, buf, q = [], [], ""
    for ch in expr:
        if q:
            buf.append(ch)
            if ch == q:
                q = ""
        elif ch in "\"'`":
            q = ch
            buf.append(ch)
        elif ch == "+":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return [p.strip() for p in parts if p.strip()]


def fold_expr(expr: str, consts: dict) -> "tuple[str, bool]":
    """Fold a ``+``-concatenation to a string. Returns ``(value, used_ident)`` where an
    identifier that does not resolve becomes ``EXPR``. ``used_ident`` marks that at least
    one operand was a variable (so the result is NOT just a literal jsluice already had)."""
    out, used = [], False
    for p in _split_plus(expr):
        if p[:1] in "\"'`":
            out.append(p[1:-1])
        elif _IDENT_RE.match(p):
            used = True
            v = consts.get(p)
            out.append(v if v is not None else "EXPR")
        else:
            used = True
            out.append("EXPR")
    return "".join(out), used


def _build_consts(text: str) -> dict:
    """Map of fully-resolved string constants in one file (a few hops, string RHS only)."""
    raw = {m.group(1): m.group(2) for m in _STR_DECL_RE.finditer(text)}
    resolved: dict = {}
    for _ in range(4):                                   # bounded fixpoint
        progressed = False
        for name, rhs in raw.items():
            if name in resolved:
                continue
            val, _used = fold_expr(rhs.replace("`", '"'), resolved)
            if "EXPR" not in val:                        # only keep a CONCRETE string
                resolved[name] = val
                progressed = True
        if not progressed:
            break
    return resolved


def _looks_endpoint(s: str) -> bool:
    if not s or " " in s or len(s) < 3:
        return False
    low = s.lower().split("?", 1)[0].split("#", 1)[0]
    if low.startswith(("http://", "https://", "//")):
        return True
    if s.startswith("/") and not s.startswith("//"):
        return not low.endswith(_ASSET_EXT)
    return False


def _fold_template(tmpl: str, consts: dict) -> "tuple[str, bool]":
    used = False

    def sub(m):
        nonlocal used
        used = True
        return consts.get(m.group(1), "EXPR")

    return _TMPL_VAR_RE.sub(sub, tmpl), used


def _join(base: str, path: str) -> str:
    if not path:
        return base
    if path.startswith(("http://", "https://", "//")):
        return path
    return base.rstrip("/") + ("" if path.startswith("/") else "/") + path


def _client_base_map(text: str, consts: dict) -> dict:
    """Map a client identifier to its resolved baseURL (axios.create / ApolloClient / config)."""
    clients: dict = {}
    for m in _CLIENT_DEF_RE.finditer(text):
        name, objbody = m.group(1), m.group(2)
        bm = _BASEURL_RE.search(objbody)
        if not bm:
            continue
        tok = bm.group(1)
        base = tok[1:-1] if tok[:1] in "\"'`" else consts.get(tok)
        if base:                                         # only a CONCRETE base (no half-fold)
            clients[name] = base
    return clients


def resolve_string_endpoints(items) -> list:
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
        consts = _build_consts(text)
        clients = _client_base_map(text, consts)

        def add(url, pos, *, method="", detector="strings", ctype="concat"):
            if not _looks_endpoint(url):
                return
            key = (base, method, url)
            if key in seen:
                return
            seen.add(key)
            rec = {"url": url, "type": ctype, "detector": detector,
                   "source_file": base, "filename": sp, "line": text.count("\n", 0, pos) + 1}
            if method:
                rec["method"] = method
            if "EXPR" in url:
                # a half-folded path — the EXPR is a build gap, NOT necessarily an id segment,
                # so it must not become an IDOR just because folding stopped (round 4 pt 1).
                rec["fold_partial"] = True
            out.append(rec)

        for m in _CONCAT_RE.finditer(text):
            expr = m.group(1)
            if "/" not in expr:                          # must build a path, not e.g. a+b message
                continue
            folded, used_ident = fold_expr(expr, consts)
            if used_ident:                               # a concat with a variable (jsluice can't join it)
                add(folded, m.start())
        for m in _TMPL_RE.finditer(text):
            if "/" not in m.group(1):
                continue
            folded, used_ident = _fold_template(m.group(1), consts)
            if used_ident:
                add(folded, m.start())
        # baseURL join: a client method call `c.get("/x")` -> baseURL + "/x" (round 4 pt 1)
        for m in _CLIENT_CALL_RE.finditer(text):
            name, verb, pathexpr = m.group(1), m.group(2), m.group(3)
            if name not in clients:
                continue
            path, _u = fold_expr(pathexpr, consts)
            add(_join(clients[name], path), m.start(), method=verb.upper(), detector="baseurl",
                ctype=f"client.{verb}")
    return out

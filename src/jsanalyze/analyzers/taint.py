"""Bounded backward taint tracer (critique point 1) — pure, stdlib-only.

jsluice marks only DIRECT taint: ``el.innerHTML = location.hash`` is caught, but the
real-bundle shape ``var t = location.hash; ... el.innerHTML = t`` (one hop through a
helper variable) reports ``tainted:false`` — empirically verified. React's
``dangerouslySetInnerHTML = f(t)`` / ``{__html: t}`` and Vue's ``v-html`` are not
emitted by jsluice at all.

This module adds the missing JUDGEMENT layer over jsluice's facts (it does NOT run a
second URL/secret extractor):

  * :func:`backtrace` walks an identifier backward through assignments and
    single-parameter function bodies, up to ``max_hops`` *inside one file*, and reports
    whether the chain reaches a known attacker-controllable source — with the short
    human-readable chain.
  * :func:`discover_html_sinks` finds the ``dangerouslySetInnerHTML`` / ``{__html:}`` /
    ``v-html`` sink sites jsluice misses, so they can be traced too.

Deliberately CONSERVATIVE: it follows nearest-definition assignments and simple param
bindings only, is bounded, and resolves nothing across files. A sink whose argument it
cannot tie to a source is reported ``reached=None`` so the caller keeps it as a
low-confidence ``sink-untraced`` audit row — promoted to a lead ONLY on a real source.
"""

from __future__ import annotations

import re

__all__ = ["backtrace", "sink_arg_idents", "discover_html_sinks", "source_label"]

# attacker-controllable source tokens (lower-cased substring test on an expression).
# NOTE (round 2, point 2): the loose ``.data`` / bare ``location`` matchers are gone —
# they tagged ``formData`` / ``metadata`` / ``updateLocation`` as attacker input. A
# ``.data`` source must be a MESSAGE-event data access (``e.data`` / ``event.data``),
# never any identifier that happens to end in "data".
_SOURCES = (
    "location.hash", "location.search", "location.href", "location.pathname",
    "document.url", "document.documenturi", "document.referrer",
    "document.baseuri", "window.name", "postmessage",
    "localstorage", "sessionstorage", "urlsearchparams", "searchparams",
    "getparameter", "referrer",
    "event.data", "e.data", "evt.data", "ev.data", "msg.data", "message.data",
    "window.location", "hashchange", "popstate",
)
# a source token that, standing alone, is really just navigation (not injectable)
_NAV_ONLY = ("location.pathname", "location.origin")

_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")
_SOURCE_RE = re.compile(
    r"location\s*\.\s*(?:hash|search|href|pathname)"
    r"|document\s*\.\s*(?:URL|documentURI|referrer|baseURI)"
    # a message-event data access ONLY — bound the left side to a known event ident so
    # ``formData`` / ``metadata`` / ``res.data`` are NOT treated as attacker sources.
    r"|\b(?:e|ev|evt|event|msg|message)\s*\.\s*data\b"
    r"|window\s*\.\s*name|URLSearchParams|searchParams|getParameter"
    r"|localStorage|sessionStorage|\breferrer\b",
    re.IGNORECASE,
)

# JS globals / DOM that are not taint carriers when they appear as a bare identifier
_NOISE_IDENTS = {
    "var", "let", "const", "function", "return", "if", "else", "for", "while", "new",
    "this", "true", "false", "null", "undefined", "void", "typeof", "window", "document",
    "console", "JSON", "Object", "Array", "String", "Number", "Boolean", "Math", "Date",
    "await", "async", "yield", "of", "in", "instanceof", "class", "extends", "super",
}


def source_label(expr: str) -> "str | None":
    """Return the attacker-source substring present in ``expr`` (navigation-only
    self-copies excluded), or None."""
    low = (expr or "").lower()
    hit = None
    m = _SOURCE_RE.search(expr or "")
    if m:
        hit = m.group(0)
    else:
        for s in _SOURCES:
            if s in low:
                hit = s
                break
    if hit is None:
        return None
    hl = hit.lower().replace(" ", "")
    # a bare location.pathname/origin with no injectable token is navigation, not XSS
    if hl in _NAV_ONLY:
        return None
    return hit


def sink_arg_idents(kind: str, source: str) -> list:
    """Root identifiers of a sink's *argument* (the value that could be tainted).

    ``q.innerHTML = t``        -> ['t']
    ``x.innerHTML = a + b``    -> ['a', 'b']
    ``eval(foo)``              -> ['foo']
    ``el.innerHTML = "<b>"+x`` -> ['x']
    """
    expr = _arg_expr(kind, source)
    return _root_idents(expr)


def _arg_expr(kind: str, source: str) -> str:
    s = source or ""
    if kind in ("eval", "Function", "setTimeout", "setInterval", "dangerouslySetInnerHTML",
                "v-html", "insertAdjacentHTML"):
        m = re.search(r"\((.*)\)\s*;?\s*$", s, re.S)
        if m:
            return m.group(1)
    # property/assignment sink: take the RHS of the first single '='
    eq = re.search(r"(?<![=!<>])=(?![=])", s)
    if eq:
        return s[eq.end():]
    return s


def _root_idents(expr: str) -> list:
    """Identifiers in ``expr`` that are not a property access tail, string content,
    or a JS keyword/global — i.e. the variables that could carry taint."""
    out = []
    # drop string literals so their contents aren't scanned
    stripped = re.sub(r"""(['"`])(?:\\.|(?!\1).)*\1""", " ", expr or "")
    for m in _IDENT_RE.finditer(stripped):
        name = m.group(0)
        prev = stripped[m.start() - 1] if m.start() > 0 else ""
        if prev == ".":                      # a.b -> skip the property name `b`
            continue
        if name in _NOISE_IDENTS:
            continue
        if name not in out:
            out.append(name)
    return out


def backtrace(text: str, idents, max_hops: int = 4,
              before: "int | None" = None) -> "tuple[str | None, list[str]]":
    """Walk ``idents`` backward through assignments / simple params in ``text``.

    Returns ``(source_or_None, chain)`` where ``chain`` is the short list of hops
    (e.g. ``['t = location.hash.slice(1)']``). Bounded by ``max_hops`` and a visited
    set; resolves nearest definitions only and never leaves this file.

    ``before`` is the character offset of the SINK. In a minified bundle one letter
    (``t``) is reassigned dozens of times; the definition that taints the sink is the
    nearest one *preceding* it, never the first in the file (round 2, point 2). An
    assignment at/after the sink cannot taint it, so it is ignored.
    """
    if isinstance(idents, str):
        idents = [idents]
    # any starting ident that is itself a source expression?
    for idv in idents:
        lab = source_label(idv)
        if lab:
            return lab, [idv]

    visited: set = set()
    # each item carries the offset below which its definition must sit
    work = [(i, before) for i in dict.fromkeys(idents)]
    chain: list[str] = []
    hops = 0
    while work and hops < max_hops:
        hops += 1
        nxt: list = []
        for name, limit in work:
            if name in visited or name in _NOISE_IDENTS:
                continue
            visited.add(name)
            rhs, at = _definition_rhs(text, name, limit)
            if rhs is None:
                # maybe it is a function parameter bound at a call site
                rhs = _param_binding(text, name)
                if rhs is None:
                    continue
                chain.append(f"{name} ⇐ {_short(rhs)}")
                at = None
            else:
                chain.append(f"{name} = {_short(rhs)}")
            lab = source_label(rhs)
            if lab:
                return lab, chain
            for sub in _root_idents(rhs):
                if sub not in visited:
                    nxt.append((sub, at))        # the next hop must precede THIS def
        work = list(dict.fromkeys(nxt))
    return None, chain


def _definition_rhs(text: str, name: str,
                    before: "int | None" = None) -> "tuple[str | None, int | None]":
    """RHS (and start offset) of the ``[var|let|const] name = <rhs>`` assignment nearest
    *before* ``before``; the first in the file when ``before`` is None. Returns
    ``(None, None)`` if the only definitions sit at/after the sink."""
    rx = re.compile(r"(?:\b(?:var|let|const)\s+)?\b" + re.escape(name) + r"\s*=\s*([^;\n,]{1,300})")
    chosen = None
    for m in rx.finditer(text):
        rhs = m.group(1).strip()
        if re.match(r"^" + re.escape(name) + r"\b", rhs):
            continue                             # self-reference (name = name.foo) — skip
        if before is None:
            chosen = m
            break                                # first definition (whole-file fallback)
        if m.start() < before:
            chosen = m                           # keep the LATEST one preceding the sink
        else:
            break                                # reached/passed the sink: later defs can't taint it
    if chosen is None:
        return None, None
    return chosen.group(1).strip(), chosen.start()


def _param_binding(text: str, name: str) -> "str | None":
    """If ``name`` is the SOLE parameter of a named function/arrow, return the first
    call-site argument bound to it (best-effort, single-arg only)."""
    # function NAME(name){...}  |  const NAME = (name) => ...  |  const NAME = name => ...
    for rx in (
        re.compile(r"function\s+([A-Za-z_$][\w$]*)\s*\(\s*" + re.escape(name) + r"\s*\)"),
        re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*\(\s*" + re.escape(name) + r"\s*\)\s*=>"),
        re.compile(r"\b([A-Za-z_$][\w$]*)\s*=\s*" + re.escape(name) + r"\s*=>"),
    ):
        fm = rx.search(text)
        if not fm:
            continue
        fname = fm.group(1)
        for cm in re.finditer(re.escape(fname) + r"\s*\(\s*([^),;]{1,200})\)", text):
            arg = cm.group(1).strip()
            # skip the declaration itself (arg is the bare param name, or preceded by
            # `function `) — we want a real CALL site that passes a different expression.
            if arg == name:
                continue
            if text[max(0, cm.start() - 9):cm.start()] == "function ":
                continue
            return arg
    return None


def _short(s: str, n: int = 80) -> str:
    s = " ".join((s or "").split())
    return s[:n] + ("…" if len(s) > n else "")


# --- framework / DOM HTML sinks jsluice does not emit -------------------------
_DSIH_RE = re.compile(r"dangerouslySetInnerHTML\s*[=:]\s*(\{[^}]{0,200}\}|[^,;\n}]{1,120})")
_HTML_PROP_RE = re.compile(r"__html\s*:\s*([^,}\n]{1,160})")
_VHTML_RE = re.compile(r"""v-html\s*=\s*(['"])(.*?)\1|"v-html"\s*,\s*([^,)\n]{1,120})""")
# round 2, new sinks: DOMParser.parseFromString(x,'text/html'), Range.createContextual
# Fragment(x), and the iframe `srcdoc` property/attribute — all parse attacker HTML.
_DOMPARSER_RE = re.compile(r"\.\s*parseFromString\s*\(\s*([^,){\n]{1,160})")
_CCF_RE = re.compile(r"\.\s*createContextualFragment\s*\(\s*([^){\n]{1,160})")
_SRCDOC_RE = re.compile(r"""\bsrcdoc\s*[=:]\s*(?!['"])([^,;)}\n]{1,160})|\bsrcdoc\s*=\s*(['"])(.*?)\2""")


def discover_html_sinks(text: str) -> list:
    """Synthetic sink records for React/Vue/DOM HTML sinks jsluice misses.

    Each: ``{"kind","source","line","pos","arg_expr","framework"}`` — the caller traces
    ``arg_expr`` and clusters/promotes exactly like a jsluice sink. ``pos`` is the char
    offset so the tracer can scope to the nearest definition before it.
    """
    out = []
    if not text:
        return out
    seen = set()

    def add(kind, whole, arg, pos, fw):
        line = text.count("\n", 0, pos) + 1
        key = (kind, line, _short(arg, 40))
        if key in seen:
            return
        seen.add(key)
        out.append({"kind": kind, "source": _short(whole, 160), "line": line, "pos": pos,
                    "arg_expr": arg.strip(), "framework": fw})

    for m in _DSIH_RE.finditer(text):
        val = m.group(1)
        hm = _HTML_PROP_RE.search(val)
        arg = hm.group(1) if hm else val
        add("dangerouslySetInnerHTML", m.group(0), arg, m.start(), "react")
    # a bare {__html: x} not captured above (object built elsewhere)
    for m in _HTML_PROP_RE.finditer(text):
        add("dangerouslySetInnerHTML", m.group(0), m.group(1), m.start(), "react")
    for m in _VHTML_RE.finditer(text):
        arg = m.group(2) or m.group(3) or ""
        if arg:
            add("v-html", m.group(0), arg, m.start(), "vue")
    for m in _DOMPARSER_RE.finditer(text):
        add("parseFromString", m.group(0), m.group(1), m.start(), "dom")
    for m in _CCF_RE.finditer(text):
        add("createContextualFragment", m.group(0), m.group(1), m.start(), "dom")
    for m in _SRCDOC_RE.finditer(text):
        arg = m.group(3) if m.group(3) is not None else m.group(1)
        if arg:
            add("srcdoc", m.group(0), arg, m.start(), "dom")
    return out

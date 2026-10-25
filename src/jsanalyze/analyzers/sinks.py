"""Triage jsluice `sinks` output into an auditable, de-noised set (critique point 1).

jsluice flags every DOM-sink occurrence; naively one-lead-per-row floods the queue with
feature-detection probes and vendor polyfills (`"<svg>"+a+"</svg>"` ×25, `Function("return
this")`, `eval("require('crypto')")`, `document.cookie=...`, `href = location.href`). This
module:

  * classifies each sink (html / js / url / attr / cookie),
  * DROPS pure noise: constant-literal args, and cookie writes (those belong in storage.json),
  * judges REAL taint — `tainted:true` counts only when the source is attacker-controllable
    (location.hash/search, event.data, referrer, storage, params); `location.href` copied to a
    same-kind `href`/`src` is navigation, not DOM-XSS,
  * clusters identical-shape occurrences into ONE record with a count + occurrences,
  * tags party (first/vendor/third).

Only clusters with `lead=True` (real attacker taint, actionable class) should become XSS
leads; every surviving cluster is kept in sinks.json for audit.
"""

from __future__ import annotations

import os
import re

from jsanalyze.analyzers.taint import (
    backtrace, discover_html_sinks, sink_arg_idents, source_label, _root_idents,
)
from jsanalyze.party import party_of

_SINK_CLASS = {
    "innerHTML": "html", "outerHTML": "html", "dangerouslySetInnerHTML": "html",
    "insertAdjacentHTML": "html", "documentWrite": "html", "document.write": "html",
    "v-html": "html", "parseFromString": "html", "createContextualFragment": "html",
    "srcdoc": "html",
    "eval": "js", "Function": "js", "setTimeout": "js", "setInterval": "js",
    "src": "url", "href": "url", "location": "url", "location.href": "url",
    "assign": "url", "replace": "url", "open": "url",
    "setAttribute": "attr",
    "documentCookie": "cookie",
}

# attacker-controllable taint origins (lower-cased substring match on jsluice `taint`)
_ATTACKER_SOURCES = (
    "location.hash", "location.search", "location.href", "location.pathname", "location",
    "document.url", "document.documenturi", "document.referrer", "document.baseuri",
    "window.name", "event.data", "e.data", ".data", "postmessage",
    "localstorage", "sessionstorage", "urlsearchparams", "searchparams",
    "getparameter", "referrer", "hash", "search",
)
# tokens that mean "really attacker input" even on a url-class sink
_INJECTABLE = ("hash", "search", "param", "data", "storage", "referrer", "name", "query")
# a url-class taint that is just the current location copied around = navigation, not XSS
_SELF_NAV = ("location.href", "location.pathname", "location.origin", "document.location")
# a url-class sink is XSS only when the scheme can be javascript:/data:text/html — otherwise a
# tainted navigation target is an OPEN REDIRECT, not DOM-XSS (round 5 pt 13).
_JS_SCHEME_RE = re.compile(r"javascript:|data:\s*text/html|vbscript:", re.I)

_STRING_RE = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")

# a sanitizer whose OUTPUT lands in this sink — maps the call name to its retire component
# so a vulnerable VERSION (known bypass) can be bound to the actual call site (round 4 pt 4).
# must be a CALL (`DOMPurify.sanitize(` / `marked(` / `xss(`) — a bare word `xss` or `marked`
# in a snippet is not a sanitizer invocation (round 5 pt 8).
_SANITIZER_RE = re.compile(
    r"\b(DOMPurify|sanitizeHtml|sanitize_html|marked|markdownit|markdown_it|xss)\b"
    r"\s*(?:\.\s*[A-Za-z_$][\w$]*\s*)?\(")
_SAN_COMPONENT = {
    "dompurify": "dompurify", "sanitizehtml": "sanitize-html", "sanitize_html": "sanitize-html",
    "marked": "marked", "markdownit": "markdown-it", "markdown_it": "markdown-it", "xss": "xss",
}

# builtin/DOM calls that are NOT a "missing helper" if absent from the capture
_NOISE_CALLS = frozenset({
    "String", "Number", "Boolean", "Array", "Object", "JSON", "parse", "stringify",
    "encodeURIComponent", "decodeURIComponent", "encodeURI", "decodeURI", "escape",
    "unescape", "getElementById", "querySelector", "querySelectorAll", "getAttribute",
    "createElement", "require", "import", "setTimeout", "setInterval", "fetch", "concat",
    "slice", "substring", "substr", "replace", "trim", "toString", "map", "join", "split",
    "if", "for", "while", "switch", "return", "function", "catch", "then",
})


def _sink_class(kind: str) -> str:
    return _SINK_CLASS.get(kind, "html")


def _is_constant_arg(kind: str, source: str) -> bool:
    """True if a code-exec sink's argument is only string literal(s) — a hardcoded
    constant (`Function("return this")`, `eval("require('crypto')")`), never attacker input."""
    if kind not in ("eval", "Function", "setTimeout", "setInterval"):
        return False
    m = re.search(r"\b(?:eval|Function|setTimeout|setInterval)\s*\((.*)\)\s*;?\s*$",
                  source or "", re.S)
    inner = (m.group(1) if m else "").strip()
    if not inner:
        return False
    # strip string literals; if only separators/operators remain, the arg was constant
    residue = _STRING_RE.sub("", inner)
    return not _IDENT_RE.search(residue)


def _real_taint(sink_class: str, tainted, taint) -> bool:
    if not tainted:
        return False
    t = (taint or "").lower()
    if not t or not any(src in t for src in _ATTACKER_SOURCES):
        return False
    if sink_class == "url" and any(sn in t for sn in _SELF_NAV) \
            and not any(tok in t for tok in _INJECTABLE):
        return False  # location.href -> href: navigation self-copy, not DOM-XSS
    return True


def _signature(kind: str, sink_class: str, source: str, real_taint: bool):
    s = _STRING_RE.sub('"S"', source or "")
    s = re.sub(r"\b\d+\b", "N", s)
    s = _IDENT_RE.sub("V", s)
    s = re.sub(r"\s+", "", s)
    return (kind, sink_class, real_taint, s[:140])


def _prio(sink_class: str) -> tuple:
    # (severity_hint, confidence) for a REAL-tainted sink of this class
    return {
        "js": ("critical", "high"),
        "html": ("high", "high"),
        "url": ("medium", "medium"),
        "attr": ("medium", "medium"),
    }.get(sink_class, ("medium", "medium"))


_FN_DECL_RE = re.compile(r"\bfunction\s+([A-Za-z_$][\w$]*)\s*\(")
_FN_ARROW_RE = re.compile(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*")
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_$][\w$]*)\s*\(")
_RETURN_RE = re.compile(r"\breturn\b([^;\n}]{1,200})")
# a brace-bodied function HEADER in any of the shapes minifiers emit (round 5 pt 15):
# function NAME(p){ | const NAME = (p)=>{ | NAME = function(p){ | NAME: (p)=>{ | const NAME = p =>{
_FN_HEADER_RE = re.compile(
    r"function\s+(?P<n1>[A-Za-z_$][\w$]*)\s*\((?P<p1>[^)]*)\)\s*\{"
    r"|\b(?:const|let|var)\s+(?P<n2>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?:function\s*\*?\s*)?\((?P<p2>[^)]*)\)\s*(?:=>\s*)?\{"
    r"|\b(?:const|let|var)\s+(?P<n4>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s+)?(?P<p4>[A-Za-z_$][\w$]*)\s*=>\s*\{"
    r"|(?P<n3>[A-Za-z_$][\w$.]*)\s*[:=]\s*(?:async\s+)?(?:function\s*\*?\s*)?\((?P<p3>[^)]*)\)\s*(?:=>\s*)?\{")


def _balanced(text: str, open_idx: int) -> int:
    """End index of the ``{…}`` opening at ``open_idx`` — STRING-AWARE, so a ``{`` or ``}``
    inside a quote/template does not break the function body (round 4, point 2)."""
    depth, j = 0, open_idx
    cap = min(len(text), open_idx + 8000)
    q = ""
    while j < cap:
        ch = text[j]
        if q:
            if ch == "\\":
                j += 2
                continue
            if ch == q:
                q = ""
        elif ch in "\"'`":
            q = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return j
        j += 1
    return -1


def _enclosing_fn(text: str, pos: int) -> "tuple[str, list] | None":
    """The nearest named/assigned/arrow function whose balanced body contains ``pos`` ->
    (name, [params]). Handles `function f(){}`, `const f=(e)=>{}`, `x.f=function(e){}` (pt 15)."""
    best = None
    for m in _FN_HEADER_RE.finditer(text):
        if m.start() > pos:
            break
        br = m.end() - 1                       # the '{' the header ends on
        end = _balanced(text, br)
        if end != -1 and br < pos <= end:
            name = m.group("n1") or m.group("n2") or m.group("n3") or m.group("n4")
            praw = m.group("p1") or m.group("p2") or m.group("p3") or m.group("p4") or ""
            params = [p.strip().split("=")[0].strip() for p in praw.split(",") if p.strip()]
            best = ((name or "").split(".")[-1], params)   # innermost enclosing (latest start)
    return best


# an ANONYMOUS function header — no name to resolve a call site by (a hard minify limit):
#   function (p){…}  |  function* (p){…}  |  (p)=>{…}  |  p=>{…}  (callbacks, IIFEs)
_ANON_FN_RE = re.compile(
    r"function\s*\*?\s*\((?P<pa>[^)]*)\)\s*\{"
    r"|(?<![\w$)\]])\(\s*(?P<pb>[^)]*)\)\s*=>\s*\{"
    r"|(?<![\w$.])(?P<ps>[A-Za-z_$][\w$]*)\s*=>\s*\{")


def _anon_param_of_sink(text: str, pos: int, sink_ids) -> "str | None":
    """If the sink at ``pos`` sits inside an ANONYMOUS function and uses one of its parameters,
    return that parameter (round 6 pt 9). Its caller cannot be named across chunks, so the lead
    SAYS "anonymous function" instead of going silent — ``function (e){node.innerHTML=e}`` reached
    only from ``ye(location.hash)`` in another chunk is a real break, not an absence of a sink."""
    best = None
    for m in _ANON_FN_RE.finditer(text):
        if m.start() > pos:
            break
        br = m.end() - 1                       # the '{' the header ends on
        end = _balanced(text, br)
        if end != -1 and br < pos <= end:
            praw = m.group("pa") or m.group("pb") or m.group("ps") or ""
            params = [p.strip().split("=")[0].strip() for p in praw.split(",") if p.strip()]
            hit = next((i for i in sink_ids if i in params), None)
            if hit:
                best = hit                     # innermost (latest start) enclosing anon fn wins
    return best


def _fn_call_args(items) -> dict:
    """Run-wide index {fname: [(basefile, first_arg_expr)]} — the call sites of named
    functions across every file (the CALLER side of a cross-file taint, round 4 pt 2)."""
    calls: dict = {}
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
        for m in _CALL_NAME_RE.finditer(text):
            name = m.group(1)
            if name in _NOISE_CALLS:
                continue
            arg = _first_arg(text, m.end() - 1)
            if arg:
                calls.setdefault(name, [])
                if len(calls[name]) < 20:
                    calls[name].append((base, arg))
    return calls


def _first_arg(text: str, paren_idx: int) -> str:
    """The first argument expression of a call whose ``(`` is at ``paren_idx`` (balanced,
    stops at the top-level comma or the closing paren)."""
    depth, j = 0, paren_idx
    cap = min(len(text), paren_idx + 400)
    start = paren_idx + 1
    q = ""
    while j < cap:
        ch = text[j]
        if q:
            if ch == "\\":
                j += 2
                continue
            if ch == q:
                q = ""
        elif ch in "\"'`":
            q = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[start:j].strip()
        elif ch == "," and depth == 1:
            return text[start:j].strip()
        j += 1
    return ""


def _fn_index(items) -> "tuple[dict, set]":
    """Run-wide ONE-LEVEL function index (round 3 pt 4): ``{fname: return_expr}`` for a
    function's first ``return`` and the set of ALL defined names. Lets the single-file tracer
    follow a called helper that lives in another chunk exactly one hop — and, when the helper
    is absent from the capture, say the chain broke at the file boundary instead of faking taint."""
    returns: dict = {}
    defined: set = set()
    for it in items or []:
        sp = getattr(it, "saved_path", None)
        if not sp:
            continue
        try:
            with open(sp, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in _FN_DECL_RE.finditer(text):
            name = m.group(1)
            defined.add(name)
            br = text.find("{", m.end())
            if br != -1 and br - m.end() < 40:
                end = _balanced(text, br)
                if end != -1:
                    rm = _RETURN_RE.search(text, br, end)
                    if rm and name not in returns:
                        returns[name] = rm.group(1).strip()
        for m in _FN_ARROW_RE.finditer(text):
            name = m.group(1)
            defined.add(name)
            tail = text[m.end():m.end() + 200]
            if tail[:1] != "{":                          # expression-body arrow: tail IS the return
                returns.setdefault(name, tail.split(";")[0].split("\n")[0].strip())
        for m in _FN_HEADER_RE.finditer(text):           # assigned/method/arrow names too (pt 15)
            nm = m.group("n1") or m.group("n2") or m.group("n3") or m.group("n4")
            if nm:
                defined.add(nm.split(".")[-1])
    return returns, defined


def _called_names(expr: str) -> list:
    return [m.group(1) for m in _CALL_NAME_RE.finditer(expr or "")]


def _san_component(source: str) -> "str | None":
    m = _SANITIZER_RE.search(source or "")
    return _SAN_COMPONENT.get(m.group(1).lower()) if m else None


def triage_sinks(sink_records, items, cfg=None, scope_hosts=None) -> list[dict]:
    """Return clustered, classified sink records (for sinks.json). Each has `lead`
    True only for a real-tainted, actionable, non-noise cluster.

    Taint is judged in two passes (critique point 1): jsluice's own ``tainted`` flag,
    then — when that is false but the sink's argument is an identifier — a bounded
    backward trace through the file (``var t = location.hash; … innerHTML = t``). A
    cluster whose argument cannot be tied to a source is kept as a demoted
    ``sink-untraced`` audit row (low confidence, never a lead) rather than dropped.
    React/Vue sinks jsluice misses (``dangerouslySetInnerHTML`` / ``v-html``) are
    discovered and traced the same way.
    """
    path_to_url = {it.saved_path: it.url for it in (items or []) if getattr(it, "saved_path", None)}
    text_by_base = _text_index(items)
    fn_returns, fn_defined = _fn_index(items)            # one-hop cross-file index (round 3 pt 4)
    fn_call_args = _fn_call_args(items)                  # caller-side index (round 4 pt 2)
    clusters: dict = {}

    records = list(sink_records or []) + _discovered_records(items)

    for rec in records:
        if not isinstance(rec, dict):
            continue
        kind = rec.get("kind") or ""
        sink_class = _sink_class(kind)
        source = rec.get("source") or ""

        if sink_class == "cookie":
            continue  # cookie writes are storage, not an XSS sink (see storage.json)
        if _is_constant_arg(kind, source):
            continue  # constant-literal arg -> pure noise, drop entirely

        filename = rec.get("filename") or ""
        src_file = rec.get("source_file") or (filename.rsplit("/", 1)[-1] if filename else "")
        origin = rec.get("origin_url") or path_to_url.get(filename)
        party = party_of(src_file, origin or "", scope_hosts)
        tainted = bool(rec.get("tainted"))
        taint = rec.get("taint")

        # pass 1: jsluice's own direct-taint judgement
        real = _real_taint(sink_class, tainted, taint)
        taint_source = taint if real else None
        chain: list = []
        untraced = False
        crossfile_break = None
        anon_param = None

        # pass 2: bounded backward trace when jsluice saw no direct taint
        if not real and sink_class in ("html", "js", "attr", "url"):
            arg_expr = rec.get("arg_expr") or ""
            # the argument expression may itself BE a source (``parseFromString(location.search)``)
            # — check it directly before reducing to root idents (which would drop the property).
            direct = source_label(arg_expr) if arg_expr else None
            if direct and (sink_class != "url" or any(tok in direct.lower() for tok in _INJECTABLE)):
                real, taint_source = True, direct
                chain = [arg_expr.strip()]
            else:
                idents = (_root_idents(arg_expr) if arg_expr else []) \
                    or sink_arg_idents(kind, source)
                if idents:
                    text = text_by_base.get(src_file, "")
                    if text:
                        # scope the trace to the nearest definition BEFORE this sink — in a
                        # minified bundle the same identifier is assigned many times (point 2).
                        before = _sink_offset(text, source, rec.get("pos"), rec.get("line"))
                        lab, chain = backtrace(text, idents, before=before)
                        if lab and (sink_class != "url" or any(
                                tok in lab.lower() for tok in _INJECTABLE)):
                            real, taint_source = True, lab
                        else:
                            untraced = True
                    else:
                        untraced = True

            # one-hop cross-file (RETURN direction): a called helper whose RETURN is itself a
            # source. Only claims taint when the return LITERALLY reaches a source (round 3).
            if untraced:
                cand = (arg_expr + " " + source + " " + " ".join(chain))
                for fname in _called_names(cand):
                    ret = fn_returns.get(fname)
                    if ret is not None:
                        lab = source_label(ret)
                        if lab and (sink_class != "url" or any(tok in lab.lower() for tok in _INJECTABLE)):
                            real, taint_source, untraced = True, lab, False
                            chain = chain + [f"{fname}() ⇒ {ret[:60]} (cross-file)"]
                            break
                    elif fname not in fn_defined and fname not in _NOISE_CALLS:
                        crossfile_break = crossfile_break or fname

            # one-hop cross-file (CALLER direction, round 4 pt 2): the sink sits inside a helper
            # and uses its PARAMETER; the source is at the call site, often in another chunk —
            # function ye(e){node.innerHTML=e}  (file A) ;  ye(location.hash)  (file B).
            if untraced:
                self_text = text_by_base.get(src_file, "")
                off = _sink_offset(self_text, source, rec.get("pos"), rec.get("line")) or 0
                sink_ids = (_root_idents(arg_expr) if arg_expr else []) or sink_arg_idents(kind, source)
                encl = _enclosing_fn(self_text, off) if self_text else None
                named_owns = bool(encl and encl[0] and any(i in encl[1] for i in sink_ids))
                if named_owns:
                    fname = encl[0]
                    callsites = fn_call_args.get(fname) or []
                    if callsites:
                        for cbase, carg in callsites:
                            lab2 = source_label(carg)
                            c2: list = []
                            if not lab2:
                                ctext = text_by_base.get(cbase, "")
                                ids = _root_idents(carg)
                                if ctext and ids:
                                    lab2, c2 = backtrace(ctext, ids)
                            if lab2 and (sink_class != "url" or any(tok in lab2.lower() for tok in _INJECTABLE)):
                                real, taint_source, untraced = True, lab2, False
                                chain = chain + [f"{fname}({carg}) @ {cbase} (caller, cross-file)"] + c2
                                break
                    else:
                        crossfile_break = crossfile_break or fname
                # still unresolved and NO named function owns the param, but the sink uses a param of
                # an ANONYMOUS function? Then the caller lives in another chunk and cannot be named
                # (minify limit) — record it so the sink-untraced lead explains the break rather than
                # vanishing (round 6 pt 9). `not named_owns` keeps a NAMED arrow (`const f=e=>{…}`)
                # attributed to its helper name, never mislabelled anonymous.
                if untraced and not real and self_text and not named_owns:
                    ap = _anon_param_of_sink(self_text, off, sink_ids)
                    if ap:
                        anon_param = ap
                        chain = chain + [f"{ap} ⇐ parameter of an anonymous function "
                                         f"(caller in another chunk, unnameable — minify limit)"]

        key = _signature(kind, sink_class, source, real)
        occ = {"file": src_file, "line": rec.get("line"), "source": " ".join(source.split())[:200]}
        cl = clusters.get(key)
        if cl is None:
            sev, conf = _prio(sink_class)
            # a cluster leads only if it is really attacker-tainted and first/third party
            # (vendor-bundled sinks are de-prioritised: kept in sinks.json, not a lead)
            lead = real and sink_class in ("html", "js", "url", "attr") and party != "vendor"
            clusters[key] = {
                "sink_class": sink_class, "kind": kind, "party": party,
                "tainted": tainted, "taint_source": taint_source, "real_taint": real,
                "lead": lead, "untraced": untraced and not real,
                "caller_chain": chain, "crossfile_break": crossfile_break, "anon_param": anon_param,
                "sanitizer": _san_component(source),
                # a tainted url-class sink with no javascript:/data: scheme is an open redirect
                "redirect": sink_class == "url" and real and not _JS_SCHEME_RE.search(source),
                "detector": "jsluice:sinks" if not rec.get("discovered") else f"taint:{rec.get('framework', 'dom')}",
                "severity_hint": sev if real else "info",
                "confidence": conf if real else "low",
                "count": 0, "occurrences": [],
            }
            cl = clusters[key]
        cl["count"] += 1
        if chain and not cl.get("caller_chain"):
            cl["caller_chain"] = chain
        if crossfile_break and not cl.get("crossfile_break"):
            cl["crossfile_break"] = crossfile_break    # a later occurrence may find the broken hop
        if anon_param and not cl.get("anon_param"):
            cl["anon_param"] = anon_param
        if taint_source and not cl.get("taint_source"):
            cl["taint_source"] = taint_source
        if len(cl["occurrences"]) < 10:
            cl["occurrences"].append(occ)
        # a cluster's party is first/third if ANY occurrence is (vendor is the weakest)
        if party != "vendor" and cl["party"] == "vendor":
            cl["party"] = party
            if cl["real_taint"]:
                cl["lead"] = True

    # order: leads first, then by severity, then by count
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    out = sorted(
        clusters.values(),
        key=lambda c: (not c["lead"], sev_rank.get(c["severity_hint"], 9), -c["count"]),
    )
    return out


def _sink_offset(text: str, source: str, pos, line) -> "int | None":
    """Char offset of the sink in ``text`` so the tracer can scope to defs before it.

    Prefers an explicit ``pos`` (discovered sinks carry it), then the raw ``source``
    literal, then the start of ``line``. None means 'search the whole file' (old
    behaviour) — acceptable for a short, non-minified file."""
    if isinstance(pos, int) and pos >= 0:
        return pos
    if source:
        idx = text.find(source.strip()[:80])
        if idx != -1:
            return idx
    if isinstance(line, int) and line > 1:
        off = 0
        for _ in range(line - 1):
            nl = text.find("\n", off)
            if nl == -1:
                return None
            off = nl + 1
        return off
    return None


def _text_index(items) -> dict:
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


def _discovered_records(items) -> list:
    """React/Vue/DOM HTML sinks jsluice does not emit, as sink-record dicts."""
    out = []
    for it in (items or []):
        sp = getattr(it, "saved_path", None)
        if not sp:
            continue
        base = os.path.basename(sp)
        try:
            with open(sp, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for d in discover_html_sinks(text):
            out.append({
                "kind": d["kind"], "source": d["source"], "line": d["line"],
                "pos": d.get("pos"),
                "filename": sp, "source_file": base, "origin_url": getattr(it, "url", ""),
                "arg_expr": d["arg_expr"], "framework": d["framework"],
                "tainted": False, "discovered": True,
            })
    return out

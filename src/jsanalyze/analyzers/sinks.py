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
    "v-html": "html",
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

_STRING_RE = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")


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

        # pass 2: bounded backward trace when jsluice saw no direct taint
        if not real and sink_class in ("html", "js", "attr", "url"):
            idents = rec.get("arg_expr") and _root_idents(rec["arg_expr"]) \
                or sink_arg_idents(kind, source)
            if idents:
                text = text_by_base.get(src_file, "")
                if text:
                    lab, chain = backtrace(text, idents)
                    if lab and (sink_class != "url" or any(
                            tok in lab.lower() for tok in _INJECTABLE)):
                        real, taint_source = True, lab
                    else:
                        untraced = True
                else:
                    untraced = True

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
                "caller_chain": chain,
                "detector": "jsluice:sinks" if not rec.get("discovered") else f"taint:{rec.get('framework', 'dom')}",
                "severity_hint": sev if real else "info",
                "confidence": conf if real else "low",
                "count": 0, "occurrences": [],
            }
            cl = clusters[key]
        cl["count"] += 1
        if chain and not cl.get("caller_chain"):
            cl["caller_chain"] = chain
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
    """React/Vue HTML sinks jsluice does not emit, as sink-record dicts."""
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
                "filename": sp, "source_file": base, "origin_url": getattr(it, "url", ""),
                "arg_expr": d["arg_expr"], "framework": d["framework"],
                "tainted": False, "discovered": True,
            })
    return out

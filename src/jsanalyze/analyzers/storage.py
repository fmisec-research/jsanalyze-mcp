"""Static client-storage extractor (deterministic, stdlib-only).

Scans each beautified ``item.saved_path`` for client-side storage **writes/reads**
— ``localStorage`` / ``sessionStorage`` item calls and ``document.cookie`` name
assignments — so the model can triage what the app persists on the client
(session tokens, room ids, feature flags) without re-reading a 30k-line bundle.

This is a line-wise regex pass (one record per distinct ``(type, key, op, file)``),
NOT taint analysis: a hit means the literal key appears in a storage call site, it
does not prove the value is attacker-reachable. Every record is tagged with
``party`` via :func:`jsanalyze.party.party_of` so vendor/runtime noise can be
filtered out of the leads queue.

Contract: ``scan_storage(items, cfg=None) -> list[dict]``. Never raises — returns
whatever it collected (``[]`` on total failure). A record is::

    {"type": "localStorage|sessionStorage|cookie",
     "key":  "<name>",
     "op":   "set|get|remove",
     "file": "<basename of saved_path>",
     "line": <int, 1-based>,
     "party": "first|vendor|third",
     "evidence": "<trimmed source line, ~120 chars>"}

Only literal keys are captured. ``localStorage.setItem(e, t)`` (variable key) and
``document.cookie = name + "=" ...`` (dynamic cookie name) are intentionally
skipped — there is no literal to report.
"""

from __future__ import annotations

import os
import re

from jsanalyze.party import party_of

__all__ = ["scan_storage"]

# localStorage/sessionStorage .setItem/.getItem/.removeItem('KEY' ...)
#   - optional leading ``window.``
#   - single OR double quoted key; key capture stops at the matching quote only
#     (so a key containing the other quote char is not truncated).
_WEBSTORE_RE = re.compile(
    r'''(?:window\s*\.\s*)?'''
    r'''(?P<store>localStorage|sessionStorage)\s*\.\s*'''
    r'''(?P<method>setItem|getItem|removeItem)\s*\(\s*'''
    r'''(?P<q>['"])(?P<key>(?:(?!(?P=q)).)*)(?P=q)'''
)

# document.cookie = "KEY=..."  /  .cookie = `KEY=...`  /  foo.cookie="KEY=..."
#   A literal assignment to a ``.cookie`` property whose string value starts with
#   ``name=``. Requires the ``=`` after the name so a cookie *read* / comparison
#   (``document.cookie == "x"``) or an empty clear (``.cookie = ""``) is not matched.
_COOKIE_RE = re.compile(
    r'''\.cookie\s*=\s*'''
    r'''(?P<q>['"`])\s*(?P<key>[^=;,'"`\s]+)\s*='''
)

_OP = {"setItem": "set", "getItem": "get", "removeItem": "remove"}


def _add(out, seen, type_, key, op, file_, line, party, src):
    """Append one record, deduped by (type, key, op, file) — first line wins."""
    if not key:
        return
    dk = (type_, key, op, file_)
    if dk in seen:
        return
    seen.add(dk)
    out.append({
        "type": type_,
        "key": key,
        "op": op,
        "file": file_,
        "line": line,
        "party": party,
        "evidence": (src or "").strip()[:120],
    })


def _scan_item(item, scope_hosts, seen, out):
    saved_path = getattr(item, "saved_path", None)
    if not saved_path or not os.path.isfile(saved_path):
        return
    url = getattr(item, "url", "") or ""
    base = os.path.basename(saved_path)
    party = party_of(base, url, scope_hosts)

    with open(saved_path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            for m in _WEBSTORE_RE.finditer(line):
                _add(out, seen,
                     m.group("store"),                 # localStorage|sessionStorage
                     m.group("key"),
                     _OP.get(m.group("method"), "get"),
                     base, lineno, party, line)
            for m in _COOKIE_RE.finditer(line):
                _add(out, seen, "cookie", m.group("key"), "set",
                     base, lineno, party, line)


def scan_storage(items, cfg=None) -> list[dict]:
    """Return a deduped list of client-storage write/read records for ``items``.

    ``cfg`` is optional; if it carries a ``scope_hosts`` allow-list it is forwarded
    to :func:`party_of` so out-of-scope origins are tagged ``third``. Never raises.
    """
    out: list[dict] = []
    try:
        scope_hosts = cfg.get("scope_hosts") if isinstance(cfg, dict) else None
        seen: set = set()
        for item in (items or []):
            try:
                _scan_item(item, scope_hosts, seen, out)
            except Exception:
                continue  # one unreadable file must not sink the rest
    except Exception:
        return out
    return out

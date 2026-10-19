"""Mine comments & path-ish strings from recovered sources (critique point 5).

When a ``.map`` yields ``sourcesContent``, the ORIGINAL source carries things the
minified bundle does not: developer comments, ``mock``/``dummyData`` fixture paths,
staging/internal hostnames, and the occasional credential left in a comment. jsluice
re-scans the recovered ``sources/`` for urls/secrets, but it ignores COMMENTS and
non-URL path strings — which is exactly the archaeology that pays here.

``mine_comments(items)`` scans each item's text and returns records::

    {"category": "credential|internal-host|mock-path|note",
     "text": "<trimmed>", "file": "<basename>", "line": <int>, "party": "..."}

Only ``credential`` and ``internal-host`` are high-signal enough to become leads
(the engine decides); ``note`` / ``mock-path`` stay in the artifact for the analyst.
Pure, stdlib-only, never raises.
"""

from __future__ import annotations

import os
import re

from jsanalyze.party import party_of

__all__ = ["mine_comments"]

_LINE_COMMENT_RE = re.compile(r"//[^\n]{0,400}")
_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
_STRING_RE = re.compile(r"""(['"`])((?:\\.|(?!\1).)*)\1""")

_NOTE_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG|DEBUG|DEPRECATED|WORKAROUND|INSECURE|"
                      r"do not ship|remove before|temporary)\b", re.I)
_CRED_RE = re.compile(r"\b(password|passwd|secret|api[_\-]?key|bearer|token|credential|"
                      r"apikey|auth)\b\s*[:=]?\s*['\"]?[\w\-./+=]{6,}", re.I)
_INTERNAL_HOST_RE = re.compile(
    r"\b(?:https?://)?((?:staging|stage|dev|qa|uat|test|internal|intranet|corp|preprod|"
    r"sandbox|local|admin)[\w.\-]*\.[a-z]{2,}|[\w.\-]+\.(?:internal|local|corp|intranet|test))\b",
    re.I)
_MOCK_PATH_RE = re.compile(r"\b[\w./\-]*(?:mock|dummy|fixture|sample|seed|stub|fake)[\w./\-]*"
                           r"(?:data|s)?[\w./\-]*\.(?:json|js|ts|yaml|yml)\b", re.I)

_SECRETY = re.compile(r"(password|secret|api[_\-]?key|bearer|token|credential|apikey)", re.I)


def _lineno(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def mine_comments(items) -> list:
    out = []
    seen = set()
    for item in items or []:
        sp = getattr(item, "saved_path", None)
        if not sp:
            continue
        try:
            with open(sp, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        base = os.path.basename(sp)
        party = party_of(base, getattr(item, "url", "") or "", scope_hosts=None)

        def add(cat, snippet, pos):
            snippet = " ".join((snippet or "").split())[:200]
            key = (cat, base, snippet[:80])
            if not snippet or key in seen:
                return
            seen.add(key)
            out.append({"category": cat, "text": snippet, "file": base,
                        "line": _lineno(text, pos), "party": party})

        # comments: notes + credential-in-comment
        for rx in (_LINE_COMMENT_RE, _BLOCK_COMMENT_RE):
            for m in rx.finditer(text):
                c = m.group(0)
                if _CRED_RE.search(c) and _SECRETY.search(c):
                    add("credential", c, m.start())
                elif _NOTE_RE.search(c):
                    add("note", c, m.start())
                ih = _INTERNAL_HOST_RE.search(c)
                if ih:
                    add("internal-host", ih.group(0), m.start() + ih.start())

        # string literals: internal hosts + mock/dummy data paths
        for m in _STRING_RE.finditer(text):
            s = m.group(2)
            if not s or len(s) > 300:
                continue
            ih = _INTERNAL_HOST_RE.search(s)
            if ih:
                add("internal-host", ih.group(0), m.start())
            elif _MOCK_PATH_RE.search(s):
                add("mock-path", s, m.start())
    return out

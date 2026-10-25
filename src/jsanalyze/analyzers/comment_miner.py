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

_NOTE_RE = re.compile(r"\b(TODO|FIXME|HACK|XXX|BUG|DEBUG|DEPRECATED|WORKAROUND|INSECURE|"
                      r"do not ship|remove before|temporary)\b", re.I)
# a credential MUST be assigned/keyed (`:` or `=`) — `password resetFlow` is prose, not a
# secret (round 5 pt 3); the `[:=]` is now mandatory.
_CRED_RE = re.compile(r"\b(password|passwd|secret|api[_\-]?key|bearer|token|credential|"
                      r"apikey|auth)\b\s*[:=]\s*['\"]?[\w\-./+=]{6,}", re.I)
# an internal/staging host — the keyword must be a COMPLETE subdomain label (followed by a
# delimiter or digit), so `device.company.com` / `testing.example.com` no longer match (pt 4).
_INTERNAL_HOST_RE = re.compile(
    r"\b(?:https?://)?((?:staging|stage|dev|qa|uat|test|internal|intranet|corp|preprod|"
    r"sandbox|local|admin)(?=[.\-\d])[\w.\-]*\.[a-z]{2,}"
    r"|[\w.\-]+\.(?:internal|local|corp|intranet|test)\b)",
    re.I)
# only STRONG test-data markers — `sample`/`seed`/`stub`/`fake` are ordinary filenames
# (`sample.js`, `seed.ts`, `stub.js`) and minted a mock-path lead for every one (round 6 pt 2);
# keep `mock`/`dummy`/`fixture` (covers `dummyData`, `mocks`, `fixtures`).
_MOCK_PATH_RE = re.compile(r"\b[\w./\-]*(?:mock|dummy|fixture)[\w./\-]*"
                           r"(?:data|s)?[\w./\-]*\.(?:json|js|ts|yaml|yml)\b", re.I)

_SECRETY = re.compile(r"(password|secret|api[_\-]?key|bearer|token|credential|apikey)", re.I)


def _lineno(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _scan(text: str):
    """Split JS into COMMENT and STRING spans with a tiny state machine, so `//` inside
    `https://` is not a comment and `/* */` does not leap across a string (round 5 pt 2).
    Returns (comments:[(pos,text)], strings:[(pos,value)])."""
    comments, strings = [], []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c in "\"'`":
            q, j = c, i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == q:
                    j += 1
                    break
                if q != "`" and text[j] == "\n":      # unterminated '/" — stop at EOL
                    break
                j += 1
            strings.append((i, text[i + 1:max(i + 1, j - 1)]))
            i = j
            continue
        if c == "/" and i + 1 < n:
            if text[i + 1] == "/":
                j = text.find("\n", i)
                j = n if j == -1 else j
                comments.append((i, text[i:j]))
                i = j
                continue
            if text[i + 1] == "*":
                j = text.find("*/", i + 2)
                j = n if j == -1 else j + 2
                comments.append((i, text[i:j]))
                i = j
                continue
        i += 1
    return comments, strings


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

        comments, strings = _scan(text)
        # comments: notes + credential-in-comment + internal host
        for pos, c in comments:
            if _CRED_RE.search(c) and _SECRETY.search(c):
                add("credential", c, pos)
            elif _NOTE_RE.search(c):
                add("note", c, pos)
            ih = _INTERNAL_HOST_RE.search(c)
            if ih:
                add("internal-host", ih.group(0), pos + ih.start())
        # string literals: internal hosts + mock/dummy data paths
        for pos, s in strings:
            if not s or len(s) > 300:
                continue
            ih = _INTERNAL_HOST_RE.search(s)
            if ih:
                add("internal-host", ih.group(0), pos)
            elif _MOCK_PATH_RE.search(s):
                add("mock-path", s, pos)
    return out

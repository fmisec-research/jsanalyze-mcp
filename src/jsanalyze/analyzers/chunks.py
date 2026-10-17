"""Analyzer: webpack (or similar) code-split chunk mapping (deterministic, best-effort).

Static, stdlib-only. Reconstructs the chunk-id -> filename map that a webpack runtime
carries and flags which chunks are actually present in the provided JS set versus only
*referenced* ("missing" — the operator must capture them; this NEVER fetches). Never
raises.

One record per chunk id::

    {"id": "<chunk id>", "file": "<reconstructed filename or ''>",
     "present": true|false, "kind": "entry|async|referenced"}

``present`` is true when a reconstructed filename (or the bare numeric/name id) matches
a file we already have. The chunk map is read from a runtime/main chunk via either::

    __webpack_require__.u = e => "static/js/" + e + "." + {ID:"HASH", ...}[e] + ".chunk.js"
    __webpack_require__.u = function(e){return"static/js/"+e+"."+{ID:"HASH"}[e]+".chunk.js"}

or a bare ``{ID:"HASH", ...}`` literal sitting next to a chunk-filename template string.
Dynamic-import references (``__webpack_require__.e(ID)`` / ``x.e(ID)``) add chunk ids too.
If no map is found, ``[]`` is returned (most bundles are not the runtime chunk) — that is
an acceptable, expected result.
"""

from __future__ import annotations

import os
import re

__all__ = ["map_chunks"]


_PARSER_SUFFIX_RE = re.compile(r"__[0-9a-f]{6,}\.js$", re.IGNORECASE)
_JS_EXT_RE = re.compile(r"\.(?:js|mjs|cjs)$", re.IGNORECASE)
_HASHY_RE = re.compile(r"^[0-9a-z]{4,}$", re.IGNORECASE)

# any sign the file is a webpack-ish bundle worth scanning
_WEBPACK_SIGNAL_RE = re.compile(
    r"__webpack_require__|webpackJsonp|webpackChunk|\.chunk\.js|static/js/|installedChunks"
)

# `.u = e => ...`  |  `.u = (e) => ...`  |  `.u = function(e){ ...`
_U_ASSIGN_RE = re.compile(
    r"\.u\s*=\s*(?:function\s*\([^)]*\)\s*\{|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"
)

_STRING_RE = re.compile(r"""(["'])((?:\\.|(?!\1).)*)\1""")

# one  ID:"HASH"  entry — numeric / quoted / bare identifier key, string hash value
_MAP_ENTRY_RE = re.compile(
    r"""(?:(\d+)|["']([A-Za-z0-9_\-]+)["']|([A-Za-z_$][\w$]*))\s*:\s*["']([A-Za-z0-9_\-]+)["']"""
)

# dynamic import:  x.e(7)  |  x.e("id")
_E_REF_RE = re.compile(r"""\.e\s*\(\s*(?:(\d+)|["']([A-Za-z0-9_\-]+)["'])\s*\)""")

# entry chunks:  installedChunks = { 1:0, 2:0 }   (value 0 == already loaded)
_INSTALLED_RE = re.compile(r"installedChunks\s*=\s*\{([^{}]{0,4000})\}")
_INSTALLED_ENTRY_RE = re.compile(r"""(?:(\d+)|["']([A-Za-z0-9_\-]+)["'])\s*:\s*0\b""")

# a chunk-filename template literal (gates the bare-object fallback)
_CHUNK_TEMPLATE_RE = re.compile(r"""["'][^"']*(?:static/js/|\.chunk\.js)[^"']*["']""")


def map_chunks(items, cfg=None) -> list:
    """Map code-split chunks to the present JS set. Never raises; ``[]`` if no map."""
    out: list = []
    try:
        names, ids = _present_index(items)

        map_entries: dict = {}   # chunk id -> hash
        prefix = ""
        suffix = ""
        entry_ids: set = set()
        ref_ids: set = set()
        found_map = False

        for item in items or []:
            try:
                text = _read_text(item)
            except Exception:
                text = ""
            if not text or not _WEBPACK_SIGNAL_RE.search(text):
                continue

            pfx, sfx, entries = _extract_u_map(text)
            if not entries:
                pfx, sfx, entries = _extract_fallback_map(text)
            if entries:
                found_map = True
                if pfx and not prefix:
                    prefix = pfx
                if sfx and not suffix:
                    suffix = sfx
                for k, v in entries.items():
                    map_entries.setdefault(k, v)

            for em in _E_REF_RE.finditer(text):
                rid = em.group(1) or em.group(2)
                if rid:
                    ref_ids.add(rid)

            for im in _INSTALLED_RE.finditer(text):
                for e2 in _INSTALLED_ENTRY_RE.finditer(im.group(1)):
                    eid = e2.group(1) or e2.group(2)
                    if eid:
                        entry_ids.add(eid)

        if not found_map or not map_entries:
            # No chunk map: referenced ids alone can't be told from noise -> [] (spec).
            return []

        seen: set = set()
        # mapped chunks -> async (entry if flagged by installedChunks)
        for cid, chash in map_entries.items():
            fname = _reconstruct(prefix, suffix, cid, chash)
            present = _is_present(cid, fname, names, ids)
            kind = "entry" if cid in entry_ids else "async"
            _add(out, seen, cid, fname, present, kind)
        # referenced-only chunks (dynamic import to an id not in the map) -> referenced
        for rid in ref_ids:
            if rid in map_entries:
                continue
            kind = "entry" if rid in entry_ids else "referenced"
            _add(out, seen, rid, "", _is_present(rid, "", names, ids), kind)
        # entry chunks neither mapped nor referenced
        for eid in entry_ids:
            if eid in map_entries or eid in ref_ids:
                continue
            _add(out, seen, eid, "", _is_present(eid, "", names, ids), "entry")
        return out
    except Exception:
        return out if isinstance(out, list) else []


# --- present set --------------------------------------------------------------
def _present_index(items):
    """Build ``(names, ids)`` from the provided items.

    ``names`` = normalized basenames/stems (lowercased); ``ids`` = id-ish stems
    (``4``, ``vendors-bundle``, ``main``) after stripping the parser's ``__<sha1>.js``
    suffix and the ``.chunk.<hash>`` middle.
    """
    names: set = set()
    ids: set = set()
    for item in items or []:
        base = _item_basename(item)
        if not base:
            continue
        base = _PARSER_SUFFIX_RE.sub("", base).lower()
        names.add(base)
        stem = _JS_EXT_RE.sub("", base)
        names.add(stem)
        if ".chunk." in stem:
            left = stem.partition(".chunk.")[0]
            if left:
                ids.add(left)
        parts = stem.split(".")
        if parts and parts[0]:
            ids.add(parts[0])
    return names, ids


def _is_present(cid, filename, names, ids) -> bool:
    if str(cid).lower() in ids:
        return True
    if filename:
        fb = os.path.basename(filename).lower()
        if fb in names:
            return True
        fstem = _JS_EXT_RE.sub("", fb)
        if fstem in names:
            return True
        lead = fstem.split(".")[0]
        if lead and lead in ids:
            return True
    return False


# --- map extraction -----------------------------------------------------------
def _extract_u_map(text: str):
    """Authoritative: the ``{id:"hash"}`` map anchored to a ``.u = ...`` assignment."""
    for um in _U_ASSIGN_RE.finditer(text):
        obj, _oi, oj = _first_object(text, um.end(), limit=2000)
        if not obj:
            continue
        entries = _parse_map(obj)
        if not entries:
            continue
        win = text[um.start(): (oj + 60 if oj > 0 else um.end() + 200)]
        prefix, suffix = _template_affixes(win)
        return prefix, suffix, entries
    return "", "", {}


def _extract_fallback_map(text: str):
    """Fallback: a bare ``{id:"hash"}`` literal near a chunk-filename template string.

    Only fires when a ``static/js/`` or ``.chunk.js`` template literal is present, and
    only accepts an object that *looks like* a chunk map (numeric ids -> alnum hashes),
    so CSS-module / config objects are not mistaken for one.
    """
    tm = _CHUNK_TEMPLATE_RE.search(text)
    if not tm:
        return "", "", {}
    lo = max(0, tm.start() - 1800)
    hi = min(len(text), tm.end() + 1800)
    window = text[lo:hi]
    pos = 0
    scanned = 0
    while scanned < 300:
        bi = window.find("{", pos)
        if bi == -1:
            break
        obj, _oi, oj = _first_object(window, bi, limit=1)
        if obj:
            entries = _parse_map(obj)
            if _looks_like_chunk_map(entries):
                prefix, suffix = _template_affixes(window)
                return prefix, suffix, entries
            pos = oj if oj > bi else bi + 1
        else:
            pos = bi + 1
        scanned += 1
    return "", "", {}


def _parse_map(obj_text: str) -> dict:
    entries: dict = {}
    for m in _MAP_ENTRY_RE.finditer(obj_text):
        key = m.group(1) or m.group(2) or m.group(3)
        val = m.group(4)
        if key is None or val is None:
            continue
        entries[str(key)] = val
    return entries


def _looks_like_chunk_map(entries: dict) -> bool:
    if not entries:
        return False
    numeric = sum(1 for k in entries if str(k).isdigit())
    hashy = sum(1 for v in entries.values() if _HASHY_RE.match(str(v)))
    return numeric >= 1 and hashy >= max(1, int(0.6 * len(entries)))


def _template_affixes(window: str):
    """Pick a filename prefix (first string with ``/``) and suffix (last ``.xxx``/chunk
    string) from the string literals in a ``.u`` RHS window."""
    strings = [m.group(2) for m in _STRING_RE.finditer(window)]
    prefix = ""
    for s in strings:
        if "/" in s:
            prefix = s
            break
    suffix = ""
    for s in reversed(strings):
        sl = s.lower()
        if (s.startswith(".") and s != ".") or "chunk" in sl or sl.endswith(".js"):
            suffix = s
            break
    return prefix, suffix


def _reconstruct(prefix: str, suffix: str, cid, chash) -> str:
    if not prefix and not suffix:
        return ""
    return "{}{}.{}{}".format(prefix, cid, chash, suffix)


def _first_object(text: str, start: int, limit: int = 0):
    """Return ``(obj_text, open_idx, end_idx)`` for the first balanced ``{...}`` at/after
    ``start`` (within ``limit`` chars of ``start`` if given), else ``(None, -1, -1)``.

    Brace counting is naive (does not track strings) — fine here: chunk hashes never
    contain braces and the map object is tiny.
    """
    if limit:
        i = text.find("{", start, start + limit)
    else:
        i = text.find("{", start)
    if i == -1:
        return None, -1, -1
    depth = 0
    j = i
    end_cap = min(len(text), i + 20000)
    while j < end_cap:
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1], i, j + 1
        j += 1
    return None, -1, -1


def _add(out, seen, cid, fname, present, kind) -> None:
    key = str(cid)
    if key in seen:
        return
    seen.add(key)
    out.append({"id": key, "file": fname or "", "present": bool(present), "kind": kind})


# --- text ---------------------------------------------------------------------
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


def _item_basename(item) -> str:
    sp = getattr(item, "saved_path", None)
    if sp:
        return os.path.basename(sp)
    url = getattr(item, "url", "") or ""
    path = url.split("?", 1)[0].split("#", 1)[0]
    return path.rsplit("/", 1)[-1] or ""

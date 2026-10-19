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
from urllib.parse import urljoin, urlsplit

__all__ = ["map_chunks"]


_PARSER_SUFFIX_RE = re.compile(r"__[0-9a-f]{6,}\.js$", re.IGNORECASE)
_JS_EXT_RE = re.compile(r"\.(?:js|mjs|cjs)$", re.IGNORECASE)
_HASHY_RE = re.compile(r"^[0-9a-z]{4,}$", re.IGNORECASE)

# any sign the file is a webpack-ish bundle worth scanning
_WEBPACK_SIGNAL_RE = re.compile(
    r"__webpack_require__|webpackJsonp|webpackChunk|\.chunk\.js|static/js/|installedChunks|"
    r"jsonpScriptSrc|__vite__mapDeps"
)

# publicPath:  __webpack_require__.p = "https://cdn/app/"  |  n.p="/static/js/"
_PUBLIC_PATH_RE = re.compile(r"""(?:__webpack_require__|[A-Za-z_$][\w$]*)\.p\s*=\s*["']([^"']*)["']""")

# Vite:  d=(m.f||(m.f=["assets/a.js","assets/b.js"]))   (the dep-file manifest array)
_VITE_DEPS_RE = re.compile(r"""__vite__mapDeps[\s\S]{0,80}?\[([^\]]{0,8000})\]""")
_VITE_FILE_RE = re.compile(r"""["']([^"']+?\.(?:js|mjs|css))["']""")

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
    """Map code-split chunks to the present JS set. Never raises; ``[]`` if no map.

    Handles webpack 5 (``.u = e => …{id:hash}``), CRA/webpack-4 (``static/js/``/
    ``.chunk.js`` template), bare webpack-4 jsonp (``jsonpScriptSrc`` / ``webpackJsonp``
    with a plain ``.js`` suffix and a custom ``publicPath``), and Vite (``__vite__mapDeps``
    file array). Each record carries a reconstructed ``url`` (publicPath + origin) so a
    ``present:false`` chunk is an actionable "operator must capture this" item — this
    NEVER fetches (critique point 4)."""
    out: list = []
    try:
        names, ids = _present_index(items)

        map_entries: dict = {}   # chunk id -> hash
        prefix = ""
        suffix = ""
        public_path = ""
        base_url = ""
        entry_ids: set = set()
        ref_ids: set = set()
        found_map = False
        vite_files: list = []

        for item in items or []:
            try:
                text = _read_text(item)
            except Exception:
                text = ""
            if not text or not _WEBPACK_SIGNAL_RE.search(text):
                continue
            origin = getattr(item, "url", "") or ""

            # Vite: the dep manifest lists real filenames directly.
            for f in _extract_vite_files(text):
                if f not in vite_files:
                    vite_files.append(f)
                    if not base_url and origin:
                        base_url = origin

            pfx, sfx, entries = _extract_u_map(text)
            if not entries:
                pfx, sfx, entries = _extract_fallback_map(text)
            if not entries:
                pfx, sfx, entries = _extract_jsonp_map(text)
            if entries:
                found_map = True
                if pfx and not prefix:
                    prefix = pfx
                if sfx and not suffix:
                    suffix = sfx
                for k, v in entries.items():
                    map_entries.setdefault(k, v)
                if not base_url and origin:
                    base_url = origin
            if not public_path:
                pm = _PUBLIC_PATH_RE.search(text)
                if pm:
                    public_path = pm.group(1)

            for em in _E_REF_RE.finditer(text):
                rid = em.group(1) or em.group(2)
                if rid:
                    ref_ids.add(rid)

            for im in _INSTALLED_RE.finditer(text):
                for e2 in _INSTALLED_ENTRY_RE.finditer(im.group(1)):
                    eid = e2.group(1) or e2.group(2)
                    if eid:
                        entry_ids.add(eid)

        seen: set = set()
        # Vite chunk files (filenames are authoritative; reconstruct the URL only)
        for f in vite_files:
            fid = os.path.basename(f)
            present = _is_present(fid, f, names, ids)
            _add(out, seen, fid, f, present, "vite", _reconstruct_url(public_path or "/", f, base_url))

        if found_map and map_entries:
            for cid, chash in map_entries.items():
                fname = _reconstruct(prefix, suffix, cid, chash)
                present = _is_present(cid, fname, names, ids)
                kind = "entry" if cid in entry_ids else "async"
                _add(out, seen, cid, fname, present, kind,
                     _reconstruct_url(public_path, fname, base_url))
            for rid in ref_ids:
                if rid in map_entries:
                    continue
                kind = "entry" if rid in entry_ids else "referenced"
                _add(out, seen, rid, "", _is_present(rid, "", names, ids), kind)
            for eid in entry_ids:
                if eid in map_entries or eid in ref_ids:
                    continue
                _add(out, seen, eid, "", _is_present(eid, "", names, ids), "entry")
        return out
    except Exception:
        return out if isinstance(out, list) else []


def _extract_vite_files(text: str) -> list:
    """Filenames from a Vite ``__vite__mapDeps`` dependency array."""
    m = _VITE_DEPS_RE.search(text)
    if not m:
        return []
    return [f for f in _VITE_FILE_RE.findall(m.group(1))]


def _extract_jsonp_map(text: str):
    """webpack-4 bare jsonp: a ``{id:"hash",...}`` map near ``jsonpScriptSrc`` /
    ``webpackJsonp`` even when there is no ``static/js/``/``.chunk.js`` template.

    Anchored on the jsonp signal to avoid matching unrelated objects; the filename
    template (prefix/suffix) is read from the strings around the src function, else
    defaults to a plain ``.js`` suffix."""
    anchor = re.search(r"jsonpScriptSrc|webpackJsonp|installedChunks", text)
    if not anchor:
        return "", "", {}
    lo = max(0, anchor.start() - 2500)
    hi = min(len(text), anchor.end() + 2500)
    window = text[lo:hi]
    pos, scanned = 0, 0
    while scanned < 400:
        bi = window.find("{", pos)
        if bi == -1:
            break
        obj, _oi, oj = _first_object(window, bi, limit=1)
        if obj:
            entries = _parse_map(obj)
            if _looks_like_chunk_map(entries) and len(entries) >= 2:
                prefix, suffix = _template_affixes(window)
                if not suffix:
                    suffix = ".js"          # bare webpack-4 default
                return prefix, suffix, entries
            pos = oj if oj > bi else bi + 1
        else:
            pos = bi + 1
        scanned += 1
    return "", "", {}


def _reconstruct_url(public_path: str, filename: str, base_url: str) -> str:
    """Best-effort absolute URL for a chunk: publicPath + filename, resolved against
    the origin of the runtime chunk. Returns '' when nothing can be reconstructed."""
    if not filename:
        return ""
    pp = public_path or ""
    # the filename may already carry the publicPath (our template scan bakes it into the
    # prefix); only apply publicPath to a genuinely RELATIVE filename to avoid doubling.
    if filename.startswith(("http://", "https://")):
        return filename
    origin = ""
    if base_url:
        parts = urlsplit(base_url)
        origin = f"{parts.scheme}://{parts.netloc}"
    if filename.startswith("//"):
        return ("https:" + filename) if not origin else urlsplit(base_url).scheme + ":" + filename
    if filename.startswith("/"):                 # already host-rooted: just add origin
        return origin + filename if origin else filename
    # relative filename -> prepend publicPath, then resolve against origin
    if pp.startswith(("http://", "https://")):
        return pp.rstrip("/") + "/" + filename.lstrip("/")
    rel = (pp.rstrip("/") + "/" + filename.lstrip("/")) if pp else filename.lstrip("/")
    if not origin:
        return rel if rel.startswith("/") else ""
    return origin + "/" + rel.lstrip("/")


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


def _add(out, seen, cid, fname, present, kind, url="") -> None:
    key = str(cid)
    if key in seen:
        return
    seen.add(key)
    rec = {"id": key, "file": fname or "", "present": bool(present), "kind": kind}
    if url:
        rec["url"] = url
    out.append(rec)


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

"""Request-shape recovery at a call site (critique point 3) — pure, stdlib-only.

jsluice reports ``bodyParams`` for a *direct* object body (``axios.put(u,{status})``)
but returns ``[]`` for the far more common ``fetch(u,{body: JSON.stringify({...})})``
(empirically verified). This module recovers the body field NAMES (keys only, never
values) from the source window at the line jsluice already gave us — so we augment a
fact jsluice produced, we do not run a second global extractor.

``request_shape(text, line)`` returns ``{"method": "<verb or ''>", "body_keys": [...]}``:

  * locates the request call on/after ``line`` (``fetch`` / ``axios[.verb]`` /
    ``$http`` / ``client.*`` / ``request(`` / ``.ajax(`` / ``xhr`` ...),
  * extracts its balanced ``( ... )`` argument list,
  * pulls ``method:`` from an options object (else infers from ``axios.post`` etc.),
  * resolves the body: a ``body:``/``data:`` value that is an object literal or a
    ``JSON.stringify({...})`` wrapper -> that object's TOP-LEVEL keys; or, for an
    axios-style ``verb(url, {..})`` with no wrapper, the second object's keys.

Best-effort and bounded (never walks more than a small window); a variable body
(``body: payload``) yields no keys, which is correct — there is nothing literal.
"""

from __future__ import annotations

import re

__all__ = ["request_shape", "object_keys"]

_REQ_NEAR_RE = re.compile(
    r"\b(?:fetch|axios|request|superagent|ky|got|\$http|\$\.ajax|xhr|XMLHttpRequest|"
    r"sendBeacon|useSWR|useQuery|useMutation|client|api|http)\b"
    r"(?:\s*\.\s*(?P<verb>get|post|put|patch|delete|head|options|request|ajax|fetch))?",
    re.IGNORECASE,
)
_VERB_WORDS = ("get", "post", "put", "patch", "delete", "head", "options")
_METHOD_KEY_RE = re.compile(r"""\bmethod\s*:\s*(['"])(?P<m>[a-zA-Z]+)\1""")
_BODY_KEY_RE = re.compile(r"\b(?:body|data)\s*:")
_STRINGIFY_RE = re.compile(r"JSON\s*\.\s*stringify\s*\(")
_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")


def _balanced(text: str, open_idx: int, open_ch="(", close_ch=")", cap=8000):
    """Return the substring inside the balanced bracket starting at ``open_idx``
    (which must be ``open_ch``), string-aware. ``(inner, end_idx)`` or ``("", -1)``."""
    n = min(len(text), open_idx + cap)
    depth = 0
    i = open_idx
    while i < n:
        c = text[i]
        if c in "\"'`":
            i = _skip_str(text, i, n)
            continue
        if c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i], i
        i += 1
    return "", -1


def _skip_str(text: str, i: int, n: int) -> int:
    q = text[i]
    i += 1
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == q:
            return i + 1
        i += 1
    return i


def object_keys(obj_src: str, cap: int = 24) -> list:
    """Top-level keys of the FIRST balanced ``{...}`` in ``obj_src`` (keys only).

    A proper depth-aware scan (not regex) so it handles both ``{"a-b": 1}`` quoted
    keys and ``{name, email}`` shorthand properties, and never descends into nested
    objects/arrays. Spread (``...x``) and computed keys are ignored.
    """
    start = obj_src.find("{")
    if start == -1:
        return []
    inner, end = _balanced(obj_src, start, "{", "}")
    if end == -1:
        return []
    keys: list = []
    n = len(inner)
    i = 0
    depth = 0                       # nesting within the object's VALUES
    expect_key = True               # True between a ',' and the next ':' (key position)
    token = None                    # candidate key (ident/string) in key position
    valid = True                    # False once this property proves non-plain (spread/computed)
    while i < n:
        c = inner[i]
        if c in "\"'`":
            j = _skip_str(inner, i, n)
            if depth == 0 and expect_key and token is None:
                token = inner[i + 1:j - 1] if j - 1 > i else ""
            i = j
            continue
        if c in "{[(":
            depth += 1
            i += 1
            continue
        if c in "}])":
            depth = max(0, depth - 1)
            i += 1
            continue
        if depth == 0:
            if c == ":" and expect_key:     # token confirmed as an explicit key
                if valid:
                    _push(keys, token, cap)
                expect_key, token = False, None
            elif c == ",":                  # property boundary
                if expect_key and valid:    # no ':' seen -> shorthand key
                    _push(keys, token, cap)
                expect_key, token, valid = True, None, True
            elif expect_key and (c.isalpha() or c in "_$"):
                m = _IDENT_RE.match(inner, i)
                if m:
                    if token is None:
                        token = m.group(0)
                    else:               # two idents, no ':' -> not a plain key (e.g. async fn)
                        valid = False
                    i = m.end()
                    continue
            elif expect_key and c == ".":   # spread ...x or computed access -> skip property
                valid = False
        i += 1
        if len(keys) >= cap:
            break
    if expect_key and valid:               # trailing shorthand key (no comma before '}')
        _push(keys, token, cap)
    return keys


def _push(keys: list, token, cap: int) -> None:
    if token and token not in keys and len(keys) < cap:
        # reject spread/rest and pure-numeric literal keys
        if token.startswith("...") or token.isdigit():
            return
        keys.append(token)


_BARE_IDENT_RE = re.compile(r"^[A-Za-z_$][\w$]*$")


def _body_keys_from_arg(arg: str, text: str = "") -> list:
    """Keys of a body/data value: a JSON.stringify({...}) wrapper, a bare object, or —
    when the value is a bare identifier — the object literal that variable is assigned in
    the same file (`const payload = { role, name }`; round 5 pt 16)."""
    sm = _STRINGIFY_RE.search(arg)
    if sm:
        inner, end = _balanced(arg, sm.end() - 1, "(", ")")
        if end != -1:
            keys = object_keys(inner)
            if keys:
                return keys
            arg = inner                          # JSON.stringify(payload) -> resolve payload
    keys = object_keys(arg)
    if keys:
        return keys
    if text:
        v = arg.strip().rstrip(",);").strip()
        if _BARE_IDENT_RE.match(v):
            dm = re.search(r"\b(?:const|let|var)?\s*" + re.escape(v) + r"\s*=\s*\{", text)
            if dm:
                inner, end = _balanced(text, dm.end() - 1, "{", "}")
                if end != -1:
                    return object_keys("{" + inner + "}")
    return keys


def request_shape(text: str, line: int, radius: int = 2) -> dict:
    """Recover ``{"method", "body_keys"}`` for the request call at/near ``line``."""
    empty = {"method": "", "body_keys": []}
    if not text or not line:
        return empty
    lines = text.splitlines()
    idx = max(0, int(line) - 1)
    # minified bundles put everything on one line; take the line plus a little slack
    lo = max(0, idx - radius)
    hi = min(len(lines), idx + radius + 1)
    window = "\n".join(lines[lo:hi])

    rm = _REQ_NEAR_RE.search(window)
    if not rm:
        return empty
    paren = window.find("(", rm.end() - 1)
    if paren == -1:
        return empty
    args_src, end = _balanced(window, paren, "(", ")")
    if end == -1:
        return empty

    method = (rm.group("verb") or "").upper()
    mm = _METHOD_KEY_RE.search(args_src)
    if mm:
        method = mm.group("m").upper()

    # split top-level args on commas (bracket/string aware)
    args = _split_args(args_src)
    body_keys: list = []
    # a body:/data: key anywhere in the options object(s)
    for a in args:
        if _BODY_KEY_RE.search(a):
            # isolate the value after body:/data:
            bm = _BODY_KEY_RE.search(a)
            body_keys = _body_keys_from_arg(a[bm.end():], text)
            if body_keys:
                break
    # axios-style verb(url, {..}) with no body: wrapper -> 2nd arg object is the body
    if not body_keys and method in ("POST", "PUT", "PATCH", "DELETE") and len(args) >= 2:
        second = args[1].strip()
        if second.startswith("{") and "body:" not in second and "data:" not in second \
                and "method:" not in second:
            body_keys = object_keys(second)
    return {"method": method, "body_keys": body_keys}


def _split_args(s: str) -> list:
    """Split a call's argument string on top-level commas (bracket/string aware)."""
    out, buf, depth, i, n = [], [], 0, 0, len(s)
    while i < n:
        c = s[i]
        if c in "\"'`":
            j = _skip_str(s, i, n)
            buf.append(s[i:j])
            i = j
            continue
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
        if c == "," and depth == 0:
            out.append("".join(buf))
            buf = []
            i += 1
            continue
        buf.append(c)
        i += 1
    if buf:
        out.append("".join(buf))
    return out

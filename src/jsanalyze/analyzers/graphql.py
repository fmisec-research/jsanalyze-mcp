"""Deterministic GraphQL *operation* extractor (static, stdlib-only).

The critique this answers: a bundle "has GraphQL" leads should be one row per
OPERATION (query / mutation / subscription with its name, variables and
top-level fields), not merely "a path containing /graphql". So we read each
decoded ``item.saved_path`` and pull every operation we can see in the text,
whether it lives in a ``gql`...` `` / ``graphql`...` `` tagged template literal
or in a plain string (``"query GetUser(...){...}"``).

This is pure text/AST-lite parsing (no jsluice, no network); it never raises and
returns ``[]`` when there is no GraphQL at all. Each record::

    {"operation": "query|mutation|subscription",
     "operationName": "<name or ''>",
     "variables": ["$id", ...],
     "fields": ["user", "orders"],          # TOP-LEVEL selection set, best-effort, capped
     "file": "<basename>",
     "line": <int>,
     "party": "first|vendor|third"}

Deduped by ``(operation, operationName, file)``.
"""

from __future__ import annotations

import os
import re

from jsanalyze.party import party_of

__all__ = ["extract_graphql"]

# Keyword + optional name + optional (...variables...) + opening selection brace.
# The variable group forbids '{' so it cannot swallow the selection set; this is
# best-effort (a variable default value containing '{' will make that one op be
# skipped, which is acceptable for a static heuristic).
_OP_RE = re.compile(
    r"\b(?P<kw>query|mutation|subscription)\b"
    r"[ \t\r\n]*(?P<name>[A-Za-z_]\w*)?"
    r"[ \t\r\n]*(?P<vars>\([^{]*?\))?"
    r"[ \t\r\n]*\{"
)

# A `gql` / `graphql` tagged template literal opener (the backtick is included).
_GQL_TAG_RE = re.compile(r"(?<![\w$])(?:gql|graphql)\s*`", re.IGNORECASE)

_VAR_RE = re.compile(r"\$[A-Za-z_]\w*")

_FIELD_CAP = 10
_MAX_SELECTION_SCAN = 20000   # don't walk more than this many chars of one op body


def _skip_string(text: str, i: int) -> int:
    """Index just past the string literal that starts at ``text[i]`` (a quote)."""
    q = text[i]
    n = len(text)
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


def _skip_parens(text: str, i: int) -> int:
    """Index just past the balanced ``(...)`` group that starts at ``text[i]``."""
    n = len(text)
    depth = 0
    while i < n:
        c = text[i]
        if c in "\"'":
            i = _skip_string(text, i)
            continue
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def _find_closing_backtick(text: str, start: int) -> int:
    """Index of the backtick closing a template literal whose body starts at ``start``."""
    n = len(text)
    i = start
    while i < n:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if c == "`":
            return i
        i += 1
    return -1


def _gql_spans(text: str) -> list:
    """(body_start, body_end) spans of every gql/graphql tagged template literal."""
    spans = []
    for m in _GQL_TAG_RE.finditer(text):
        body_start = m.end()            # just past the opening backtick
        close = _find_closing_backtick(text, body_start)
        if close == -1:
            continue
        spans.append((body_start, close))
    return spans


def _in_spans(pos: int, spans: list) -> bool:
    return any(a <= pos < b for a, b in spans)


def _top_level_fields(text: str, open_idx: int, cap: int = _FIELD_CAP) -> list:
    """Field names at the first selection-set level (inside the operation's braces).

    Walks from the opening ``{``: identifiers seen at brace-depth 1 (outside any
    ``(...)`` argument group, directive or nested selection) are field names. An
    ``alias: field`` is recorded as ``field`` (the alias label is dropped).
    Best-effort — inline fragments / spreads may contribute a stray name.
    """
    n = len(text)
    stop = min(n, open_idx + _MAX_SELECTION_SCAN)
    i = open_idx + 1
    depth = 1
    fields: list = []
    while i < stop and depth > 0:
        c = text[i]
        if c in "\"'":
            i = _skip_string(text, i)
            continue
        if c == "{":
            depth += 1
            i += 1
            continue
        if c == "}":
            depth -= 1
            i += 1
            continue
        if depth != 1:
            i += 1
            continue
        if c == "(":
            i = _skip_parens(text, i)
            continue
        if c == "@":                         # directive name (and its args next loop)
            i += 1
            while i < stop and (text[i].isalnum() or text[i] == "_"):
                i += 1
            continue
        if c == "#":                         # GraphQL line comment
            while i < stop and text[i] != "\n":
                i += 1
            continue
        if c.isalpha() or c == "_":
            start = i
            while i < stop and (text[i].isalnum() or text[i] == "_"):
                i += 1
            ident = text[start:i]
            k = i
            while k < stop and text[k].isspace():
                k += 1
            if k < stop and text[k] == ":":   # alias label -> skip it and the ':'
                i = k + 1
                continue
            if ident != "on" and ident not in fields:
                fields.append(ident)
                if len(fields) >= cap:
                    break
            continue
        i += 1
    return fields


def extract_graphql(items, cfg=None) -> "list[dict]":
    """One record per GraphQL operation found across every ``item.saved_path``."""
    try:
        cfg = cfg or {}
        scope_hosts = cfg.get("scope_hosts")
        out: list = []
        seen: set = set()

        for item in items or []:
            saved_path = getattr(item, "saved_path", None)
            if not saved_path:
                continue
            try:
                with open(saved_path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if not text:
                continue

            basename = os.path.basename(saved_path)
            origin_url = getattr(item, "url", None) or ""
            party = party_of(basename, origin_url, scope_hosts)

            spans = _gql_spans(text)

            for m in _OP_RE.finditer(text):
                name = m.group("name") or ""
                # A named operation ("query Foo {") is a strong GraphQL signal on
                # its own; an anonymous one ("query {") is only trusted inside a
                # gql tag or right after a string quote, to avoid JS false hits.
                if not name:
                    prev = text[m.start() - 1] if m.start() > 0 else ""
                    if not (_in_spans(m.start(), spans) or prev in "\"'`"):
                        continue

                operation = m.group("kw")
                key = (operation, name, basename)
                if key in seen:
                    continue
                seen.add(key)

                variables: list = []
                for v in _VAR_RE.findall(m.group("vars") or ""):
                    if v not in variables:
                        variables.append(v)

                brace_idx = m.end() - 1       # the '{' the regex consumed
                fields = _top_level_fields(text, brace_idx)

                line = text.count("\n", 0, m.start()) + 1

                out.append({
                    "operation": operation,
                    "operationName": name,
                    "variables": variables,
                    "fields": fields,
                    "file": basename,
                    "line": line,
                    "party": party,
                })

        return out
    except Exception:
        # Static extractors never raise into the pipeline.
        return []

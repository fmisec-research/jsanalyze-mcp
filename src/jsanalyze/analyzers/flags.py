"""Deterministic feature-flag detector (jsluice tree-sitter queries, stdlib-only).

Why queries, not regex: a bare ``enable`` / ``beta`` grep hits CSS class names
and comments. Instead we ask jsluice (tree-sitter) three structural questions on
each first-party / vendor ``item.saved_path``:

  Q1  SDK calls — ``x.variation("flag")``, ``statsig.checkGate("gate")`` ...  (sdk)
  Q2  role / FEATURE_ identifiers — ``isAdmin``, ``FEATURE_BILLING`` ...   (ui-gate|local)
  Q3  flag-ish string literals — ``"launchdarkly"``, ``"feature_flag_x"``   (local|provider)

jsluice ``query`` emits one JSON object per matched pattern, naming the file and
the captured node(s) but NOT the line. We re-scan the file for the matched key to
recover a line number and a short evidence snippet (``None`` line if not found).

Each record::

    {"key": "<flag key or identifier>",
     "provider": "launchdarkly|statsig|unleash|openfeature|growthbook|split|"
                 "flagsmith|local|ui-gate|unknown",
     "kind": "sdk|local|ui-gate",
     "file": "<basename>",
     "line": <int or None>,
     "party": "first|vendor|third",
     "evidence": "<matched text>"}

Deduped by ``(key, file)`` (first match wins; Q1 SDK classification therefore
beats a weaker Q3 string match for the same key). Never raises; returns ``[]``
when jsluice is missing or no flags are found.
"""

from __future__ import annotations

import json
import os
import re

from jsanalyze.party import party_of
from jsanalyze.analyzers.jsluice_wrapper import resolve_jsluice
from jsanalyze.enrichers import tools

__all__ = ["scan_flags", "_classify"]

# --- the three project-doctrine queries --------------------------------------
Q1 = (
    "((call_expression function: (member_expression property: "
    "(property_identifier) @method) arguments: (arguments (string) @key)) "
    '(#match? @method "^(variation|boolVariation|checkGate|getConfig|isEnabled|'
    'getBooleanValue|isOn)$"))'
)
Q2 = (
    "((property_identifier) @p "
    '(#match? @p "^(isAdmin|isStaff|isSuperUser|FEATURE_|__FLAGS__)"))'
)
Q3 = (
    "((string) @s "
    '(#match? @s "(?i)(feature[_-]?flag|launchdarkly|statsig|unleash|growthbook|'
    'flagsmith|split[.]io|killswitch|rollout|__FLAGS__|FEATURE_)"))'
)

# SDK call method -> provider (Q1).
_METHOD_PROVIDER = {
    "variation": "launchdarkly",
    "boolVariation": "launchdarkly",
    "checkGate": "statsig",
    "getConfig": "statsig",
    "isEnabled": "unleash",
    "getBooleanValue": "openfeature",
    "isOn": "growthbook",
}

# Role identifiers that gate UI (Q2) -> "ui-gate"; other Q2 hits -> "local".
_UI_GATE_PREFIXES = ("isAdmin", "isStaff", "isSuperUser")

# Known provider names that may appear inside a flag-ish string (Q3).
_PROVIDER_TOKENS = (
    ("launchdarkly", "launchdarkly"),
    ("statsig", "statsig"),
    ("unleash", "unleash"),
    ("growthbook", "growthbook"),
    ("flagsmith", "flagsmith"),
    ("openfeature", "openfeature"),
    ("split.io", "split"),
)

_EVIDENCE_CAP = 160
_SNIPPET_PAD = 30


def _classify(provider_method: str, key: str) -> tuple:
    """Map an SDK call method to ``(kind, provider)``.

    The Q1 regex guarantees ``provider_method`` is one of the known SDK methods,
    so this is the method -> provider map for SDK hits. Unknown method falls back
    to ``("unknown", "unknown")`` (defensive; should not happen for Q1 rows).
    """
    provider = _METHOD_PROVIDER.get((provider_method or "").strip())
    if provider:
        return ("sdk", provider)
    return ("unknown", "unknown")


def _provider_from_string(s: str) -> "str | None":
    """Provider name if a known SDK token appears in a flag-ish string, else None."""
    low = (s or "").lower()
    for token, provider in _PROVIDER_TOKENS:
        if token in low:
            return provider
    return None


def _locate(text: str, needle: str, identifier: bool = False) -> tuple:
    """Return ``(line_or_None, evidence_snippet)`` for the first hit of ``needle``.

    For a string key we try the quoted spellings first (so the snippet brackets
    the real call site), then bare; for an identifier we use a word boundary.
    """
    if not text or not needle:
        return (None, "")
    idx = -1
    if identifier:
        m = re.search(r"\b" + re.escape(needle) + r"\b", text)
        if m:
            idx = m.start()
    else:
        for cand, off in (('"' + needle + '"', 1), ("'" + needle + "'", 1),
                          ("`" + needle + "`", 1), (needle, 0)):
            p = text.find(cand)
            if p != -1:
                idx = p + off
                break
    if idx == -1:
        return (None, "")
    line = text.count("\n", 0, idx) + 1
    start = max(0, idx - _SNIPPET_PAD)
    end = min(len(text), idx + len(needle) + _SNIPPET_PAD)
    snippet = " ".join(text[start:end].split())
    return (line, snippet[:_EVIDENCE_CAP])


def _run_query(jsluice: str, query: str, path: str, timeout: int) -> list:
    """Run one jsluice query, return the parsed JSON rows (dicts). Never raises."""
    proc = tools.run([jsluice, "query", "-q", query, "-f", path], timeout=timeout)
    if proc is None:
        return []
    rows: list = []
    for line in (proc.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if isinstance(rec, dict):
            rows.append(rec)
    return rows


def scan_flags(items, cfg=None) -> "list[dict]":
    """Feature-flag records across every first-party/vendor ``item.saved_path``."""
    try:
        cfg = cfg or {}
        jsluice = resolve_jsluice(cfg)
        if not jsluice:
            return []

        timeout = int(cfg.get("per_file_timeout_sec", 60) or 60)
        scope_hosts = cfg.get("scope_hosts")

        out: list = []
        seen: set = set()

        for item in items or []:
            saved_path = getattr(item, "saved_path", None)
            if not saved_path:
                continue

            basename = os.path.basename(saved_path)
            origin_url = getattr(item, "url", None) or ""
            party = party_of(basename, origin_url, scope_hosts)
            if party == "third":            # queries run on first-party/vendor only
                continue

            # One read per file for line/evidence recovery (queries name no line).
            try:
                with open(saved_path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                text = ""

            def _add(key, kind, provider, identifier):
                key = str(key).strip()
                if not key:
                    return
                dkey = (key, basename)
                if dkey in seen:
                    return
                seen.add(dkey)
                line, snippet = _locate(text, key, identifier=identifier)
                out.append({
                    "key": key,
                    "provider": provider,
                    "kind": kind,
                    "file": basename,
                    "line": line,
                    "party": party,
                    "evidence": snippet or key,
                })

            # Q1 — SDK calls (method + string key on the same row). First so the
            # precise SDK classification wins the (key,file) dedupe.
            for rec in _run_query(jsluice, Q1, saved_path, timeout):
                method = rec.get("method")
                key = rec.get("key")
                if key is None or method is None:
                    continue
                kind, provider = _classify(method, key)
                _add(key, kind, provider, identifier=False)

            # Q2 — role / FEATURE_ / __FLAGS__ identifiers.
            for rec in _run_query(jsluice, Q2, saved_path, timeout):
                ident = rec.get("p")
                if ident is None:
                    continue
                ident = str(ident)
                if any(ident.startswith(pre) for pre in _UI_GATE_PREFIXES):
                    kind, provider = "ui-gate", "ui-gate"
                else:
                    kind, provider = "local", "local"
                _add(ident, kind, provider, identifier=True)

            # Q3 — flag-ish string literals (provider named inside -> that provider).
            for rec in _run_query(jsluice, Q3, saved_path, timeout):
                s = rec.get("s")
                if s is None:
                    continue
                s = str(s)
                provider = _provider_from_string(s) or "local"
                _add(s, "local", provider, identifier=False)

        return out
    except Exception:
        # Static extractors never raise into the pipeline.
        return []

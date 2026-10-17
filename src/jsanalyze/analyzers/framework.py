"""Static front-end framework fingerprint (deterministic, stdlib-only).

Counts framework-specific marker strings across the first-party + vendor bundle
text so the model knows *what it is reading* (React sinks vs Angular ɵ vs a jQuery
page) before triaging. Third-party (out-of-scope) files are excluded.

Contract: ``detect_framework(items, cfg=None) -> dict``. Never raises. Returns::

    {"framework": "react|vue|angular|next|svelte|preact|jquery|unknown",
     "version":   "<if confidently found, else ''>",
     "evidence":  ["<marker string seen>", ...],
     "candidates": {"react": <total hits>, ...}}   # only frameworks with hits

Selection = the framework with the most *distinctive* hits: primary key is the
number of DISTINCT markers matched, tie-broken by total occurrence count, then by
a fixed specificity order. Two explicit overrides from the spec:

  * ``__NEXT_DATA__`` present  -> prefer Next over React (Next ships React).
  * never pick jQuery while any real framework also has hits (jQuery is usually a
    co-loaded utility, not the app framework).

A version is reported ONLY when a recognised banner/constant is matched for the
chosen framework; otherwise ``""`` (never guessed).
"""

from __future__ import annotations

import os
import re

from jsanalyze.party import party_of

__all__ = ["detect_framework"]

# Distinctive marker substrings per framework (counted case-sensitively, as they
# appear in real bundles). Hits are summed across first-party + vendor files.
_MARKERS: dict[str, list[str]] = {
    "react":   ["react-dom", "__REACT_DEVTOOLS_GLOBAL_HOOK__", "useState",
                "createElement", "ReactDOM"],
    "next":    ["__NEXT_DATA__", "/_next/", "next/dist"],
    "vue":     ["__vue__", "createApp", "Vue.config", "vue-router"],
    "angular": ["@angular", "zone.js", "ɵ", "platformBrowser"],
    "svelte":  ["svelte/internal", "__svelte"],
    "preact":  ["preact"],
    "jquery":  ["jQuery", "jquery", "$.fn.jquery"],
}

# Specificity order: earlier = preferred on an exact tie (a real/specific
# framework over the generic jQuery; Next over the React it is built on).
_ORDER = ["next", "react", "vue", "angular", "svelte", "preact", "jquery"]

# Best-effort version banners/constants. Tried only for the chosen framework.
_VERSION_RES: dict[str, list[re.Pattern]] = {
    "react": [
        re.compile(r'''ReactVersion\s*=\s*['"]([0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.\-]*)['"]'''),
        re.compile(r'''['"]react(?:-dom)?['"]\s*:\s*['"][\^~>=<\s]*([0-9]+\.[0-9]+\.[0-9]+)'''),
    ],
    "next": [
        re.compile(r'''['"]next['"]\s*:\s*['"][\^~>=<\s]*([0-9]+\.[0-9]+\.[0-9]+)'''),
    ],
    "vue": [
        re.compile(r'''Vue\.version\s*=\s*['"]([0-9]+\.[0-9]+\.[0-9]+)['"]'''),
        re.compile(r'''\bversion\s*[:=]\s*['"]([0-9]+\.[0-9]+\.[0-9]+)['"][\s\S]{0,60}?vue''',
                   re.IGNORECASE),
    ],
    "angular": [
        re.compile(r'''new\s+\w*Version\(['"]([0-9]+\.[0-9]+\.[0-9]+)['"]'''),
        re.compile(r'''@angular/core['"@]*[^0-9]{0,20}?([0-9]+\.[0-9]+\.[0-9]+)'''),
    ],
    "svelte": [
        re.compile(r'''svelte[@/ ]v?([0-9]+\.[0-9]+\.[0-9]+)''', re.IGNORECASE),
    ],
    "preact": [
        re.compile(r'''preact[@/ ]v?([0-9]+\.[0-9]+\.[0-9]+)''', re.IGNORECASE),
    ],
    "jquery": [
        re.compile(r'''jQuery\s+(?:JavaScript Library\s+)?v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)'''),
        re.compile(r'''\$\.fn\.jquery\s*=\s*['"]([0-9]+\.[0-9]+(?:\.[0-9]+)?)'''),
        re.compile(r'''jquery[@/ -]v?([0-9]+\.[0-9]+(?:\.[0-9]+)?)''', re.IGNORECASE),
    ],
}


def _find_version(framework: str, text: str) -> str:
    for rx in _VERSION_RES.get(framework, []):
        try:
            m = rx.search(text)
        except Exception:
            continue
        if m:
            return m.group(1)
    return ""


def _pick(counts: dict, distinct: dict, seen_markers: set) -> str:
    present = [fw for fw in _ORDER if counts.get(fw, 0) > 0]
    if not present:
        return "unknown"

    def score(fw):
        return (distinct.get(fw, 0), counts.get(fw, 0), -_ORDER.index(fw))

    framework = max(present, key=score)

    # prefer a real framework over the generic jQuery utility
    if framework == "jquery":
        reals = [fw for fw in present if fw != "jquery"]
        if reals:
            framework = max(reals, key=score)

    # Next ships React — a Next data island outranks React markers
    if "__NEXT_DATA__" in seen_markers and counts.get("next", 0) > 0:
        framework = "next"

    return framework


def _evidence(seen_markers: set) -> list[str]:
    ev: list[str] = []
    for fw in _ORDER:
        for mk in _MARKERS[fw]:
            if mk in seen_markers and mk not in ev:
                ev.append(mk)
    return ev


def detect_framework(items, cfg=None) -> dict:
    """Fingerprint the front-end framework from the bundle text. Never raises."""
    unknown = {"framework": "unknown", "version": "", "evidence": [], "candidates": {}}
    try:
        scope_hosts = cfg.get("scope_hosts") if isinstance(cfg, dict) else None

        counts: dict[str, int] = {fw: 0 for fw in _MARKERS}
        seen_markers: set = set()
        versions: dict[str, str] = {}

        for item in (items or []):
            try:
                saved_path = getattr(item, "saved_path", None)
                if not saved_path or not os.path.isfile(saved_path):
                    continue
                url = getattr(item, "url", "") or ""
                base = os.path.basename(saved_path)
                if party_of(base, url, scope_hosts) == "third":
                    continue  # count first-party + vendor only
                with open(saved_path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except Exception:
                continue

            for fw, markers in _MARKERS.items():
                fw_hit = False
                for mk in markers:
                    c = text.count(mk)
                    if c:
                        counts[fw] += c
                        seen_markers.add(mk)
                        fw_hit = True
                if fw_hit and fw not in versions:
                    v = _find_version(fw, text)
                    if v:
                        versions[fw] = v

        distinct = {fw: sum(1 for mk in _MARKERS[fw] if mk in seen_markers)
                    for fw in _MARKERS}
        framework = _pick(counts, distinct, seen_markers)
        candidates = {fw: counts[fw] for fw in _ORDER if counts.get(fw, 0) > 0}
        version = versions.get(framework, "") if framework != "unknown" else ""

        return {
            "framework": framework,
            "version": version,
            "evidence": _evidence(seen_markers),
            "candidates": candidates,
        }
    except Exception:
        return unknown

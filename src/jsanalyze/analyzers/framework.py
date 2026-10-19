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


# --- framework-specific XSS / pollution gadgets (critique point 11) -----------
# Each: how to find it, the lead class, skill, severity and the proof instruction.
_ANGULAR_BYPASS_RE = re.compile(r"bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(")
_PROTO_LODASH_RE = re.compile(r"(?<![\w$])(?:_|lodash)\s*\.\s*(merge|mergeWith|defaultsDeep|setWith|set)\s*\(")
_PROTO_JQ_RE = re.compile(r"\$\s*\.\s*extend\s*\(\s*(?:!0|true)\b")
_NEXT_DATA_RE = re.compile(r"__NEXT_DATA__")
_JSURI_RE = re.compile(
    r"""(?:href|src|xlink:href|formaction|action)\b[^;\n{}]{0,40}?javascript:""", re.I)
_JSURI_DYNAMIC = re.compile(r"""javascript:['"`]?\s*(?:\+|\$\{)|(?:\+|\$\{)[^;\n]{0,20}javascript:""")


def _scan_gadgets(text: str, party: str, base: str) -> list:
    """Find framework DOM-XSS / prototype-pollution gadgets in one file's text.

    Conservative + LOW confidence: a gadget is a *lead*, never a finding — it still
    needs the usual reachability proof (is the argument attacker-controlled?)."""
    out = []

    def add(cls, skill, gadget, sev, m, title, nxt, neg, exp, conf="low"):
        line = text.count("\n", 0, m.start()) + 1
        out.append({
            "cls": cls, "suggested_skill": skill, "gadget": gadget, "severity_hint": sev,
            "confidence": conf, "party": party, "file": base, "line": line,
            "evidence": " ".join(text[m.start():m.start() + 100].split()),
            "title": title, "next_step": nxt, "negative_control": neg, "experiment": exp,
        })

    for m in _ANGULAR_BYPASS_RE.finditer(text):
        add("framework-gadget", "hunt-xss", "angular-bypass-security", "medium", m,
            "Angular sanitization bypass (bypassSecurityTrust*)",
            "Angular explicitly disables sanitization here — if the argument is attacker-"
            "controlled this is DOM-XSS. Trace the value back to a source. (hunt-xss)",
            "A trusted-constant argument is safe; only an attacker-controlled one executes.",
            "Trace the bypassSecurityTrust* argument to a user source; if reachable, inject and confirm execution.")
    for m in _PROTO_LODASH_RE.finditer(text):
        add("framework-gadget", "hunt-server-side", "prototype-pollution", "medium", m,
            f"Prototype-pollution sink (lodash .{m.group(1)})",
            "A deep-merge/set with an attacker-controlled object can pollute Object.prototype — "
            "confirm the merged object is user-derived AND the lodash version is vulnerable "
            "(see libs.json) before claiming impact. (hunt-server-side)",
            "A merge of only trusted/own objects is not pollution; a non-vulnerable lodash is not exploitable.",
            'Send a payload with a "__proto__" key into the merged object and check for a polluted global property.')
    for m in _PROTO_JQ_RE.finditer(text):
        add("framework-gadget", "hunt-server-side", "prototype-pollution", "medium", m,
            "Prototype-pollution sink (jQuery deep $.extend(true,…))",
            "jQuery deep extend with attacker input can pollute Object.prototype — confirm the "
            "source object is user-derived and jQuery is a vulnerable version. (hunt-server-side)",
            "A deep extend of trusted objects is safe.",
            'Feed a "__proto__"/"constructor.prototype" key into the extended object and check for pollution.')
    nd = _NEXT_DATA_RE.search(text)
    if nd:
        add("framework-gadget", "hunt-js-analysis", "next-data-island", "low", nd,
            "Next.js __NEXT_DATA__ hydration island",
            "The server-rendered __NEXT_DATA__ JSON hydrates the app — check whether it reflects "
            "user-influenced values that then flow to a sink (indirect DOM-XSS / client trust). (hunt-js-analysis)",
            "Data that never reflects attacker input is not a vector.",
            "Diff __NEXT_DATA__ with a user-controlled query/profile value; see if it lands in a sink on hydration.")
    # dynamic javascript: URI (skip the benign javascript:void(0)/; literals)
    for m in _JSURI_RE.finditer(text):
        tail = text[m.end():m.end() + 30]
        if _JSURI_DYNAMIC.search(text[m.start():m.end() + 30]) and "void(0)" not in tail:
            add("framework-gadget", "hunt-xss", "javascript-uri", "medium", m,
                "Dynamic javascript: URI sink",
                "A javascript: URI built from a variable in an href/src is script execution if the "
                "value is attacker-controlled. (hunt-xss)",
                "A static javascript:void(0) is inert; only a dynamic, attacker-influenced URI runs.",
                "Control the concatenated part of the javascript: URI and confirm execution on click/navigation.")
    return out


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
        gadgets: list = []

        for item in (items or []):
            try:
                saved_path = getattr(item, "saved_path", None)
                if not saved_path or not os.path.isfile(saved_path):
                    continue
                url = getattr(item, "url", "") or ""
                base = os.path.basename(saved_path)
                party = party_of(base, url, scope_hosts)
                if party == "third":
                    continue  # count first-party + vendor only
                with open(saved_path, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except Exception:
                continue

            try:
                gadgets.extend(_scan_gadgets(text, party, base))
            except Exception:
                pass

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
            "gadgets": gadgets,
        }
    except Exception:
        return unknown

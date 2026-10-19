"""Classify jsluice `postmessage` output into distinct families (critique point 3).

jsluice emits three different `kind`s that must NOT be collapsed into one
"listener" class:

  * addEventListener  — a `message` listener. No origin check -> `postmessage-listener`
                        (lead). An origin check that is WEAK (indexOf/startsWith/endsWith/
                        includes/`== ""`) -> `postmessage-origin-bypass` (lead). A strong
                        exact check -> not a lead (a real control).
  * postMessageSend   — a `postMessage(data, targetOrigin)` call. `targetOrigin:"*"` is a
                        data-leak -> `postmessage-sender` (lead). Skill is hunt-xss, or
                        hunt-auth-bypass when the payload looks like a token/credential.
  * onmessage         — `ws.onmessage` / `port.onmessage` (WebSocket / MessageChannel).
                        This is NOT window.postMessage -> kept for audit, never a lead here.
"""

from __future__ import annotations

import os
import re

from jsanalyze.party import party_of

# a weak origin check (defeatable) — a lead (postmessage-origin-bypass), not a control
_WEAK_ORIGIN = re.compile(
    r"\.origin\s*\.\s*(indexOf|startsWith|endsWith|includes|match|search)\b"
    r"|\borigin\s*(===?|!==?)\s*(['\"]\s*['\"]|``)"            # compare to empty string
    r"|(indexOf|includes|startsWith|endsWith)\s*\(\s*['\"][^'\"]*['\"]\s*\)",
    re.IGNORECASE,
)
_TOKENISH = re.compile(r"token|auth|jwt|oauth|\bcode\b|secret|credential|session|bearer", re.IGNORECASE)
_WILDCARD_TARGET = re.compile(r"postMessage\s*\([^;]*?,\s*(['\"])\*\1\s*\)", re.IGNORECASE)

# a sink the handler's event.data can reach (critique point 7) — if the handler body
# flows the message data into one of these, a no-origin-check listener is a real lead
# even when jsluice reported no `sinks[]`.
_DATA_SINK_RE = re.compile(
    r"innerHTML|outerHTML|insertAdjacentHTML|document\s*\.\s*write|dangerouslySetInnerHTML"
    r"|\beval\b|new\s+Function|setTimeout|setInterval|\.src\b|\.href\b|location\s*\."
    r"|location\s*=|localStorage|sessionStorage|document\s*\.\s*cookie|getUserMedia"
    r"|\.setItem\b|\.postMessage\b|importScripts",
    re.IGNORECASE,
)
# message-handler callback param ( function(e){…}  |  (evt)=>…  |  onmessage=e=> )
_HANDLER_PARAM_RE = re.compile(
    r"(?:addEventListener\s*\(\s*['\"]message['\"]\s*,|onmessage\s*=)\s*"
    r"(?:async\s*)?(?:function\s*)?\(?\s*([A-Za-z_$][\w$]*)",
)

# extra message-channel surfaces jsluice does not emit as `postmessage`
_EXTRA_SURFACES = (
    ("window-opener", re.compile(r"\bwindow\s*\.\s*opener\b|\bopener\s*\.\s*postMessage")),
    ("broadcastchannel", re.compile(r"\bnew\s+BroadcastChannel\s*\(")),
    ("serviceworker-register", re.compile(r"serviceWorker\s*\.\s*register\s*\(")),
    ("importscripts-dyn", re.compile(r"importScripts\s*\(\s*(?![\"'])")),
)
_EXTRA_META = {
    "window-opener": ("hunt-xss", "medium", "window.opener reachable — a child page can read/call "
                      "back into the opener; check for data/token leakage across origins."),
    "broadcastchannel": ("hunt-xss", "low", "BroadcastChannel receives cross-tab messages with no "
                         "origin concept — any same-origin (incl. XSS'd) tab can post to it."),
    "serviceworker-register": ("hunt-js-analysis", "low", "Service worker registration — a worker "
                               "can intercept fetches; check scope and whether its script is "
                               "attacker-influenceable."),
    "importscripts-dyn": ("hunt-xss", "medium", "importScripts() with a non-literal argument in a "
                          "worker can load attacker-chosen code if the URL is influenced."),
}


def _text_index(items) -> dict:
    out: dict = {}
    for it in (items or []):
        sp = getattr(it, "saved_path", None)
        if not sp:
            continue
        base = os.path.basename(sp)
        if base in out:
            continue
        try:
            with open(sp, "r", encoding="utf-8", errors="replace") as fh:
                out[base] = fh.read()
        except OSError:
            continue
    return out


def _data_flow_signal(text: str, line) -> "str | None":
    """Does the message handler at/near ``line`` flow event.data into a sink?

    Returns the sink token reached (e.g. ``innerHTML``), or None. Scans ONLY the
    handler's own balanced ``{...}`` body (not a fixed window — that bled into the
    next statement) and requires BOTH a ``.data`` reference and a sink token inside it."""
    if not text or not line:
        return None
    off = _offset_of(text, int(line))
    head = text[off: off + 400]
    pm = _HANDLER_PARAM_RE.search(head)
    if not pm:
        return None
    param = pm.group(1)
    body = _handler_body(text, off + pm.end())
    if not body:
        return None
    data_ref = re.search(re.escape(param) + r"\s*\.\s*data\b", body) \
        or re.search(r"\b(?:event|evt|msg)\s*\.\s*data\b", body)
    if not data_ref:
        return None
    sm = _DATA_SINK_RE.search(body)
    return sm.group(0).strip() if sm else None


def _handler_body(text: str, after: int, cap: int = 4000) -> str:
    """The balanced ``{...}`` body of the handler whose signature ends near ``after``."""
    i = text.find("{", after, after + 80)
    if i == -1:
        return ""
    depth, j, end = 0, i, min(len(text), i + cap)
    while j < end:
        c = text[j]
        if c in "\"'`":
            j = _skip_str(text, j, end)
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
        j += 1
    return text[i:end]


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


def _offset_of(text: str, line: int) -> int:
    i, cur = 0, 1
    while cur < line:
        nl = text.find("\n", i)
        if nl == -1:
            return len(text)
        i = nl + 1
        cur += 1
    return i


def classify_postmessage(pm_records, items, cfg=None, scope_hosts=None) -> list[dict]:
    path_to_url = {it.saved_path: it.url for it in (items or []) if getattr(it, "saved_path", None)}
    text_by_base = _text_index(items)
    out = []
    for rec in pm_records or []:
        if not isinstance(rec, dict):
            continue
        kind = rec.get("kind") or ""
        source = rec.get("source") or ""
        filename = rec.get("filename") or ""
        src_file = rec.get("source_file") or (filename.rsplit("/", 1)[-1] if filename else "")
        origin = rec.get("origin_url") or path_to_url.get(filename)
        party = party_of(src_file, origin or "", scope_hosts)
        reaches = rec.get("sinks") or []
        origin_checked = bool(rec.get("originChecked"))
        data_flow = None
        if kind == "addEventListener" and not reaches:
            data_flow = _data_flow_signal(text_by_base.get(src_file, ""), rec.get("line"))

        base = {
            "kind": kind, "party": party, "origin_checked": origin_checked,
            "reaches_sinks": reaches, "data_flow_signal": data_flow, "wildcard_target": False,
            "file": src_file, "line": rec.get("line"),
            "source": " ".join(source.split())[:220],
        }
        signal = bool(reaches) or bool(data_flow)

        if kind == "onmessage":
            base.update(pm_class="onmessage", lead=False, suggested_skill="hunt-websocket",
                        severity_hint="info", confidence="low")

        elif kind == "postMessageSend":
            wildcard = bool(_WILDCARD_TARGET.search(source)) or '"*"' in source or "'*'" in source
            tokenish = bool(_TOKENISH.search(source))
            base.update(
                pm_class="postmessage-sender", wildcard_target=wildcard,
                lead=wildcard,
                suggested_skill="hunt-auth-bypass" if (wildcard and tokenish) else "hunt-xss",
                severity_hint="high" if (wildcard and tokenish) else ("medium" if wildcard else "info"),
                confidence="medium" if wildcard else "low",
            )

        elif kind == "addEventListener":
            # critique point 7: a no-origin-check listener is STILL a lead (missing
            # check is the precondition and jsluice's sink list is incomplete), but it
            # is DEMOTED to low when nothing shows the data reaching a sink — so it no
            # longer sits at the top of the queue above real endpoints.
            if not origin_checked:
                sev = "high" if reaches else ("medium" if data_flow else "low")
                base.update(
                    pm_class="postmessage-listener", lead=True, suggested_skill="hunt-xss",
                    severity_hint=sev, confidence="medium" if signal else "low",
                )
            elif _WEAK_ORIGIN.search(source):
                sev = "high" if reaches else ("medium" if data_flow else "low")
                base.update(
                    pm_class="postmessage-origin-bypass", lead=True, suggested_skill="hunt-xss",
                    severity_hint=sev, confidence="medium" if signal else "low",
                )
            else:
                base.update(pm_class="postmessage-listener-checked", lead=False,
                            suggested_skill="hunt-xss", severity_hint="info", confidence="low")
        else:
            base.update(pm_class=kind or "unknown", lead=False, suggested_skill="hunt-xss",
                        severity_hint="info", confidence="low")

        # vendor-bundled handlers are de-prioritised to audit-only
        if base["lead"] and party == "vendor":
            base["lead"] = False
        out.append(base)

    out += _discover_surfaces(items, path_to_url, text_by_base, scope_hosts)

    out.sort(key=lambda r: (not r["lead"],
                            {"high": 0, "medium": 1, "low": 2, "info": 3}.get(r["severity_hint"], 4)))
    return out


def _discover_surfaces(items, path_to_url, text_by_base, scope_hosts) -> list:
    """window.opener / BroadcastChannel / serviceWorker.register / importScripts() —
    cross-context message surfaces jsluice does not report as postMessage."""
    out = []
    seen = set()
    for it in (items or []):
        sp = getattr(it, "saved_path", None)
        if not sp:
            continue
        base = os.path.basename(sp)
        text = text_by_base.get(base, "")
        if not text:
            continue
        party = party_of(base, getattr(it, "url", "") or "", scope_hosts)
        if party == "vendor":
            continue
        for name, rx in _EXTRA_SURFACES:
            m = rx.search(text)
            if not m:
                continue
            key = (name, base)
            if key in seen:
                continue
            seen.add(key)
            skill, sev, note = _EXTRA_META[name]
            line = text.count("\n", 0, m.start()) + 1
            out.append({
                "kind": name, "pm_class": name, "party": party, "origin_checked": None,
                "reaches_sinks": [], "data_flow_signal": None, "wildcard_target": False,
                "file": base, "line": line,
                "source": " ".join(text[m.start():m.start() + 120].split()),
                "lead": party != "vendor", "suggested_skill": skill,
                "severity_hint": sev, "confidence": "low", "note": note,
            })
    return out

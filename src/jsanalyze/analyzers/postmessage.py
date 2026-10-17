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


def classify_postmessage(pm_records, items, cfg=None, scope_hosts=None) -> list[dict]:
    path_to_url = {it.saved_path: it.url for it in (items or []) if getattr(it, "saved_path", None)}
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

        base = {
            "kind": kind, "party": party, "origin_checked": origin_checked,
            "reaches_sinks": reaches, "wildcard_target": False,
            "file": src_file, "line": rec.get("line"),
            "source": " ".join(source.split())[:220],
        }

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
            if not origin_checked:
                base.update(
                    pm_class="postmessage-listener", lead=True, suggested_skill="hunt-xss",
                    severity_hint="high" if reaches else "medium", confidence="medium",
                )
            elif _WEAK_ORIGIN.search(source):
                base.update(
                    pm_class="postmessage-origin-bypass", lead=True, suggested_skill="hunt-xss",
                    severity_hint="high" if reaches else "medium", confidence="medium",
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

    out.sort(key=lambda r: (not r["lead"],
                            {"high": 0, "medium": 1, "info": 2}.get(r["severity_hint"], 3)))
    return out

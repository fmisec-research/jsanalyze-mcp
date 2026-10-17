"""Turn a :class:`Triaged` bundle into an ordered list of DISTINCT lead candidates.

A lead is a candidate, never a finding. The triage analyzers already gated the noise
(vendor/constant/non-tainted sinks, garbage endpoints, split postMessage families), so
here we simply mint one lead per surviving, de-duplicated signal — not one per raw
jsluice row. Every lead names the hunt-* skill that would PROVE it.
"""

from __future__ import annotations

import json

from jsanalyze.analyzers.endpoints import classify_endpoint
from jsanalyze.leads.rules import NEXT_STEP
from jsanalyze.models import Lead
from jsanalyze.utils.workspace import load_config, mask_data

__all__ = ["build_leads"]

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}

_CLOUD_PREFIXES = ("AKIA", "AIza", "ASIA")
_CLOUD_TOKENS = ("aws", "amazon", "gcp", "google", "azure", "service_account",
                 "serviceaccount", "service-account")


def _is_cloud_secret(kind, data) -> bool:
    try:
        blob = f"{kind or ''} {json.dumps(data, ensure_ascii=False, default=str)}"
    except (TypeError, ValueError):
        blob = f"{kind or ''} {data!r}"
    if any(p in blob for p in _CLOUD_PREFIXES):
        return True
    return any(t in blob.lower() for t in _CLOUD_TOKENS)


def _lib_skill(cwe) -> str:
    joined = " ".join(cwe or [])
    if "79" in joined:
        return "hunt-xss"
    if "89" in joined:
        return "hunt-injection"
    if any(x in joined for x in ("77", "78", "94", "502")):
        return "hunt-server-side"
    return "hunt-js-analysis"


def _secret_evidence(data, mask: bool) -> str:
    value = mask_data(data) if mask else data
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        return str(value)


def _first_occ(cluster):
    occ = (cluster.get("occurrences") or [{}])[0]
    return occ.get("file", ""), occ.get("line"), occ.get("source", "")


def build_leads(triaged, cfg=None) -> list[dict]:
    cfg = cfg or load_config()
    mask = cfg.get("mask_secrets_in_leads", True)
    leads: list[Lead] = []

    # --- DOM-XSS sinks (one lead per gated cluster) ---------------------------
    for c in getattr(triaged, "sinks", []) or []:
        if not c.get("lead"):
            continue
        f, line, src = _first_occ(c)
        extra = f" (+{c['count'] - 1} more)" if c.get("count", 1) > 1 else ""
        leads.append(Lead(
            id="", cls="xss-sink", suggested_skill="hunt-xss",
            title=f"DOM-XSS {c.get('kind')} [{c.get('sink_class')}] tainted by {c.get('taint_source')}",
            source_file=f, line=line, evidence=src, detector="jsluice:sinks",
            tainted=True, confidence=c.get("confidence", "medium"),
            severity_hint=c.get("severity_hint", "high"),
            next_step=NEXT_STEP["xss-sink"],
            notes=f"party={c.get('party')}; occurrences={c.get('count')}{extra}.",
        ))

    # --- postMessage family ---------------------------------------------------
    for r in getattr(triaged, "postmessage", []) or []:
        if not r.get("lead"):
            continue
        cls = r.get("pm_class", "postmessage-listener")
        note = f"party={r.get('party')}; originChecked={r.get('origin_checked')}"
        if r.get("wildcard_target"):
            note += "; targetOrigin=*"
        if r.get("reaches_sinks"):
            note += f"; reaches sinks {r['reaches_sinks']}"
        leads.append(Lead(
            id="", cls=cls, suggested_skill=r.get("suggested_skill", "hunt-xss"),
            title=f"{cls} ({r.get('kind')})",
            source_file=r.get("file", ""), line=r.get("line"), evidence=r.get("source", ""),
            detector="jsluice:postmessage", confidence=r.get("confidence", "medium"),
            severity_hint=r.get("severity_hint", "medium"),
            next_step=NEXT_STEP.get(cls, NEXT_STEP["postmessage-listener"]), notes=note + ".",
        ))

    # --- endpoints (classified, deduped) --------------------------------------
    seen_ep = set()
    for n in getattr(triaged, "endpoints", []) or []:
        info = classify_endpoint(n)
        if not info:
            continue
        cls, skill, conf, sev, why = info
        key = (cls, n.get("method"), n.get("path"))
        if key in seen_ep:
            continue
        seen_ep.add(key)
        ev = f"{n.get('method') or ''} {n.get('path')}".strip()
        note = f"{why}; party={n.get('party')}; in_scope={n.get('in_scope')}"
        if n.get("dynamic"):
            note += "; dynamic(EXPR)"
        leads.append(Lead(
            id="", cls=cls, suggested_skill=skill, title=f"{cls} — {ev}",
            source_file=(n.get("where_found") or "").split(":")[0],
            line=None, evidence=ev, detector=f"{n.get('detector', 'jsluice')}:urls",
            confidence=conf, severity_hint=sev, next_step=NEXT_STEP.get(cls, ""), notes=note + ".",
        ))

    # --- secrets --------------------------------------------------------------
    for s in getattr(triaged, "secrets", []) or []:
        kind = s.get("kind") or "secret"
        data = s.get("data")
        skill = "hunt-cloud" if _is_cloud_secret(kind, data) else "hunt-secrets-disclosure"
        leads.append(Lead(
            id="", cls="secret-location", suggested_skill=skill,
            title=f"Client-side secret ({kind})",
            source_file=s.get("source_file", ""), line=s.get("line"),
            evidence=_secret_evidence(data, mask), detector=f"{s.get('detector', 'jsluice')}:secrets",
            confidence="medium", severity_hint=s.get("severity") or "medium",
            next_step=NEXT_STEP["secret-location"],
            notes=f"[{s.get('detector', 'jsluice')}] secret format match — a lead until proven live.",
        ))

    # --- vulnerable libraries -------------------------------------------------
    for lib in getattr(triaged, "libs", []) or []:
        cves = lib.get("cves") or []
        cve_str = ", ".join(cves[:4]) + (" …" if len(cves) > 4 else "")
        leads.append(Lead(
            id="", cls="vulnerable-library", suggested_skill=_lib_skill(lib.get("cwe")),
            title=f"{lib.get('component')} {lib.get('version')} — {cve_str or 'known vuln'}",
            source_file=lib.get("source_file", ""), line=None,
            evidence=f"{lib.get('component')}@{lib.get('version')}"
                     + (f" (< {lib.get('below')})" if lib.get("below") else ""),
            detector="retire", confidence="medium", severity_hint=lib.get("severity") or "medium",
            next_step=(f"Confirm {lib.get('component')} {lib.get('version')} is loaded and the "
                       f"vulnerable path is reachable, then map the CVE to an effect. "
                       f"{lib.get('summary', '')}".strip()),
            notes=f"retire.js ({lib.get('detection')}); CWE={','.join(lib.get('cwe') or []) or '-'}.",
        ))

    # --- UI-gate feature flags (hidden-mode surface) --------------------------
    for fl in getattr(triaged, "flags", []) or []:
        if fl.get("kind") != "ui-gate":
            continue  # SDK/local flags stay in flags.json; only role/mode gates are a lead
        leads.append(Lead(
            id="", cls="feature-gate", suggested_skill="hunt-api",
            title=f"Client-side role/mode gate ({fl.get('key')})",
            source_file=fl.get("file", ""), line=fl.get("line"), evidence=fl.get("evidence", ""),
            detector="flags", confidence="low", severity_hint="medium",
            next_step="A client-enforced role/mode gate often hides privileged UI/endpoints — "
                      "test the gated action server-side as a low-privilege role. (hunt-api)",
            notes=f"party={fl.get('party')}; mechanism={fl.get('provider')}.",
        ))

    leads.sort(key=lambda ld: (_SEV_RANK.get(ld.severity_hint, 9),
                               _CONF_RANK.get(ld.confidence, 9)))
    for i, ld in enumerate(leads, 1):
        ld.id = f"lead-{i:04d}"
    return [ld.to_dict() for ld in leads]

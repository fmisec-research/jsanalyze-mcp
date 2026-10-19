"""Composite lead scoring (critique point 10) — pure, testable, explainable.

The old queue ordered by ``(severity_hint, confidence)`` alone, so every
no-origin-check postMessage listener sorted above a hidden endpoint. The real
signal a hunter wants is a BLEND: a first-party, in-scope endpoint that the
operator has NOT yet exercised, carries an id segment, and sits next to a secret
is worth more than a vendor-bundled listener with no reachable sink — regardless
of the raw severity label.

``score_lead`` returns ``(score, factors)`` where ``factors`` is the list of
human-readable ``+term`` / ``-term`` contributions, so the number is never a
black box. Higher = more worth a human's time. The score is the PRIMARY sort key;
severity_hint/confidence remain as tie-breakers and as honest potential-impact
labels (never proof).
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["score_lead", "ScoreInputs"]

_SEV_BASE = {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 2.0, "info": 1.0}
_CONF_BONUS = {"high": 0.6, "medium": 0.3, "low": 0.0}


@dataclass
class ScoreInputs:
    """Signals the scorer needs that are not all on the Lead itself. The lead
    engine fills these from the triage records it already holds."""

    party: str = "first"               # first | vendor | third
    in_scope: bool | None = None       # None = unknown (don't penalize)
    call_type: str = ""                # jsluice url `type` (stringLiteral => penalty)
    has_id_segment: bool = False       # a resource/{id} shape or id-ish param
    secret_nearby: bool = False        # same source_file carries a secret
    pm_has_signal: bool = False        # postMessage listener reaches a sink / writes data
    history_known: bool = False        # was a traffic history available to compare?


def score_lead(ld, si: ScoreInputs) -> "tuple[float, list[str]]":
    """Return ``(score, factors)`` for a Lead given its ScoreInputs."""
    factors: list[str] = []
    score = _SEV_BASE.get(ld.severity_hint, 1.0)
    factors.append(f"sev:{ld.severity_hint}={score:.0f}")

    cb = _CONF_BONUS.get(ld.confidence, 0.0)
    if cb:
        score += cb
        factors.append(f"+conf:{ld.confidence}")

    # party
    if si.party == "first":
        score += 2.0
        factors.append("+first_party")
    elif si.party == "vendor":
        score -= 2.0
        factors.append("-vendor")
    # third party: neutral (out-of-scope penalty handled by in_scope below)

    # scope
    if si.in_scope is True:
        score += 1.0
        factors.append("+in_scope")
    elif si.in_scope is False:
        score -= 1.5
        factors.append("-out_of_scope")

    # real attacker taint reaching a sink
    if ld.tainted:
        score += 2.0
        factors.append("+tainted")

    # the untested-surface signal: in JS but never exercised in captured traffic
    if si.history_known:
        if ld.seen_in_history is False:
            score += 2.0
            factors.append("+not_in_history")
        elif ld.seen_in_history is True:
            score -= 1.0
            factors.append("-already_exercised")

    # a manipulable object identifier
    if si.has_id_segment:
        score += 1.0
        factors.append("+id_segment")

    # a secret in the same file (key material next to the surface that uses it)
    if si.secret_nearby:
        score += 1.0
        factors.append("+secret_nearby")

    # request-shape knowledge: an endpoint we can actually replay (method + body)
    if ld.body_keys:
        score += 0.5
        factors.append("+body_keys")

    # penalties: weak provenance
    if (si.call_type or "").lower() == "stringliteral":
        score -= 1.0
        factors.append("-string_literal")
    if ld.cls.endswith("-candidate") or ld.cls in ("endpoint-hidden", "endpoint-unverified"):
        if not ld.method:
            score -= 1.0
            factors.append("-no_method")

    # a postMessage listener with no reachable sink and no data-flow signal
    if ld.cls.startswith("postmessage") and not si.pm_has_signal:
        score -= 2.0
        factors.append("-listener_no_sink")

    score = round(max(score, 0.1), 2)
    return score, factors

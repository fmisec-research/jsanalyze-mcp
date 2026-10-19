"""Normalize + classify secrets (critique point 9) — pure, stdlib-only.

jsluice and gitleaks/trufflehog frequently report the SAME value (often with
``line: None``), so the queue shows the one Stripe key three times; and every match is
labelled ``severity: high`` even when it is a PUBLISHABLE key that is meant to ship in
the client. This module:

  * dedupes by a NORMALIZED value (quote/space-stripped) and MERGES the detectors that
    found it into one record (``detectors: [...]``),
  * tags ``visibility``: ``public`` (``pk_``/Sentry DSN/analytics/reCAPTCHA site key —
    designed to be in client code) vs ``private`` (``sk_live``/AWS/GitHub/Slack/private
    key/npm token) vs ``unknown`` (e.g. a Google ``AIza`` key — usually a referrer-
    restricted Firebase/Maps *browser* key, so NOT auto-high: check the restriction),
  * sets ``severity`` from that (public -> info, cloud/live -> high, else medium) and a
    typed ``weaponization`` + ``use_hint`` so the lead's next step is concrete.

Provider VERIFICATION stays off (Operator Gate) — this only reads the values already
extracted.
"""

from __future__ import annotations

import re

__all__ = ["classify_secrets"]

# (compiled pattern, visibility, severity, label, weaponization)
_RULES = [
    # --- public: designed to live in client code -----------------------------
    (re.compile(r"\bpk_(live|test)_[0-9A-Za-z]+"), "public", "info", "stripe-publishable",
     "Publishable Stripe key — public by design; not a finding on its own."),
    (re.compile(r"https://[0-9a-f]+@[\w.\-]*(ingest\.)?sentry\.io/\d+", re.I), "public", "info",
     "sentry-dsn", "Sentry DSN — public ingestion endpoint; at most noise/abuse."),
    (re.compile(r"\bUA-\d{4,}-\d+\b|\bG-[A-Z0-9]{6,}\b|\bGTM-[A-Z0-9]{4,}\b|\bAW-\d+\b"),
     "public", "info", "analytics-id", "Analytics measurement id — public identifier."),
    (re.compile(r"\bpk\.[0-9A-Za-z._\-]{20,}"), "public", "info", "mapbox-public",
     "Mapbox public token — meant for the client; check scope/URL restriction only."),
    # --- private: must never ship ---------------------------------------------
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "private", "high", "aws-access-key",
     "AWS access key id — pair with a secret to reach the account (Operator Gate to verify)."),
    (re.compile(r"\bsk_live_[0-9A-Za-z]+"), "private", "high", "stripe-secret-live",
     "Stripe LIVE secret key — full API access to the account; do NOT call it (Operator Gate)."),
    (re.compile(r"\bsk_test_[0-9A-Za-z]+"), "private", "medium", "stripe-secret-test",
     "Stripe TEST secret key — test-mode API access; still a leaked secret."),
    (re.compile(r"\bgh[pousr]_[0-9A-Za-z]{30,}"), "private", "high", "github-token",
     "GitHub token — repo/org access; map scopes (Operator Gate to verify)."),
    (re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}"), "private", "high", "slack-token",
     "Slack token — workspace access."),
    (re.compile(r"\bglpat-[0-9A-Za-z_\-]{20,}"), "private", "high", "gitlab-pat",
     "GitLab personal access token."),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "private", "high", "private-key",
     "Embedded private key — signing/decryption material."),
    (re.compile(r"//.*:_authToken=|_authToken\s*=\s*[0-9A-Za-z\-_]+"), "private", "high",
     "npm-token", "Private npm registry token — pull/push private packages."),
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}"), "private", "high", "openai-key",
     "OpenAI secret key — billable API access."),
    # --- unknown / context-dependent ------------------------------------------
    (re.compile(r"\bAIza[0-9A-Za-z\-_]{30,}"), "unknown", "medium", "google-api-key",
     "Google API key (often a referrer-restricted Firebase/Maps BROWSER key) — check whether "
     "it is unrestricted and what APIs it enables before rating it (hunt-cloud)."),
]


def _norm(value: str) -> str:
    if not isinstance(value, str):
        return ""
    return value.strip().strip("'\"` ").strip()


def _secret_value(rec: dict):
    data = rec.get("data") if isinstance(rec, dict) else None
    if isinstance(data, dict):
        for k in ("raw", "secret", "match", "key", "value", "token"):
            v = data.get(k)
            if isinstance(v, str) and v:
                return v
        vals = [v for v in data.values() if isinstance(v, str)]
        return max(vals, key=len) if vals else None
    if isinstance(data, str):
        return data
    return None


def _classify_value(value: str, kind: str):
    """Return (visibility, severity, label, weaponization) for a secret value."""
    blob = f"{value or ''} {kind or ''}"
    for rx, vis, sev, label, weap in _RULES:
        if rx.search(blob):
            return vis, sev, label, weap
    return "unknown", None, kind or "secret", ""


def classify_secrets(records: list, severity_floor: str = "medium") -> list:
    """Dedupe by normalized value, merge detectors, and classify each secret."""
    groups: dict = {}
    order: list = []
    for rec in records or []:
        if not isinstance(rec, dict):
            continue
        value = _secret_value(rec)
        nv = _norm(value) if value else None
        key = nv or id(rec)                      # no value -> keep distinct
        g = groups.get(key)
        if g is None:
            groups[key] = dict(rec)
            groups[key]["detectors"] = []
            order.append(key)
            g = groups[key]
        det = rec.get("detector")
        if det and det not in g["detectors"]:
            g["detectors"].append(det)
        # prefer a record that carries a line / richer context
        if rec.get("line") and not g.get("line"):
            g["line"] = rec["line"]
        if rec.get("context") and not g.get("context"):
            g["context"] = rec["context"]

    out = []
    for key in order:
        g = groups[key]
        value = _secret_value(g) or ""
        vis, sev, label, weap = _classify_value(value, g.get("kind") or "")
        g["visibility"] = vis
        if sev is not None:
            g["severity"] = sev
        else:
            g.setdefault("severity", severity_floor)
        g["secret_label"] = label
        if weap:
            g["weaponization"] = weap
        g["use_hint"] = (
            "This key is meant to ship — treat as public; no action unless it is unexpectedly "
            "privileged." if vis == "public" else
            f"Find the request in {g.get('source_file') or 'this file'} that sends it in a "
            f"key/authorization field; (Operator Gate) test it against that service.")
        if not g.get("detectors"):
            g["detectors"] = [g.get("detector", "jsluice")]
        out.append(g)
    return out

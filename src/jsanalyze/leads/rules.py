"""URL classification table + helpers (pure functions, no I/O).

``classify_url(rec)`` maps a jsluice ``urls`` record to a lead class (or None for
a boring endpoint). It inspects the record's ``url`` string case-insensitively,
plus the ``queryParams`` / ``bodyParams`` arrays jsluice provides.

Precedence (first match wins), chosen so the most specific / highest-impact
class is preferred:

    bfla-candidate  >  graphql-candidate  >  auth-endpoint  >  idor-candidate  >  api-version

Rationale:
  * BFLA is the highest-impact (function-level authz, severity_hint high) and a
    privileged path like ``/admin`` dominates any id/version token also present
    (e.g. ``/admin/users/123`` -> bfla, not idor).
  * GraphQL is a single, unambiguous endpoint that owns a dedicated skill, so a
    ``/graphql`` path should route there regardless of other tokens.
  * Auth surfaces outrank a generic id/version signal on the same path
    (e.g. ``/auth/token/123`` -> auth-endpoint).
  * ``/internal`` appears in both the BFLA and the api-version signal lists; BFLA
    is checked first, so ``/internal`` always resolves to bfla-candidate (the
    api-version ``/internal`` entry is intentionally shadowed).

Not every URL is a lead: a plain endpoint returns None (it is still counted as an
endpoint elsewhere in the pipeline).
"""

from __future__ import annotations

import re

__all__ = ["classify_url", "NEXT_STEP", "CLASS_META"]

# class -> (suggested_skill, confidence, severity_hint)
CLASS_META = {
    "idor-candidate": ("hunt-idor", "medium", "medium"),
    "bfla-candidate": ("hunt-api", "medium", "high"),
    "auth-endpoint": ("hunt-auth-bypass", "medium", "medium"),
    "graphql-candidate": ("hunt-graphql", "medium", "medium"),
    "api-version": ("hunt-api", "low", "low"),
}

# Per-class "what to do next" text. Also carries the non-URL lead classes
# emitted by the lead engine so every lead can source its next_step from here.
NEXT_STEP = {
    "idor-candidate": (
        "Two accounts A/B: request this object with account B using A's identifier "
        "(and the reverse), with a negative control. A cross-account read/write is "
        "the proof — a single account proves nothing. (hunt-idor)"
    ),
    "bfla-candidate": (
        "Invoke this privileged function as a low-privilege role; the action "
        "executing (vs 403 for the control account) proves BFLA. (hunt-api)"
    ),
    "auth-endpoint": (
        "Attack the mechanism itself: token forgery, reset race/leak, OAuth "
        "redirect_uri/state, MFA bypass. Large-scale OTP/reset brute = Operator "
        "Gate. (hunt-auth-bypass)"
    ),
    "graphql-candidate": (
        "Fingerprint the engine, attempt introspection + bypasses, then test "
        "per-resolver authz (node(id:)) and batching/aliasing. If introspection is "
        "open (Operator Gate), visualize the schema with GraphQL Voyager. (hunt-graphql)"
    ),
    "api-version": (
        "Compare this old/internal version against the current one for controls "
        "dropped on the legacy surface (authz, rate-limit, hidden fields). (hunt-api)"
    ),
    "secret-location": (
        "Verify the secret is live and map its blast radius to a takeover "
        "(session/JWT forgery, cloud access, DB creds). Validating a cloud key "
        "against the provider = Operator Gate. (hunt-cloud / hunt-secrets-disclosure)"
    ),
    "xss-sink": (
        "In a browser, drive attacker-controlled input into this sink and capture "
        "execution (dialog or DOM marker). A reflection is not proof. (hunt-xss)"
    ),
    "postmessage-listener": (
        "From an attacker origin, postMessage into this listener and reach the "
        "named sink with a browser PoC (execution captured). (hunt-xss)"
    ),
    "postmessage-sender": (
        "This postMessage targets origin '*', leaking its payload to any framing/opener "
        "origin. Receive it from an attacker origin; if it carries a token/OAuth code that "
        "is an account-takeover path. (hunt-xss / hunt-auth-bypass)"
    ),
    "postmessage-origin-bypass": (
        "The origin check is weak (indexOf/startsWith/endsWith/includes/substring). From an "
        "attacker origin whose URL satisfies that weak check, postMessage into the listener "
        "and reach the sink. (hunt-xss)"
    ),
    "sourcemap": (
        "Operator-gated: fetching the .map from the target is out-of-default-scope. "
        "If authorized, recover sourcesContent for routes/secrets. (hunt-js-analysis)"
    ),
}

# RFC-4122-ish UUID anywhere in the URL.
_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE
)
# "/v0" as an old version: not followed by another digit (so /v0, /v0/, /api/v0).
_V0_RE = re.compile(r"/v0(?![0-9])", re.IGNORECASE)
# "role" as a standalone token (avoids false hits inside parole/payroll/...).
_ROLE_RE = re.compile(r"(?<![a-z])role(?![a-z])", re.IGNORECASE)

# id-ish parameter names (compared lower-cased against param names).
_ID_PARAMS = {"id", "user_id", "userid", "orderid", "account", "uuid"}

_SCHEME_AUTHORITY_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://[^/]*(/.*)?$")


def _strip_authority(url: str) -> str:
    """Drop the fragment and, for absolute URLs, the scheme://authority prefix,
    leaving just the path (+ query). Relative URLs pass through unchanged."""
    s = url.split("#", 1)[0]
    m = _SCHEME_AUTHORITY_RE.match(s)
    if m:
        s = m.group(1) or "/"
    return s


def _path_and_query(url: str):
    s = _strip_authority(url)
    if "?" in s:
        path, query = s.split("?", 1)
    else:
        path, query = s, ""
    return path, query


def _query_param_names(query: str):
    names = []
    for part in re.split(r"[&;]", query):
        if not part:
            continue
        name = part.split("=", 1)[0].strip()
        if name:
            names.append(name)
    return names


def _mk(cls: str, note: str) -> dict:
    skill, confidence, severity_hint = CLASS_META[cls]
    return {
        "cls": cls,
        "suggested_skill": skill,
        "confidence": confidence,
        "severity_hint": severity_hint,
        "notes": note,
    }


def classify_url(rec: dict):
    """Classify a jsluice ``urls`` record.

    Returns ``{cls, suggested_skill, confidence, severity_hint, notes}`` for an
    interesting endpoint, or ``None`` for a boring one.
    """
    url = rec.get("url") or ""
    if not url:
        return None

    low = url.lower()
    path, query = _path_and_query(url)
    path_low = path.lower()

    # Parameter names: query string of the URL + jsluice's own arrays.
    params = {n.lower() for n in _query_param_names(query)}
    for n in rec.get("queryParams") or []:
        if isinstance(n, str):
            params.add(n.lower())
    for n in rec.get("bodyParams") or []:
        if isinstance(n, str):
            params.add(n.lower())

    # 1) BFLA — privileged function / role management (highest impact).
    bfla_hit = next((t for t in ("/admin", "/internal", "/manage") if t in path_low), None)
    if bfla_hit is None and "promote" in low:
        bfla_hit = "promote"
    if bfla_hit is None and _ROLE_RE.search(url):
        bfla_hit = "role"
    if bfla_hit is None and "role" in params:
        bfla_hit = "param:role"
    if bfla_hit is not None:
        return _mk("bfla-candidate", f"privileged path/action signal ({bfla_hit})")

    # 2) GraphQL endpoint.
    if "/graphql" in path_low:
        return _mk("graphql-candidate", "GraphQL endpoint (/graphql)")

    # 3) Authentication surface.
    auth_hit = next(
        (
            t
            for t in (
                "/auth",
                "/oauth",
                "/login",
                "/token",
                "/reset",
                "/verify",
                "/password",
                "/mfa",
                "/otp",
            )
            if t in path_low
        ),
        None,
    )
    if auth_hit is not None:
        return _mk("auth-endpoint", f"auth surface ({auth_hit})")

    # 4) IDOR — a manipulable object identifier.
    idor_reason = None
    if "EXPR" in url:
        idor_reason = "EXPR placeholder (dynamic id in path)"
    elif _UUID_RE.search(url):
        idor_reason = "UUID in URL"
    elif any(seg.isdigit() for seg in path.split("/") if seg):
        idor_reason = "all-digit path segment"
    else:
        id_params = params & _ID_PARAMS
        if id_params:
            idor_reason = f"id-ish param ({', '.join(sorted(id_params))})"
    if idor_reason:
        return _mk("idor-candidate", idor_reason)

    # 5) Old / internal API version (lowest impact).
    version_hit = None
    if _V0_RE.search(path):
        version_hit = "/v0"
    else:
        version_hit = next((t for t in ("/beta", "/legacy", "/internal") if t in path_low), None)
    if version_hit:
        return _mk("api-version", f"old/internal API version ({version_hit})")

    return None

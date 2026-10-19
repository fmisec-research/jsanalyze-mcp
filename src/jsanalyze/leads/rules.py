"""Per-class ``next_step`` text for leads (pure data, no I/O).

URL/endpoint CLASSIFICATION lives in ``jsanalyze.analyzers.endpoints.classify_endpoint``
(segment-based, ``string_kind``-gated, with the request shape) — that is the single
source of truth. This module only holds the human-readable "what to prove next" text
keyed by lead class, shared by the lead engine. (The older ``classify_url`` table that
used to live here was unused dead code and has been removed to avoid a second, drifting
classifier — see critique point 3/13.)
"""

from __future__ import annotations

__all__ = ["NEXT_STEP"]

# Per-class "what to do next" text. The lead engine sources each lead's next_step from
# here (endpoint classes, sinks, postMessage, secrets, sourcemaps); the newer classes
# (endpoint-hidden/-unverified, token-storage, graphql-operation, csp-endpoint,
# framework-gadget, websocket) carry lead-specific next_step inline in the engine.
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
    "websocket": (
        "Test CSWSH (cross-origin handshake carrying the victim cookie) and whether authz "
        "is enforced per-message vs only at the handshake. (hunt-websocket)"
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

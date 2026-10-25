"""Turn a :class:`Triaged` bundle into an ordered list of DISTINCT lead candidates.

A lead is a candidate, never a finding. The triage analyzers already gated the noise
(vendor/constant/non-tainted sinks, garbage endpoints, split postMessage families), so
here we mint one lead per surviving, de-duplicated signal — not one per raw jsluice row.
Every lead names the hunt-* skill that would PROVE it.

v2 (critique point 10): leads are ordered by a composite :func:`~jsanalyze.leads.scoring.
score_lead` (first-party / in-scope / tainted / not-in-history / id-segment / secret-nearby
up; vendor / string-literal / no-method / listener-without-sink down), not by raw severity;
and every lead carries the fields a model needs to act without re-opening the bundle
(``caller_chain``, ``body_keys``, ``negative_control``, ``experiment``, ``seen_in_history``).

Sources previously computed but never turned into leads are now consumed (points 5/8/9):
SPA routes with no fetch equivalent -> ``endpoint-hidden``; token/id-ish client storage ->
auth/idor leads; GraphQL operations -> ``graphql-operation``; external ``.map`` refs ->
``sourcemap``; and endpoints absent from the captured traffic -> ``endpoint-unverified``.
"""

from __future__ import annotations

import json

from jsanalyze.analyzers.endpoints import classify_endpoint
from jsanalyze.leads.rules import NEXT_STEP
from jsanalyze.leads.scoring import ScoreInputs, score_lead
from jsanalyze.models import Lead
from jsanalyze.party import LIBRARY_COMMENT_HOSTS
from jsanalyze.utils.normalize import normalize_path
from jsanalyze.utils.workspace import load_config, mask_data

__all__ = ["build_leads"]

_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}

_CLOUD_PREFIXES = ("AKIA", "ASIA")
_CLOUD_TOKENS = ("aws", "amazon", "gcp", "azure", "service_account",
                 "serviceaccount", "service-account")

# token-ish / id-ish client-storage key names (critique point 8)
_TOKEN_KEYS = ("token", "jwt", "access_token", "accesstoken", "refresh", "id_token",
               "idtoken", "session", "sess", "bearer", "auth", "apikey", "api_key",
               "secret", "credential")
_ID_KEYS = ("rid", "uid", "userid", "user_id", "account", "accountid", "account_id",
            "tenant", "org", "orgid", "customer", "customerid", "member")

# body/query fields that change AUTHORIZATION or MONEY — the only ones worth a lead when
# the bundle can send them but the operator never did (critique round 3, point 1). A field
# like `locale`/`page` stays in the artifact. Matched case-insensitively.
_AUTHZ_MONEY_KEYS = frozenset({
    "role", "roles", "isadmin", "is_admin", "admin", "superuser", "is_superuser",
    "issuperuser", "permission", "permissions", "scope", "scopes", "grant", "grants",
    "owner", "owner_id", "ownerid", "user_id", "userid", "uid", "account", "account_id",
    "accountid", "tenant", "tenant_id", "tenantid", "org", "org_id", "orgid",
    "plan", "tier", "subscription", "price", "amount", "cost", "total", "balance",
    "credit", "discount", "coupon", "qty", "quantity", "status", "state", "verified",
    "approved", "enabled", "active",
    # round 4: account-takeover / tenant-pivot fields that frequently pay
    "email", "password", "redirect", "redirect_uri", "redirect_url", "return_to",
    "returnurl", "return_url", "callback", "callback_url", "next", "group_id", "groupid",
    "company_id", "companyid", "workspace_id", "workspaceid", "team_id", "teamid",
})
# money fields whose VALUE coming from the client at all (even if sent) is a business-logic
# smell — the server, not the browser, should price things (round 5 pt 18).
_MONEY_KEYS = frozenset({"price", "unit_price", "unitprice", "total", "subtotal", "amount",
                         "cost", "discount", "qty", "quantity", "points", "credit", "balance"})
_UNVERIFIED_CAP = 15        # big SPAs have hundreds of bundle paths; keep the queue readable
_GQL_UNSENT_CAP = 10


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


def _auth_hint(history) -> str:
    """The replay recipe (round 4, point 5): the auth header / cookie NAMES the operator's
    own requests carried (values stay in auth/, never here). Lets a lead's experiment say
    exactly how to replay instead of a generic sentence."""
    if not isinstance(history, dict):
        return ""
    hdrs = sorted(history.get("auth_headers") or ())
    cks = sorted(history.get("auth_cookies") or ())
    if not hdrs and not cks:
        return ""
    bits = []
    if hdrs:
        bits.append("header(s) " + ", ".join(hdrs[:4]))
    if cks:
        bits.append("cookie(s) " + ", ".join(cks[:4]))
    return "Replay as the operator — send " + " and ".join(bits) + " (values are in auth/, masked here)."


def build_leads(triaged, cfg=None, history=None, scope_hosts=None) -> list[dict]:
    cfg = cfg or load_config()
    mask = cfg.get("mask_secrets_in_leads", True)
    # "the API was exercised" (a non-asset request exists) — NOT merely "some .js was
    # fetched". endpoint-unverified and the +not_in_history boost ride on this, so a
    # JS-only capture no longer paints every bundle path as untested surface (round 2 pt 1).
    api_known = bool((history or {}).get("api_known")) if isinstance(history, dict) else False
    auth_hint = _auth_hint(history)

    secret_files = {s.get("source_file") for s in (getattr(triaged, "secrets", []) or [])
                    if s.get("source_file")}
    # the set of normalized API paths that actually have a request site (for "no fetch
    # equivalent" route detection)
    api_paths = {n.get("norm_path") for n in (getattr(triaged, "endpoints", []) or [])
                 if n.get("string_kind") == "api"}

    pairs: list[tuple[Lead, ScoreInputs]] = []
    pairs += _sink_leads(triaged, secret_files)
    pairs += _pm_leads(triaged, secret_files)
    pairs += _endpoint_leads(triaged, secret_files, api_known, auth_hint)
    pairs += _body_delta_leads(triaged, history, auth_hint)
    pairs += _hidden_route_leads(triaged, api_paths, api_known)
    pairs += _storage_leads(triaged, secret_files)
    pairs += _graphql_leads(triaged)
    pairs += _sourcemap_leads(triaged)
    pairs += _csp_leads(triaged, history, scope_hosts)
    pairs += _note_leads(triaged)
    pairs += _gadget_leads(triaged, secret_files)
    pairs += _secret_leads(triaged, mask, secret_files)
    pairs += _vuln_sink_leads(triaged)
    pairs += _response_leads(triaged, auth_hint)
    pairs += _lib_leads(triaged)
    pairs += _flag_leads(triaged)

    leads: list[Lead] = []
    for ld, si in pairs:
        si.history_known = api_known
        ld.score, ld.score_factors = score_lead(ld, si)
        leads.append(ld)

    # composite score is the queue order; severity/confidence are tie-breakers only
    leads.sort(key=lambda ld: (-ld.score, _SEV_RANK.get(ld.severity_hint, 9),
                               _CONF_RANK.get(ld.confidence, 9)))
    for i, ld in enumerate(leads, 1):
        ld.id = f"lead-{i:04d}"
    return [ld.to_dict() for ld in leads]


# --- DOM-XSS sinks ------------------------------------------------------------
_UNTRACED_CAP = 5            # a React bundle has dozens of untraced dangerouslySetInnerHTML;
                             # keep the queue short — the rest stay in sinks.json for audit.


def _sink_leads(triaged, secret_files):
    out = []
    untraced = []
    for c in getattr(triaged, "sinks", []) or []:
        f, line, src = _first_occ(c)
        extra = f" (+{c['count'] - 1} more)" if c.get("count", 1) > 1 else ""
        chain = c.get("caller_chain") or []
        party = c.get("party", "first")
        if c.get("lead"):
            taint_src = c.get("taint_source") or (chain[0] if chain else "attacker input")
            if c.get("redirect"):
                # a tainted navigation target with no javascript:/data: scheme is an OPEN REDIRECT
                ld = Lead(
                    id="", cls="open-redirect", suggested_skill="hunt-open-redirect",
                    title=f"Open redirect — {c.get('kind')} navigation tainted by {taint_src}",
                    source_file=f, line=line, evidence=src, detector=c.get("detector", "jsluice:sinks"),
                    tainted=True, confidence=c.get("confidence", "medium"),
                    severity_hint="medium",
                    caller_chain=chain,
                    next_step="Attacker input sets a navigation target (location/href/assign). If the "
                              "scheme is NOT validated, point it off-site (open redirect); if the "
                              "scheme is also attacker-controlled, `javascript:` makes it DOM-XSS. "
                              "(hunt-open-redirect)",
                    negative_control="A same-origin/relative-only target that rejects external schemes "
                                     "is not a finding.",
                    experiment=f"At {f}:{line}, set the tainted source ({taint_src}) to an external "
                               f"https URL and confirm navigation off-origin; then try `javascript:` "
                               f"for XSS.",
                    notes=f"party={c.get('party')}; occurrences={c.get('count')}{extra}; url-class sink.",
                )
                out.append((ld, ScoreInputs(party=party, in_scope=True, secret_nearby=f in secret_files)))
                continue
            ld = Lead(
                id="", cls="xss-sink", suggested_skill="hunt-xss",
                title=f"DOM-XSS {c.get('kind')} [{c.get('sink_class')}] tainted by {taint_src}",
                source_file=f, line=line, evidence=src, detector=c.get("detector", "jsluice:sinks"),
                tainted=True, confidence=c.get("confidence", "medium"),
                severity_hint=c.get("severity_hint", "high"),
                caller_chain=chain,
                next_step=NEXT_STEP["xss-sink"],
                negative_control="A benign value in the same source must NOT execute; only the "
                                 "attacker-controlled payload does.",
                experiment=f"In a browser, set the tainted source ({taint_src}) to a JS payload "
                           f"and confirm execution (dialog/DOM marker) at {f}:{line}.",
                notes=f"party={c.get('party')}; occurrences={c.get('count')}{extra}.",
            )
            out.append((ld, ScoreInputs(party=party, in_scope=True,
                                        secret_nearby=f in secret_files)))
            continue
        # an untraced FIRST/THIRD-party html/js sink is a LOW audit lead, NOT silence — but
        # ONLY when the tracer got somewhere (caller_chain non-empty), and CAPPED per run, or a
        # React bundle's dozens of dangerouslySetInnerHTML would flood the queue (round 3 pt 2).
        elif (c.get("untraced") and party != "vendor" and c.get("sink_class") in ("html", "js")
              and chain):
            untraced.append((c, f, line, src, extra, chain, party))

    # keep the strongest few untraced sinks (longest chain first = most worth a human look)
    untraced.sort(key=lambda t: (-len(t[5]), -(t[0].get("count") or 1)))
    for c, f, line, src, extra, chain, party in untraced[:_UNTRACED_CAP]:
        ld = Lead(
            id="", cls="sink-untraced", suggested_skill="hunt-xss",
            title=f"Untraced {c.get('kind')} [{c.get('sink_class')}] — argument not tied to a source",
            source_file=f, line=line, evidence=src,
            detector=c.get("detector", "jsluice:sinks"),
            tainted=False, confidence="low", severity_hint="low",
            caller_chain=chain,
            next_step="A first-party HTML/JS sink whose input the bounded tracer could not tie to a "
                      "source — confirm by hand whether attacker input reaches it (it may arrive "
                      "from another chunk the tracer can't cross). (hunt-xss)",
            negative_control="Not XSS unless an attacker-controlled value actually reaches this "
                             "argument; a purely internal value is not a finding.",
            experiment=f"At {f}:{line}, read what feeds `{c.get('kind')}`; if it is reachable from "
                       f"location/postMessage/storage (possibly via another file), build the browser "
                       f"PoC — else drop it.",
            notes=(f"party={party}; occurrences={c.get('count')}{extra}; "
                   + (f"the sink uses the parameter `{c.get('anon_param')}` of an ANONYMOUS function "
                      f"— its caller is in another chunk and cannot be named (minify limit), so the "
                      f"trace stops here; "
                      if c.get("anon_param")
                      else f"chain breaks at a file boundary — helper `{c.get('crossfile_break')}()` "
                           f"is not in this capture (capture its chunk to continue the trace); "
                      if c.get("crossfile_break") else "tracer is single-file (no cross-chunk); ")
                   + f"{len(untraced)} untraced sinks total, showing top {_UNTRACED_CAP}."),
        )
        out.append((ld, ScoreInputs(party=party, in_scope=True, secret_nearby=f in secret_files)))
    return out


# --- postMessage --------------------------------------------------------------
def _pm_leads(triaged, secret_files):
    out = []
    for r in getattr(triaged, "postmessage", []) or []:
        if not r.get("lead"):
            continue
        cls = r.get("pm_class", "postmessage-listener")
        reaches = r.get("reaches_sinks")
        signal = bool(reaches) or bool(r.get("data_flow_signal"))
        note = f"party={r.get('party')}; originChecked={r.get('origin_checked')}"
        if r.get("wildcard_target"):
            note += "; targetOrigin=*"
        if reaches:
            note += f"; reaches sinks {reaches}"
        if r.get("data_flow_signal"):
            note += f"; handler writes event.data to {r.get('data_flow_signal')}"
        detector = "jsluice:postmessage" if cls.startswith("postmessage") else f"scan:{r.get('kind')}"
        default_step = r.get("note") or NEXT_STEP.get(cls, NEXT_STEP["postmessage-listener"])
        ld = Lead(
            id="", cls=cls, suggested_skill=r.get("suggested_skill", "hunt-xss"),
            title=f"{cls} ({r.get('kind')})",
            source_file=r.get("file", ""), line=r.get("line"), evidence=r.get("source", ""),
            detector=detector, confidence=r.get("confidence", "medium"),
            severity_hint=r.get("severity_hint", "medium"),
            caller_chain=([f"event.data → {r.get('data_flow_signal')}"] if r.get("data_flow_signal")
                          else (reaches or [])),
            next_step=default_step,
            negative_control="A postMessage from a DISALLOWED origin must be ignored; if the "
                             "handler acts on it regardless, the origin check is the bug."
                             if cls.startswith("postmessage") else
                             "The cross-context channel must not carry data that changes a trust decision.",
            experiment=("From an attacker origin, postMessage a payload into this listener and "
                        f"confirm it reaches {r.get('data_flow_signal') or reaches} "
                        if signal and cls.startswith("postmessage")
                        else (r.get("note") or "Map where the message data flows before investing.")),
            notes=note + ".",
        )
        out.append((ld, ScoreInputs(party=r.get("party", "first"), in_scope=True,
                                    pm_has_signal=signal, secret_nearby=r.get("file") in secret_files)))
    return out


# --- endpoints (classified) + the history delta -------------------------------
def _endpoint_leads(triaged, secret_files, api_known, auth_hint=""):
    out = []
    unverified = []                              # capped separately (round 5 pt 21)
    seen_ep = set()
    for n in getattr(triaged, "endpoints", []) or []:
        info = classify_endpoint(n)
        src_file = (n.get("where_found") or "").split(":")[0]
        in_hist = n.get("seen_in_history")
        has_id = _has_id_shape(n)
        if info:
            cls, skill, conf, sev, why = info
            key = (cls, n.get("method"), n.get("norm_path"))
            if key in seen_ep:
                continue
            seen_ep.add(key)
            ld = _mk_endpoint_lead(n, cls, skill, conf, sev, why, src_file, in_hist, auth_hint)
            out.append((ld, ScoreInputs(
                party=n.get("party", "first"), in_scope=n.get("in_scope"),
                call_type=n.get("call_type", ""), has_id_segment=has_id,
                secret_nearby=src_file in secret_files, history_known=api_known)))
            continue
        # not a classified class, but a first-party in-scope API endpoint that was
        # NEVER exercised in the captured traffic is untested surface (critique point 2).
        # Requires REAL api traffic (api_known) — a JS-only capture claims nothing.
        if (api_known and in_hist is False and n.get("string_kind") == "api"
                and n.get("party") == "first" and n.get("in_scope") is not False
                and n.get("fetchable")):
            key = ("endpoint-unverified", n.get("method"), n.get("norm_path"))
            if key in seen_ep:
                continue
            seen_ep.add(key)
            ld = _mk_endpoint_lead(
                n, "endpoint-unverified", "hunt-api", "low", "low",
                "in the bundle but absent from captured traffic", src_file, in_hist, auth_hint)
            si = ScoreInputs(
                party="first", in_scope=n.get("in_scope"), call_type=n.get("call_type", ""),
                has_id_segment=has_id, secret_nearby=src_file in secret_files,
                history_known=api_known)
            # rank: a privileged/auth path or one with a body/id first, plain reads last
            priv = bool(n.get("body_keys")) or has_id or any(
                s in (n.get("norm_path") or "").lower() for s in _PRIV_ROUTE_HINTS)
            unverified.append((priv, ld, si))
    unverified.sort(key=lambda t: (not t[0],))
    out += [(ld, si) for _p, ld, si in unverified[:_UNVERIFIED_CAP]]
    return out


def _mk_endpoint_lead(n, cls, skill, conf, sev, why, src_file, in_hist, auth_hint=""):
    ev = f"{n.get('method') or ''} {n.get('path')}".strip()
    note = f"{why}; party={n.get('party')}; in_scope={n.get('in_scope')}; kind={n.get('string_kind')}"
    if n.get("dynamic"):
        note += "; dynamic(EXPR)"
    if in_hist is not None:
        note += f"; seen_in_history={in_hist}"
    body = n.get("body_keys") or []
    neg = ("Account B must get 403/404 (not the object) when replaying A's id — a negative "
           "control proves isolation." if cls == "idor-candidate" else
           "A low-privilege role must be refused (403); if the action executes, authz is missing."
           if cls in ("bfla-candidate", "endpoint-hidden") else
           "The control (current/authorized path or role) must behave differently.")
    exp = _endpoint_experiment(cls, n, body)
    if auth_hint:
        exp += " " + auth_hint
    return Lead(
        id="", cls=cls, suggested_skill=skill, title=f"{cls} — {ev}",
        source_file=src_file, line=n.get("line"), evidence=ev,
        detector=f"{n.get('detector', 'jsluice')}:urls", confidence=conf, severity_hint=sev,
        method=n.get("method", ""), body_keys=body, seen_in_history=in_hist,
        next_step=NEXT_STEP.get(cls, "Map this endpoint's authz against two accounts/roles. (hunt-api)"),
        negative_control=neg, experiment=exp, notes=note + ".")


def _endpoint_experiment(cls, n, body):
    ev = f"{n.get('method') or 'GET'} {n.get('path')}"
    bk = f" body={{{', '.join(body)}}}" if body else ""
    if cls == "idor-candidate":
        return f"Replay `{ev}`{bk} from account B using account A's identifier (+ reverse); a cross-account read/write is the proof."
    if cls in ("bfla-candidate", "endpoint-hidden"):
        return f"Invoke `{ev}`{bk} as a low-privilege role; execution (vs 403 for control) proves BFLA."
    if cls == "auth-endpoint":
        return f"Attack the mechanism at `{ev}` (token forgery / reset race / OAuth redirect_uri)."
    if cls == "graphql-candidate":
        return f"Fingerprint + attempt introspection at `{ev}`, then per-resolver authz (node(id:))."
    if cls == "websocket":
        return f"Test CSWSH on `{ev}` (cross-origin handshake with the victim cookie) and per-message authz."
    if cls == "endpoint-unverified":
        return f"Request `{ev}`{bk} (in-scope) — it was never exercised; map its authz vs two accounts."
    return f"Exercise `{ev}`{bk} and compare the authorized vs unauthorized response."


def _has_id_shape(n) -> bool:
    if n.get("dynamic"):
        return True
    segs = [s for s in (n.get("norm_path") or "").split("/") if s]
    return "{id}" in segs


# --- body/query/GraphQL-op delta vs the request the operator ACTUALLY sent ----
def _body_delta_leads(triaged, history, auth_hint=""):
    """Fields the BUNDLE can send that were NEVER in the captured traffic (round 3 pt 1).

    This is the one signal a crawler/other JS tool cannot reproduce: it joins the call-site
    ``body_keys``/``query`` from the JS with the body the OPERATOR actually sent (now parsed
    from the Burp ``<request>`` / HAR postData). An authz/money field present in the bundle's
    call but absent from every sent request to that path = an untested mass-assignment / price
    / tenant vector. GraphQL operations in the bundle never seen in a sent POST become leads
    too (one POST /graphql no longer marks every mutation 'exercised')."""
    out = []
    if not isinstance(history, dict):
        return out
    sent = history.get("sent") or {}
    if not sent:
        return out
    seen = set()
    for n in getattr(triaged, "endpoints", []) or []:
        host, npath = n.get("host") or "", n.get("norm_path") or ""
        entry = sent.get((host, npath)) or sent.get(("", npath))
        if not entry:
            continue                                   # path never sent -> endpoint-unverified's job
        jbody = {k.lower() for k in (n.get("body_keys") or [])}
        jquery = {q.lower() for q in (n.get("query") or [])}
        sent_body_lower = {s.lower() for s in entry["body"]}
        # a money field the CLIENT sends (even if the operator already did) = price/qty tampering
        money_sent = sorted({k for k in jbody if k in _MONEY_KEYS and k in sent_body_lower})
        if money_sent:
            mkey = (n.get("norm_path"), "money", tuple(money_sent))
            if mkey not in seen:
                seen.add(mkey)
                ev = f"{n.get('method') or ''} {n.get('path')}".strip()
                out.append((Lead(
                    id="", cls="client-controlled-value", suggested_skill="hunt-business-logic",
                    title=f"Client sets money field {money_sent} on {ev}",
                    source_file=(n.get("where_found") or "").split(":")[0], line=n.get("line"),
                    evidence=ev, detector="history:body-delta", confidence="low", severity_hint="medium",
                    method=n.get("method", ""), body_keys=money_sent, seen_in_history=True,
                    next_step="The browser submits a price/quantity/amount the server should own — "
                              "tamper it on your OWN order and see if the backend trusts the client "
                              "value (under-charge / over-credit). (hunt-business-logic)",
                    negative_control="The server must recompute/validate the amount; if it bills the "
                                     "client-sent value, that is the bug.",
                    experiment=(f"Replay `{ev}` with {money_sent} set to an advantageous value on your "
                                f"own object; a persisted price/total that matches your input proves it."
                                + (" " + auth_hint if auth_hint else "")),
                    notes=f"party={n.get('party')}; money field is client-supplied.",
                ), ScoreInputs(party=n.get("party", "first"), in_scope=n.get("in_scope"))))
        unsent_body = sorted({k for k in jbody if k in _AUTHZ_MONEY_KEYS
                              and k not in sent_body_lower})
        unsent_query = sorted({q for q in jquery if q in _AUTHZ_MONEY_KEYS
                               and q not in {s.lower() for s in entry["query"]}})
        if not (unsent_body or unsent_query):
            continue
        key = (npath, tuple(unsent_body), tuple(unsent_query))
        if key in seen:
            continue
        seen.add(key)
        method = n.get("method") or ""
        ev = f"{method} {n.get('path')}".strip()
        fields = unsent_body + [f"?{q}" for q in unsent_query]
        ld = Lead(
            id="", cls="body-field-unsent", suggested_skill="hunt-api",
            title=f"Bundle can send {fields} to {ev} — never sent in captured traffic",
            source_file=(n.get("where_found") or "").split(":")[0], line=n.get("line"),
            evidence=ev, detector="history:body-delta", confidence="low", severity_hint="medium",
            method=method, body_keys=unsent_body, seen_in_history=True,
            next_step="The client code builds this request with an authorization/money field the "
                      "operator never submitted — replay it WITH that field (mass-assignment/BOPLA, "
                      "price/quantity tamper, tenant/owner swap) and compare vs the control. (hunt-api)",
            negative_control="The server must ignore/reject the injected field; a changed object, "
                             "role, price or tenant in the response is the bug.",
            experiment=(f"Replay `{ev}` adding {fields} (start on your OWN object); a persisted change "
                        f"to a field you should not control proves it."
                        + (" " + auth_hint if auth_hint else "")),
            notes=f"party={n.get('party')}; sent_body={sorted(entry['body'])[:8]}; "
                  f"bundle_body={sorted(jbody)[:8]}"
                  + (f"; auth: {sorted(entry.get('auth_headers') or ())[:3]}"
                     f"{'+cookies' if entry.get('cookies') else ''}" if entry.get('auth_headers')
                     or entry.get('cookies') else "") + ".",
        )
        out.append((ld, ScoreInputs(party=n.get("party", "first"), in_scope=n.get("in_scope"),
                                    has_id_segment=_has_id_shape(n))))

    # GraphQL operations in the bundle that were never seen in a sent GraphQL POST
    sent_gql = set()
    for e in sent.values():
        sent_gql.update(x.lower() for x in e.get("gql", set()))
    # persisted queries (APQ) are sent by hash + usually an operationName — the name is captured
    # from traffic and lands in sent_gql above, so a named op still matches. The `@persisted`
    # sentinel means only that at least one HASH-ONLY (anonymous) send existed that we could not
    # name. Round 5 suppressed the WHOLE delta on that sentinel, which silenced named mutations the
    # bundle has but never sent; now it merely CAVEATS each lead (round 6 pt 8).
    persisted = "@persisted" in sent_gql
    sent_gql.discard("@persisted")
    gql_pairs = []
    if sent_gql or persisted:                          # GraphQL exercised by name OR by hash
        for g in getattr(triaged, "graphql", []) or []:
            if g.get("party") == "third":
                continue
            name = (g.get("operationName") or "").strip()
            if name and name.lower() in sent_gql:
                continue                               # this named op WAS sent
            op = g.get("operation") or "query"
            # an anonymous operation can't be matched to traffic by name — still surface it
            # (round 4 pt 3), flagged, rather than dropping it on `if not name`.
            display = name or f"(anonymous {op})"
            key = ("gql", display, g.get("file"))
            if key in seen:
                continue
            seen.add(key)
            anon_note = "" if name else " — anonymous op, cannot be matched to traffic by name"
            persisted_note = (" — persisted queries (hash-only sends) were also observed; confirm "
                              "this op's sha256 is not already registered before treating it as "
                              "untested" if persisted else "")
            ld = Lead(
                id="", cls="graphql-unsent", suggested_skill="hunt-graphql",
                title=f"GraphQL {op} {display} is in the bundle but was never sent",
                source_file=g.get("file", ""), line=g.get("line"),
                evidence=f"{op} {display}", detector="history:gql-delta",
                confidence="low", severity_hint="medium" if op != "query" else "low",
                body_keys=[v.lstrip("$") for v in (g.get("variables") or [])], seen_in_history=False,
                next_step="GraphQL was exercised but THIS operation never was — a POST /graphql in "
                          "traffic does not mean every operation is tested. Send it and test its "
                          "per-resolver authz with two accounts. (hunt-graphql)",
                negative_control="With account B's token the operation must not read/mutate A's object.",
                experiment=(f"Send `{op} {display}` authenticated as B using A's id in its variables; a "
                            f"cross-account effect proves BOLA/BFLA on an untested operation."
                            + (" " + auth_hint if auth_hint else "")),
                notes=f"party={g.get('party')}; sent_ops={sorted(sent_gql)[:8]}{anon_note}{persisted_note}.",
            )
            gql_pairs.append((op != "query", ld,  # mutation/subscription rank first
                              ScoreInputs(party=g.get("party", "first"), in_scope=True,
                                          has_id_segment=any("id" in v.lower() for v in (g.get("variables") or [])))))
    # cap the unsent-GraphQL leads so a big schema doesn't flood the queue (round 5 pt 21)
    gql_pairs.sort(key=lambda t: (not t[0],))
    out += [(ld, si) for _mut, ld, si in gql_pairs[:_GQL_UNSENT_CAP]]
    return out


# --- hidden SPA routes (no fetch equivalent, not in history) ------------------
_PRIV_ROUTE_HINTS = ("admin", "internal", "manage", "settings", "billing", "account",
                     "dashboard", "debug", "superuser", "staff", "console", "config")


def _hidden_route_leads(triaged, api_paths, api_known):
    out = []
    seen = set()
    for r in getattr(triaged, "routes", []) or []:
        if r.get("party") != "first":
            continue
        path = r.get("path") or ""
        if not path.startswith("/"):
            continue                              # bare Angular segment: too noisy alone
        npath = normalize_path(path)
        if npath in api_paths:
            continue                              # has a fetch equivalent -> covered elsewhere
        priv = any(h in npath.lower() for h in _PRIV_ROUTE_HINTS)
        # surface a route only when it is privileged-looking, or (if we have API traffic)
        # it was never navigated — otherwise plain pages would flood the queue.
        if not priv and not api_known:
            continue
        key = npath
        if key in seen:
            continue
        seen.add(key)
        conf = "medium" if priv else "low"
        sev = "medium" if priv else "low"
        ld = Lead(
            id="", cls="endpoint-hidden", suggested_skill="hunt-api",
            title=f"Hidden route — {path}" + (f" [{r.get('component')}]" if r.get("component") else ""),
            source_file=r.get("file", ""), line=r.get("line"), evidence=path,
            detector=f"routes:{r.get('kind', 'spa')}", confidence=conf, severity_hint=sev,
            seen_in_history=False if api_known else None,
            next_step="A first-party route with no fetch equivalent often fronts a privileged "
                      "view/API not in your traffic — drive it and test the backing calls as a "
                      "low-privilege role. (hunt-api)",
            negative_control="A low-privilege role must be denied the view/API this route fronts.",
            experiment=f"Navigate `{path}` in an authenticated low-priv session; capture the API "
                       f"calls it makes and test their authz.",
            notes=f"party=first; kind={r.get('kind')}; privileged={priv}.",
        )
        out.append((ld, ScoreInputs(party="first", in_scope=True, has_id_segment="{id}" in npath,
                                    history_known=api_known)))
    return out


# --- client storage: token / id-ish writes (critique point 8) -----------------
def _storage_leads(triaged, secret_files):
    out = []
    seen = set()
    for s in getattr(triaged, "storage", []) or []:
        if s.get("party") == "vendor":
            continue
        key = (s.get("key") or "")
        kl = key.lower()
        is_token = any(t in kl for t in _TOKEN_KEYS)
        is_id = (not is_token) and any(t == kl or kl.endswith("_" + t) or kl.startswith(t + "_")
                                       or kl == t for t in _ID_KEYS)
        if not (is_token or is_id):
            continue
        dk = (s.get("type"), key, s.get("file"))
        if dk in seen:
            continue
        seen.add(dk)
        if is_token:
            cls, skill = "token-storage", "hunt-auth-bypass"
            sev, conf = "medium", "low"
            nxt = ("A token/credential persisted in web storage/cookie is readable by any XSS "
                   "and may be a session artifact — test it for XSS-to-ATO and whether it is a "
                   "bearer you can replay. (hunt-auth-bypass)")
            neg = "The token must be rejected after logout/rotation; if it still authenticates, it is a reusable artifact."
            exp = f"Read `{key}` from {s.get('type')} in a session, then replay it as a bearer/cookie from a clean client."
        else:
            cls, skill = "idor-candidate", "hunt-idor"
            sev, conf = "medium", "low"
            nxt = ("A client-stored identifier is attacker-editable — change it to another "
                   "user's value and see if the app fetches their object. (hunt-idor)")
            neg = "Account B must not receive account A's object when B sets A's identifier."
            exp = f"Overwrite `{key}` in {s.get('type')} with account A's value while logged in as B; watch for cross-account data."
        ld = Lead(
            id="", cls=cls, suggested_skill=skill,
            title=f"Client-stored {'token' if is_token else 'identifier'} ({s.get('type')}: {key})",
            source_file=s.get("file", ""), line=s.get("line"), evidence=s.get("evidence") or key,
            detector="storage", confidence=conf, severity_hint=sev,
            next_step=nxt, negative_control=neg, experiment=exp,
            notes=f"party={s.get('party')}; op={s.get('op')}; stored client-side.",
        )
        out.append((ld, ScoreInputs(party=s.get("party", "first"), in_scope=True,
                                    has_id_segment=is_id, secret_nearby=s.get("file") in secret_files)))
    return out


# --- GraphQL operations (critique point 9) ------------------------------------
def _graphql_leads(triaged):
    out = []
    seen = set()
    for g in getattr(triaged, "graphql", []) or []:
        if g.get("party") == "third":
            continue
        op = g.get("operation") or "query"
        name = g.get("operationName") or ""
        dk = (op, name, g.get("file"))
        if dk in seen:
            continue
        seen.add(dk)
        is_mut = op in ("mutation", "subscription")
        sev = "medium" if is_mut else "low"
        fields = g.get("fields") or []
        variables = g.get("variables") or []
        ld = Lead(
            id="", cls="graphql-operation", suggested_skill="hunt-graphql",
            title=f"GraphQL {op} {name}".strip() + (f" ({', '.join(fields[:4])})" if fields else ""),
            source_file=g.get("file", ""), line=g.get("line"),
            evidence=f"{op} {name} vars={variables} fields={fields[:6]}",
            detector="graphql", confidence="low", severity_hint=sev,
            body_keys=[v.lstrip("$") for v in variables],
            next_step=("Test this operation's per-resolver authz: can another user's object be "
                       "read/mutated via its id variable? Batch/alias it to bypass rate-limit. (hunt-graphql)"),
            negative_control="With account B's token, the operation must NOT return/affect account A's object.",
            experiment=(f"Send `{op} {name}` with account A's id in {variables or 'its variables'} "
                        f"while authenticated as B; a cross-account effect proves BOLA/BFLA."),
            notes=f"party={g.get('party')}; {'mutation' if is_mut else 'query'}.",
        )
        out.append((ld, ScoreInputs(party=g.get("party", "first"), in_scope=True,
                                    has_id_segment=any("id" in v.lower() for v in variables))))
    return out


# --- sourcemaps: external .map refs not recovered (critique point 5) ----------
def _sourcemap_leads(triaged):
    out = []
    seen = set()
    for ref in getattr(triaged, "sourcemaps", []) or []:
        if ref.get("recovered"):
            continue                              # already reconstructed locally -> no lead
        url = ref.get("url") or ""
        if not url or url == "(inline)" or ref.get("inline"):
            continue
        if url in seen:
            continue
        seen.add(url)
        ld = Lead(
            id="", cls="sourcemap", suggested_skill="hunt-js-analysis",
            title=f"Un-recovered sourcemap — {url}",
            source_file=ref.get("from", ""), line=None, evidence=url,
            detector="sourcemaps", confidence="low", severity_hint="low",
            next_step=NEXT_STEP["sourcemap"],
            negative_control="(recon) — a .map only yields leads if it carries sourcesContent "
                             "(original comments/paths/secrets absent from the minified bundle).",
            experiment=f"Operator-gated: if authorized, fetch `{url}` and mine sourcesContent for "
                       f"staging hosts, mock/dummyData paths, comments and secrets not in the bundle.",
            notes=f"external .map referenced but not fetched (fetch = Operator Gate).",
        )
        out.append((ld, ScoreInputs(party="first", in_scope=True)))
    return out


# --- CSP-disclosed hosts (critique point 6) -----------------------------------
_CSP_FRAME_DIRECTIVES = ("frame-src", "child-src", "frame-ancestors")
_BENIGN_CSP_HOSTS = set(LIBRARY_COMMENT_HOSTS) | {
    "google-analytics.com", "googletagmanager.com", "google.com", "gstatic.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "doubleclick.net", "sentry.io",
    "segment.com", "segment.io", "hotjar.com", "intercom.io", "stripe.com",
    "stripe.network", "cloudflare.com", "facebook.net", "facebook.com", "bing.com",
    "recaptcha.net", "cloudflareinsights.com", "newrelic.com", "nr-data.net",
}


def _csp_leads(triaged, history, scope_hosts):
    out = []
    directives = getattr(triaged, "csp", []) or []
    if not directives:
        return out
    scope = {h.lower().lstrip("*.") for h in (scope_hosts or [])}
    hist_hosts = set((history or {}).get("hosts") or []) if isinstance(history, dict) else set()
    ep_hosts = {n.get("host") for n in (getattr(triaged, "endpoints", []) or []) if n.get("host")}
    seen_hosts = hist_hosts | ep_hosts
    seen = set()
    for d in directives:
        host = d.get("host") or ""
        if not host or host in seen:
            continue
        if any(host == b or host.endswith("." + b) for b in _BENIGN_CSP_HOSTS):
            continue                              # a known CDN/analytics host — not a surface
        in_scope = any(host == s or host.endswith("." + s) for s in scope) if scope else None
        directive = d.get("directive", "")
        is_frame = directive in _CSP_FRAME_DIRECTIVES
        # only surface a host that is in-scope/internal OR a framed origin; and prefer
        # ones not already in your endpoints/traffic (otherwise it is already covered)
        if not (in_scope or is_frame):
            continue
        already = host in seen_hosts
        seen.add(host)
        sev = "medium" if (in_scope and not already) else "low"
        if is_frame:
            title = f"CSP {directive} host — {host}"
            nxt = ("A framed/framing origin declared in CSP often fronts an internal console or "
                   "a trusted integration — enumerate it and test cross-frame messaging. (hunt-api)")
            skill = "hunt-api"
        else:
            title = f"CSP {directive} host — {host}"
            nxt = ("A host the app is allowed to call, disclosed by CSP but absent from your "
                   "traffic/bundle — an internal/forgotten API surface. Resolve it and map its "
                   "authz. (hunt-api)")
            skill = "hunt-api"
        ld = Lead(
            id="", cls="csp-endpoint", suggested_skill=skill, title=title,
            source_file="(CSP header)", line=None, evidence=f"{directive} {d.get('source')}",
            detector="csp", confidence="low", severity_hint=sev,
            seen_in_history=(already if (history or {}).get("known") else None),
            next_step=nxt,
            negative_control="If the host is already in your traffic it is not new surface.",
            experiment=f"Resolve `{host}` (in-scope?), probe it directly, and test whether it "
                       f"enforces the same authz as the main app.",
            notes=f"from CSP {directive}; in_scope={in_scope}; already_seen={already}.",
        )
        out.append((ld, ScoreInputs(party="first" if in_scope else "third",
                                    in_scope=in_scope, history_known=bool((history or {}).get("known")))))
    return out


# --- mined source comments (critique point 5) ---------------------------------
def _note_leads(triaged):
    out = []
    seen = set()
    for n in getattr(triaged, "notes", []) or []:
        cat = n.get("category")
        if cat not in ("credential", "internal-host", "mock-path"):
            continue                              # plain dev notes stay in the artifact
        key = (cat, n.get("file"), n.get("text", "")[:60])
        if key in seen:
            continue
        seen.add(key)
        if cat == "credential":
            cls, skill, sev = "secret-location", "hunt-secrets-disclosure", "medium"
            nxt = ("A credential left in an original-source comment (recovered via sourcemap) — "
                   "verify it is live and map its blast radius. (hunt-secrets-disclosure)")
            exp = "Confirm the commented credential still works against its service (Operator Gate to verify)."
            neg = "Only meaningful if the host/credential is reachable & in-scope."
        elif cat == "mock-path":
            # a "mock"/"dummyData"/"fixture" path recovered from source that is actually
            # served in prod returns REAL data — the paying sourcemap-archaeology case.
            cls, skill, sev = "mock-data-path", "hunt-js-analysis", "low"
            nxt = ("A mock/fixture data path named in the recovered source — request it against "
                   "the live origin; if it returns real (not stub) data it is an unguarded data "
                   "exposure. Fetching = Operator Gate. (hunt-js-analysis)")
            exp = (f"Request `{n.get('text')}` on the live host (Operator Gate); real/other-tenant "
                   f"rows (vs static fixture) prove an exposure — then pivot to IDOR on its ids.")
            neg = "Must return only static fixture content; live user/tenant rows = the bug."
        else:
            cls, skill, sev = "endpoint-hidden", "hunt-api", "low"
            nxt = ("A staging/internal host named only in the original source — resolve it, check "
                   "scope, and test whether it drops the main app's controls. (hunt-api)")
            exp = f"Resolve the host `{n.get('text')}` (in-scope?) and probe whether it enforces authz."
            neg = "Only meaningful if the host/credential is reachable & in-scope."
        ld = Lead(
            id="", cls=cls, suggested_skill=skill,
            title=f"Source {cat} — {n.get('text', '')[:60]}",
            source_file=n.get("file", ""), line=n.get("line"), evidence=n.get("text", ""),
            detector="sourcemap:comments", confidence="low", severity_hint=sev,
            next_step=nxt,
            negative_control=neg,
            experiment=exp,
            notes=f"mined from recovered source ({cat}); party={n.get('party')}.",
        )
        out.append((ld, ScoreInputs(party=n.get("party", "first"), in_scope=True)))
    return out


# --- framework gadgets (critique point 11) ------------------------------------
def _gadget_leads(triaged, secret_files):
    out = []
    fw = getattr(triaged, "framework", {}) or {}
    for g in fw.get("gadgets", []) or []:
        if g.get("party") == "vendor" and not g.get("force"):
            continue
        cls = g.get("cls", "framework-gadget")
        skill = g.get("suggested_skill", "hunt-xss")
        ld = Lead(
            id="", cls=cls, suggested_skill=skill,
            title=g.get("title", cls), source_file=g.get("file", ""), line=g.get("line"),
            evidence=g.get("evidence", ""), detector=f"gadget:{g.get('gadget')}",
            confidence=g.get("confidence", "low"), severity_hint=g.get("severity_hint", "medium"),
            next_step=g.get("next_step", ""), negative_control=g.get("negative_control", ""),
            experiment=g.get("experiment", ""),
            notes=f"party={g.get('party')}; gadget={g.get('gadget')}.",
        )
        out.append((ld, ScoreInputs(party=g.get("party", "first"), in_scope=True,
                                    secret_nearby=g.get("file") in secret_files)))
    return out


# --- secrets ------------------------------------------------------------------
def _secret_leads(triaged, mask, secret_files):
    out = []
    # a Google AIza key that is part of a detected Firebase config is already surfaced as
    # ONE hunt-cloud lead (cloud-config); don't also emit it as a lone secret (round 2).
    fw = getattr(triaged, "framework", {}) or {}
    fb_keys = {g.get("apikey") for g in fw.get("gadgets", []) or []
               if g.get("gadget") == "firebase-config" and g.get("apikey")}
    fb_files = {g.get("file") for g in fw.get("gadgets", []) or []
                if g.get("gadget") == "firebase-config"}
    for s in getattr(triaged, "secrets", []) or []:
        kind = s.get("kind") or "secret"
        data = s.get("data")
        if (s.get("secret_label") == "google-api-key" or "AIza" in str(data)):
            val = str(data)
            if any(k and k in val for k in fb_keys) or s.get("source_file") in fb_files:
                continue                                 # folded into the firebase cloud-config lead
        visibility = s.get("visibility")                 # set by the secrets normalizer
        if visibility == "public":
            skill, sev, conf = "hunt-js-analysis", "info", "low"
        elif _is_cloud_secret(kind, data):
            skill, sev, conf = "hunt-cloud", s.get("severity") or "high", "medium"
        else:
            skill, sev, conf = "hunt-secrets-disclosure", s.get("severity") or "medium", "medium"
        detectors = s.get("detectors") or [s.get("detector", "jsluice")]
        ld = Lead(
            id="", cls="secret-location", suggested_skill=skill,
            title=f"Client-side secret ({kind})" + (" [public]" if visibility == "public" else ""),
            source_file=s.get("source_file", ""), line=s.get("line"),
            evidence=_secret_evidence(data, mask), detector=f"{'+'.join(detectors)}:secrets",
            confidence=conf, severity_hint=sev,
            next_step=s.get("weaponization") or (
                "Verify the secret is live and map its blast radius to a takeover. Validating "
                "against the provider = Operator Gate. (hunt-secrets-disclosure)"),
            negative_control=("(public key — restricted by referrer/domain; not a secret by itself)"
                              if visibility == "public" else
                              "An invalid/rotated key must be rejected; only a live key grants access."),
            experiment=s.get("use_hint") or (
                f"Find the request in {s.get('source_file')} that sends this in a key/authorization "
                f"field, then (Operator Gate) test the key against that service."),
            notes=f"[{'+'.join(detectors)}] {s.get('context') or 'secret format match'} — "
                  f"a lead until proven live." + (f" visibility={visibility}." if visibility else ""),
        )
        out.append((ld, ScoreInputs(party="first", in_scope=True,
                                    secret_nearby=s.get("source_file") in secret_files)))
    return out


# --- vulnerable libraries -----------------------------------------------------
def _vuln_sink_leads(triaged):
    """Bind a vulnerable retire component to a REAL call site whose output reaches an HTML
    sink (round 4 pt 4). A `vulnerable-library` lead says "this version is here"; a
    `vulnerable-call` lead says "this version's sanitizer output is going into innerHTML" —
    i.e. a known bypass for this version is DOM-XSS. Without a call it stays a low lib lead."""
    out = []
    vuln = {str(lib.get("component", "")).lower(): lib
            for lib in getattr(triaged, "libs", []) or [] if lib.get("component")}
    if not vuln:
        return out
    seen = set()
    for c in getattr(triaged, "sinks", []) or []:
        san = c.get("sanitizer")
        if not san:
            continue
        lib = vuln.get(san) or next((l for k, l in vuln.items() if san in k or k in san), None)
        if not lib:
            continue
        f, line, src = _first_occ(c)
        key = (san, f, line)
        if key in seen:
            continue
        seen.add(key)
        cves = ", ".join((lib.get("cves") or [])[:3]) or "a known bypass"
        ld = Lead(
            id="", cls="vulnerable-call", suggested_skill="hunt-xss",
            title=f"Vulnerable {lib.get('component')} {lib.get('version')} output reaches {c.get('kind')}",
            source_file=f, line=line, evidence=src, detector="retire+sink",
            confidence="medium", severity_hint="high",
            caller_chain=c.get("caller_chain") or [],
            next_step=(f"{lib.get('component')} {lib.get('version')} is vulnerable ({cves}) AND its "
                       f"output flows into `{c.get('kind')}` here — unlike a version-only finding, the "
                       f"vulnerable path is REACHED. Apply the known bypass payload for this version "
                       f"and confirm execution. (hunt-xss)"),
            negative_control="If the deployed version is actually patched, or the bypass does not "
                             "execute in a browser, it is not a finding.",
            experiment=f"At {f}:{line}, feed the public {lib.get('component')}@{lib.get('version')} "
                       f"sanitizer-bypass payload through the user input and confirm script execution.",
            notes=f"retire CVE bound to call site; CVEs={cves}.",
        )
        out.append((ld, ScoreInputs(party="first", in_scope=True)))
    return out


def _response_leads(triaged, auth_hint=""):
    """Leads from what the operator's requests RETURNED (round 5 pts 17 & 20) — data only a
    Burp/HAR export carries: sensitive fields in a JSON response (over-fetch / token leak,
    with an IDOR pivot on its id fields) and inline-handler / javascript: sinks in captured HTML."""
    out = []
    resp = getattr(triaged, "responses", {}) or {}
    for r in resp.get("overfetch", []) or []:
        ev = f"{r.get('method') or 'GET'} {r.get('path')}".strip()
        sens = r.get("sensitive") or []
        ids = r.get("ids") or []
        ld = Lead(
            id="", cls="response-exposure", suggested_skill="hunt-api",
            title=f"Response of {ev} returns sensitive fields {sens}",
            source_file="(captured response)", line=None, evidence=f"{ev} -> {sens}",
            detector="response:json", confidence="medium", severity_hint="medium",
            method=r.get("method", ""), seen_in_history=True,
            next_step=("The server returns sensitive fields to the client (excessive data exposure / "
                       "over-fetch, API3). Check whether a LOW-priv or OTHER user gets the same fields, "
                       "and whether the token/secret is reusable. (hunt-api)"
                       + (f" IDOR pivot on {ids}." if ids else "")),
            negative_control="Another account must NOT receive account A's sensitive fields; a field "
                             "the UI never shows but the API returns is the over-fetch.",
            experiment=(f"Re-request `{ev}` as a second/again lower-priv account (and swap any id in "
                        f"{ids or 'the path'}); identical sensitive fields for another user prove it."
                        + (" " + auth_hint if auth_hint else "")),
            notes=f"host={r.get('host')}; sensitive fields observed in the captured response.",
        )
        out.append((ld, ScoreInputs(party="first", in_scope=True,
                                    has_id_segment=bool(ids))))
    for h in resp.get("html_sinks", []) or []:
        kind = h.get("kind")
        xss = kind == "javascript-uri"
        ld = Lead(
            id="", cls="html-sink", suggested_skill="hunt-xss",
            title=f"HTML {kind} in captured page {h.get('path')}",
            source_file="(captured HTML)", line=None, evidence=h.get("evidence", ""),
            detector=f"response:html:{kind}", confidence="low",
            severity_hint="medium" if xss else "low",
            next_step=("An inline event handler / javascript: URI in server-rendered HTML — if any "
                       "part is reflected from user input it is reflected/stored XSS. Find whether the "
                       "handler/URI carries a parameter you control. (hunt-xss)"),
            negative_control="A fully static handler with no reflected input is not a finding.",
            experiment=f"Check whether {h.get('path')} reflects a parameter into `{h.get('evidence','')[:60]}`; "
                       f"if so, inject a breakout and confirm execution.",
            notes=f"host={h.get('host')}; from the captured HTML response (jsluice reads only <script>).",
        )
        out.append((ld, ScoreInputs(party="first", in_scope=True)))
    return out


def _lib_leads(triaged):
    out = []
    for lib in getattr(triaged, "libs", []) or []:
        cves = lib.get("cves") or []
        cve_str = ", ".join(cves[:4]) + (" …" if len(cves) > 4 else "")
        ld = Lead(
            id="", cls="vulnerable-library", suggested_skill=_lib_skill(lib.get("cwe")),
            title=f"{lib.get('component')} {lib.get('version')} — {cve_str or 'known vuln'}",
            source_file=lib.get("source_file", ""), line=None,
            evidence=f"{lib.get('component')}@{lib.get('version')}"
                     + (f" (< {lib.get('below')})" if lib.get("below") else ""),
            detector="retire", confidence="low", severity_hint=lib.get("severity") or "medium",
            next_step=(f"Confirm {lib.get('component')} {lib.get('version')} is loaded AND the "
                       f"vulnerable function is actually CALLED before claiming impact. "
                       f"{lib.get('summary', '')}".strip()),
            negative_control="A CVE whose vulnerable code path is never invoked is not exploitable here.",
            experiment=f"Grep the bundle for the vulnerable {lib.get('component')} API; if reached by "
                       f"input you control, map the CVE to a concrete effect.",
            notes=f"retire.js ({lib.get('detection')}); CWE={','.join(lib.get('cwe') or []) or '-'}.",
        )
        # retire CVE without a proven call is a LOW lead (don't inflate on version alone)
        out.append((ld, ScoreInputs(party="vendor", in_scope=True)))
    return out


# --- UI-gate feature flags ----------------------------------------------------
def _flag_leads(triaged):
    out = []
    for fl in getattr(triaged, "flags", []) or []:
        if fl.get("kind") != "ui-gate":
            continue
        ld = Lead(
            id="", cls="feature-gate", suggested_skill="hunt-api",
            title=f"Client-side role/mode gate ({fl.get('key')})",
            source_file=fl.get("file", ""), line=fl.get("line"), evidence=fl.get("evidence", ""),
            detector="flags", confidence="low", severity_hint="medium",
            next_step="A client-enforced role/mode gate often hides privileged UI/endpoints — "
                      "test the gated action server-side as a low-privilege role. (hunt-api)",
            negative_control="The server must enforce the same gate; if it trusts the client flag, it is bypassable.",
            experiment=f"Flip `{fl.get('key')}` client-side (or call the gated endpoint directly) as a "
                       f"low-priv role; server-side execution is the finding.",
            notes=f"party={fl.get('party')}; mechanism={fl.get('provider')}.",
        )
        out.append((ld, ScoreInputs(party=fl.get("party", "first"), in_scope=True)))
    return out

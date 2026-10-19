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


def build_leads(triaged, cfg=None, history=None, scope_hosts=None) -> list[dict]:
    cfg = cfg or load_config()
    mask = cfg.get("mask_secrets_in_leads", True)
    history_known = bool((history or {}).get("known")) if isinstance(history, dict) else False

    secret_files = {s.get("source_file") for s in (getattr(triaged, "secrets", []) or [])
                    if s.get("source_file")}
    # the set of normalized API paths that actually have a request site (for "no fetch
    # equivalent" route detection)
    api_paths = {n.get("norm_path") for n in (getattr(triaged, "endpoints", []) or [])
                 if n.get("string_kind") == "api"}

    pairs: list[tuple[Lead, ScoreInputs]] = []
    pairs += _sink_leads(triaged, secret_files)
    pairs += _pm_leads(triaged, secret_files)
    pairs += _endpoint_leads(triaged, secret_files, history_known)
    pairs += _hidden_route_leads(triaged, api_paths, history_known)
    pairs += _storage_leads(triaged, secret_files)
    pairs += _graphql_leads(triaged)
    pairs += _sourcemap_leads(triaged)
    pairs += _csp_leads(triaged, history, scope_hosts)
    pairs += _note_leads(triaged)
    pairs += _gadget_leads(triaged, secret_files)
    pairs += _secret_leads(triaged, mask, secret_files)
    pairs += _lib_leads(triaged)
    pairs += _flag_leads(triaged)

    leads: list[Lead] = []
    for ld, si in pairs:
        si.history_known = history_known
        ld.score, ld.score_factors = score_lead(ld, si)
        leads.append(ld)

    # composite score is the queue order; severity/confidence are tie-breakers only
    leads.sort(key=lambda ld: (-ld.score, _SEV_RANK.get(ld.severity_hint, 9),
                               _CONF_RANK.get(ld.confidence, 9)))
    for i, ld in enumerate(leads, 1):
        ld.id = f"lead-{i:04d}"
    return [ld.to_dict() for ld in leads]


# --- DOM-XSS sinks ------------------------------------------------------------
def _sink_leads(triaged, secret_files):
    out = []
    for c in getattr(triaged, "sinks", []) or []:
        if not c.get("lead"):
            continue
        f, line, src = _first_occ(c)
        extra = f" (+{c['count'] - 1} more)" if c.get("count", 1) > 1 else ""
        chain = c.get("caller_chain") or []
        taint_src = c.get("taint_source") or (chain[0] if chain else "attacker input")
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
        out.append((ld, ScoreInputs(party=c.get("party", "first"), in_scope=True,
                                    secret_nearby=f in secret_files)))
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
def _endpoint_leads(triaged, secret_files, history_known):
    out = []
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
            ld = _mk_endpoint_lead(n, cls, skill, conf, sev, why, src_file, in_hist)
            out.append((ld, ScoreInputs(
                party=n.get("party", "first"), in_scope=n.get("in_scope"),
                call_type=n.get("call_type", ""), has_id_segment=has_id,
                secret_nearby=src_file in secret_files, history_known=history_known)))
            continue
        # not a classified class, but a first-party in-scope API endpoint that was
        # NEVER exercised in the captured traffic is untested surface (critique point 2)
        if (history_known and in_hist is False and n.get("string_kind") == "api"
                and n.get("party") == "first" and n.get("in_scope") is not False
                and n.get("fetchable")):
            key = ("endpoint-unverified", n.get("method"), n.get("norm_path"))
            if key in seen_ep:
                continue
            seen_ep.add(key)
            ld = _mk_endpoint_lead(
                n, "endpoint-unverified", "hunt-api", "low", "low",
                "in the bundle but absent from captured traffic", src_file, in_hist)
            out.append((ld, ScoreInputs(
                party="first", in_scope=n.get("in_scope"), call_type=n.get("call_type", ""),
                has_id_segment=has_id, secret_nearby=src_file in secret_files,
                history_known=history_known)))
    return out


def _mk_endpoint_lead(n, cls, skill, conf, sev, why, src_file, in_hist):
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
    return Lead(
        id="", cls=cls, suggested_skill=skill, title=f"{cls} — {ev}",
        source_file=src_file, line=None, evidence=ev,
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


# --- hidden SPA routes (no fetch equivalent, not in history) ------------------
_PRIV_ROUTE_HINTS = ("admin", "internal", "manage", "settings", "billing", "account",
                     "dashboard", "debug", "superuser", "staff", "console", "config")


def _hidden_route_leads(triaged, api_paths, history_known):
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
        # surface a route only when it is privileged-looking, or (if we have traffic)
        # it was never navigated — otherwise plain pages would flood the queue.
        if not priv and not history_known:
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
            seen_in_history=False if history_known else None,
            next_step="A first-party route with no fetch equivalent often fronts a privileged "
                      "view/API not in your traffic — drive it and test the backing calls as a "
                      "low-privilege role. (hunt-api)",
            negative_control="A low-privilege role must be denied the view/API this route fronts.",
            experiment=f"Navigate `{path}` in an authenticated low-priv session; capture the API "
                       f"calls it makes and test their authz.",
            notes=f"party=first; kind={r.get('kind')}; privileged={priv}.",
        )
        out.append((ld, ScoreInputs(party="first", in_scope=True, has_id_segment="{id}" in npath,
                                    history_known=history_known)))
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
        if cat not in ("credential", "internal-host"):
            continue                              # notes/mock-paths stay in the artifact
        key = (cat, n.get("file"), n.get("text", "")[:60])
        if key in seen:
            continue
        seen.add(key)
        if cat == "credential":
            cls, skill, sev = "secret-location", "hunt-secrets-disclosure", "medium"
            nxt = ("A credential left in an original-source comment (recovered via sourcemap) — "
                   "verify it is live and map its blast radius. (hunt-secrets-disclosure)")
            exp = "Confirm the commented credential still works against its service (Operator Gate to verify)."
        else:
            cls, skill, sev = "endpoint-hidden", "hunt-api", "low"
            nxt = ("A staging/internal host named only in the original source — resolve it, check "
                   "scope, and test whether it drops the main app's controls. (hunt-api)")
            exp = f"Resolve the host `{n.get('text')}` (in-scope?) and probe whether it enforces authz."
        ld = Lead(
            id="", cls=cls, suggested_skill=skill,
            title=f"Source {cat} — {n.get('text', '')[:60]}",
            source_file=n.get("file", ""), line=n.get("line"), evidence=n.get("text", ""),
            detector="sourcemap:comments", confidence="low", severity_hint=sev,
            next_step=nxt,
            negative_control="Only meaningful if the host/credential is reachable & in-scope.",
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
    for s in getattr(triaged, "secrets", []) or []:
        kind = s.get("kind") or "secret"
        data = s.get("data")
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

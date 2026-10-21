# JS Analysis — target.tld, api.target.tld (2026-10-21_example)

## Ringkasan
- JS: 4 | Endpoints: 10 fetchable/11 | Sinks: 1 lead/2 | Secrets: 5 | Vuln libs: 1 | postMessage: 1 lead/1 | Flags: 0 | Routes: 0 | Storage: 0 | GraphQL: 0 | CSP hosts: 0 | Missing chunks: 1 | Source notes: 0 | Leads: 17
- Leads per skill: hunt-xss: 3, hunt-secrets-disclosure: 3, hunt-idor: 3, hunt-cloud: 2, hunt-auth-bypass: 2, hunt-api: 1, hunt-graphql: 1, hunt-websocket: 1, hunt-js-analysis: 1
- Framework: jquery

## Leads prioritas
- [lead-0001] **xss-sink** score=10.6 (high/high → hunt-xss) — `el.innerHTML = location.hash` — app.4f2a.js__6cb6251497.js:31
    - experiment: In a browser, set the tainted source (location.hash) to a JS payload and confirm execution (dialog/DOM marker) at app.4f2a.js__6cb6251497.js:31.
    - neg-control: A benign value in the same source must NOT execute; only the attacker-controlled payload does.
- [lead-0002] **bfla-candidate** score=8.8 (medium/high → hunt-api) — `POST /api/admin/users/promote` — app.4f2a.js__6cb6251497.js:None
    - body: {role}
    - experiment: Invoke 'POST /api/admin/users/promote' body={role} as a low-privilege role; execution (vs 403 for control) proves BFLA.
    - neg-control: A low-privilege role must be refused (403); if the action executes, authz is missing.
- [lead-0003] **postmessage-listener** score=8.3 (medium/high → hunt-xss) — `window.addEventListener("message", function(e) { document.getElementById("out").innerHTML ` — app.4f2a.js__6cb6251497.js:32
    - chain: innerHTML
    - experiment: From an attacker origin, postMessage a payload into this listener and confirm it reaches ['innerHTML']
    - neg-control: A postMessage from a DISALLOWED origin must be ignored; if the handler acts on it regardless, the origin check is the bug.
- [lead-0004] **secret-location** score=8.3 (medium/high → hunt-cloud) — `{"key": "AKIA…[REDACTED]…LE"}` — app.4f2a.js__6cb6251497.js:None
    - experiment: Find the request in app.4f2a.js__6cb6251497.js that sends it in a key/authorization field; (Operator Gate) test it against that service.
    - neg-control: An invalid/rotated key must be rejected; only a live key grants access.
- [lead-0005] **secret-location** score=8.3 (medium/high → hunt-secrets-disclosure) — `{"match": "sk_l…[REDACTED]…GH", "pattern": "stripeSecretKey"}` — app.4f2a.js__6cb6251497.js:29
    - experiment: Find the request in app.4f2a.js__6cb6251497.js that sends it in a key/authorization field; (Operator Gate) test it against that service.
    - neg-control: An invalid/rotated key must be rejected; only a live key grants access.
- [lead-0006] **secret-location** score=8.3 (medium/high → hunt-secrets-disclosure) — `{"key": "ghp_…[REDACTED]…AB"}` — vendor.min.js__9d94d8982f.js:None
    - experiment: Find the request in vendor.min.js__9d94d8982f.js that sends it in a key/authorization field; (Operator Gate) test it against that service.
    - neg-control: An invalid/rotated key must be rejected; only a live key grants access.
- [lead-0007] **idor-candidate** score=8.3 (medium/medium → hunt-idor) — `GET EXPR/users/EXPR/orders/123` — app.4f2a.js__6cb6251497.js:None
    - experiment: Replay 'GET EXPR/users/EXPR/orders/123' from account B using account A's identifier (+ reverse); a cross-account read/write is the proof.
    - neg-control: Account B must get 403/404 (not the object) when replaying A's id — a negative control proves isolation.
- [lead-0008] **idor-candidate** score=8.3 (medium/medium → hunt-idor) — `GET /v1/users/EXPR/orders/123` — app.4f2a.js__6cb6251497.js:3
    - experiment: Replay 'GET /v1/users/EXPR/orders/123' from account B using account A's identifier (+ reverse); a cross-account read/write is the proof.
    - neg-control: Account B must get 403/404 (not the object) when replaying A's id — a negative control proves isolation.
- [lead-0009] **auth-endpoint** score=7.8 (medium/medium → hunt-auth-bypass) — `POST /api/v1/auth/reset-password` — app.4f2a.js__6cb6251497.js:16
    - body: {email}
    - experiment: Attack the mechanism at 'POST /api/v1/auth/reset-password' (token forgery / reset race / OAuth redirect_uri).
    - neg-control: The control (current/authorized path or role) must behave differently.
- [lead-0010] **auth-endpoint** score=7.3 (medium/medium → hunt-auth-bypass) — `POST /api/v1/auth/login` — app.4f2a.js__6cb6251497.js:9
    - experiment: Attack the mechanism at 'POST /api/v1/auth/login' (token forgery / reset race / OAuth redirect_uri).
    - neg-control: The control (current/authorized path or role) must behave differently.
- [lead-0011] **graphql-candidate** score=7.3 (medium/medium → hunt-graphql) — `POST /graphql` — app.4f2a.js__6cb6251497.js:19
    - experiment: Fingerprint + attempt introspection at 'POST /graphql', then per-resolver authz (node(id:)).
    - neg-control: The control (current/authorized path or role) must behave differently.
- [lead-0012] **idor-candidate** score=7.3 (medium/medium → hunt-idor) — `GET /api/v0/legacy/export` — app.4f2a.js__6cb6251497.js:25
    - experiment: Replay 'GET /api/v0/legacy/export' from account B using account A's identifier (+ reverse); a cross-account read/write is the proof.
    - neg-control: Account B must get 403/404 (not the object) when replaying A's id — a negative control proves isolation.
- [lead-0013] **websocket** score=7.3 (medium/medium → hunt-websocket) — `GET /socket` — app.4f2a.js__6cb6251497.js:26
    - experiment: Test CSWSH on 'GET /socket' (cross-origin handshake with the victim cookie) and per-message authz.
    - neg-control: The control (current/authorized path or role) must behave differently.
- [lead-0014] **secret-location** score=7.3 (medium/medium → hunt-cloud) — `{"key": "AIza…[REDACTED]…uv"}` — app.4f2a.js__6cb6251497.js:30
    - experiment: Find the request in app.4f2a.js__6cb6251497.js that sends it in a key/authorization field; (Operator Gate) test it against that service.
    - neg-control: An invalid/rotated key must be rejected; only a live key grants access.
- [lead-0015] **secret-location** score=7.3 (medium/medium → hunt-secrets-disclosure) — `{"match": "sk_t…[REDACTED]…wx", "pattern": "stripeTestKey"}` — widget.js__6738f2f709.js:4
    - experiment: Find the request in widget.js__6738f2f709.js that sends it in a key/authorization field; (Operator Gate) test it against that service.
    - neg-control: An invalid/rotated key must be rejected; only a live key grants access.
- [lead-0016] **sourcemap** score=5.0 (low/low → hunt-js-analysis) — `https://target.tld/static/js/app.4f2a.js.map` — app.4f2a.js__6cb6251497.js:None
    - experiment: Operator-gated: if authorized, fetch 'https://target.tld/static/js/app.4f2a.js.map' and mine sourcesContent for staging hosts, mock/dummyData paths, comments and secrets not in the bundle.
    - neg-control: (recon) — a .map only yields leads if it carries sourcesContent (original comments/paths/secrets absent from the minified bundle).
- [lead-0017] **vulnerable-library** score=2.0 (low/medium → hunt-xss) — `jquery@1.7.1 (< 1.9.0b1)` — vendor.min.js__9d94d8982f.js:None
    - experiment: Grep the bundle for the vulnerable jquery API; if reached by input you control, map the CVE to a concrete effect.
    - neg-control: A CVE whose vulnerable code path is never invoked is not exploitable here.

## Endpoints (fetchable)
| Method | Path/URL | Party | In-scope | Type |
| --- | --- | --- | --- | --- |
| - | https://api.target.tld/v1 | first | True | stringLiteral |
| POST | /api/admin/users/promote | first | True | axios.post |
| POST | /api/v1/auth/login | first | True | fetch |
| POST | /api/v1/auth/reset-password | first | True | axios.post |
| POST | /graphql | first | True | fetch |
| GET | /api/v0/legacy/export | first | True | fetch |
| GET | wss://api.target.tld/socket | first | True | websocket |
| GET | /api/v1/profile/me | first | True | fetch |
| GET | /api/v2/users/me/settings | vendor | True | fetch |
| GET | https://api.target.tld/v1/users/EXPR/orders/123 | first | True | concat |

_1 non-fetchable/dynamic kept in endpoints.json_

## Sinks (audit — ✅ = lead)
| Lead | Class | Kind | Party | Real-taint | Count | Sample |
| --- | --- | --- | --- | --- | --- | --- |
| ✅ | html | innerHTML | first | True | 1 | el.innerHTML = location.hash |
|  | html | innerHTML | first | False | 1 | document.getElementById("out").innerHTML = e.dat |

## Secrets (MASKED)
| Detector | Kind | Severity | Evidence (masked) | File |
| --- | --- | --- | --- | --- |
| jsluice | AWSAccessKey | high | {"key": "AKIA…[REDACTED]…LE"} | app.4f2a.js__6cb6251497.js |
| jsluice | gcpKey | medium | {"key": "AIza…[REDACTED]…uv"} | app.4f2a.js__6cb6251497.js |
| jsluice | stripeSecretKey | high | {"match": "sk_l…[REDACTED]…GH", "pattern": "stripeSecretKey"} | app.4f2a.js__6cb6251497.js |
| jsluice | stripeTestKey | medium | {"match": "sk_t…[REDACTED]…wx", "pattern": "stripeTestKey"} | widget.js__6738f2f709.js |
| jsluice | githubKey | high | {"key": "ghp_…[REDACTED]…AB"} | vendor.min.js__9d94d8982f.js |

## Vulnerable libraries
| Library | Version | Severity | CVE | File |
| --- | --- | --- | --- | --- |
| jquery | 1.7.1 | medium | CVE-2012-6708, CVE-2015-9251, CVE-2019-11358 | vendor.min.js__9d94d8982f.js |

## postMessage
| Lead | Class | Party | origin_checked | target* | File:line |
| --- | --- | --- | --- | --- | --- |
| ✅ | postmessage-listener | first | False | False | app.4f2a.js__6cb6251497.js:32 |

## Lainnya
**Routes:** none

**Feature flags:** none

**Storage:** none

**GraphQL ops:** none

**Missing chunks (operator must capture — NOT fetched):** 1
  - https://target.tld/static/js/app.4f2a.js

## Langkah berikutnya
- hunt-xss untuk lead-0001 (xss-sink @ app.4f2a.js__6cb6251497.js:31).
- hunt-api untuk lead-0002 (bfla-candidate @ app.4f2a.js__6cb6251497.js:None).
- hunt-xss untuk lead-0003 (postmessage-listener @ app.4f2a.js__6cb6251497.js:32).
- hunt-cloud untuk lead-0004 (secret-location @ app.4f2a.js__6cb6251497.js:None).
- hunt-secrets-disclosure untuk lead-0005 (secret-location @ app.4f2a.js__6cb6251497.js:29).
- hunt-secrets-disclosure untuk lead-0006 (secret-location @ vendor.min.js__9d94d8982f.js:None).
- Leads = kandidat, bukan temuan. Bukti = efek lintas-batas yang teramati via skill hunt-*.

## Enrichment
- Beautify: 3 file via `jsbeautifier-module` (lead line numbers refer to beautified JS).
- Sourcemaps: recovered 1 source files (inline=1, external=1, fetched=0).
- Tools: js_beautify, linkfinder, trufflehog, gitleaks, retire, sourcemapper, unwebpack_sourcemap | absent: secretfinder

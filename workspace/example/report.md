# JS Analysis — target.tld, api.target.tld (2026-10-17_example)

## Ringkasan
- JS: 4 | Endpoints: 9 fetchable/10 | Sinks: 1 lead/2 | Secrets: 8 | Vuln libs: 1 | postMessage: 1 lead/1 | Flags: 0 | Routes: 0 | Storage: 0 | GraphQL: 0 | Leads: 17
- Leads per skill: hunt-secrets-disclosure: 5, hunt-xss: 3, hunt-cloud: 3, hunt-idor: 2, hunt-auth-bypass: 2, hunt-api: 1, hunt-graphql: 1
- Framework: jquery

## Leads prioritas
### hunt-secrets-disclosure
- [lead-0004] **secret-location** (medium/high) — `{"match": "sk_l…[REDACTED]…GH", "pattern": "stripeSecretKey"}` — app.4f2a.js__6cb6251497.js:None → Verify the secret is live and map its blast radius to a takeover (session/JWT forgery, cloud access, DB creds). Validating a cloud key against the provider = Operator Gate. (hunt-cloud / hunt-secrets-disclosure)
- [lead-0005] **secret-location** (medium/high) — `{"match": "sk_t…[REDACTED]…x\"", "secret": "sk_t…[REDACTED]…wx"}` — widget.js__6738f2f709.js:4 → Verify the secret is live and map its blast radius to a takeover (session/JWT forgery, cloud access, DB creds). Validating a cloud key against the provider = Operator Gate. (hunt-cloud / hunt-secrets-disclosure)
- [lead-0007] **secret-location** (medium/high) — `{"match": "sk_l…[REDACTED]…H\"", "secret": "sk_l…[REDACTED]…GH"}` — app.4f2a.js__6cb6251497.js:29 → Verify the secret is live and map its blast radius to a takeover (session/JWT forgery, cloud access, DB creds). Validating a cloud key against the provider = Operator Gate. (hunt-cloud / hunt-secrets-disclosure)
- [lead-0016] **secret-location** (medium/low) — `{"match": "sk_t…[REDACTED]…wx", "pattern": "stripeTestKey"}` — widget.js__6738f2f709.js:None → Verify the secret is live and map its blast radius to a takeover (session/JWT forgery, cloud access, DB creds). Validating a cloud key against the provider = Operator Gate. (hunt-cloud / hunt-secrets-disclosure)
- [lead-0017] **secret-location** (medium/low) — `{"key": "ghp_…[REDACTED]…AB"}` — vendor.min.js__9d94d8982f.js:None → Verify the secret is live and map its blast radius to a takeover (session/JWT forgery, cloud access, DB creds). Validating a cloud key against the provider = Operator Gate. (hunt-cloud / hunt-secrets-disclosure)
### hunt-cloud
- [lead-0006] **secret-location** (medium/high) — `{"match": "AIza…[REDACTED]…v\"", "secret": "AIza…[REDACTED]…uv"}` — app.4f2a.js__6cb6251497.js:30 → Verify the secret is live and map its blast radius to a takeover (session/JWT forgery, cloud access, DB creds). Validating a cloud key against the provider = Operator Gate. (hunt-cloud / hunt-secrets-disclosure)
- [lead-0014] **secret-location** (medium/low) — `{"key": "AKIA…[REDACTED]…LE"}` — app.4f2a.js__6cb6251497.js:None → Verify the secret is live and map its blast radius to a takeover (session/JWT forgery, cloud access, DB creds). Validating a cloud key against the provider = Operator Gate. (hunt-cloud / hunt-secrets-disclosure)
- [lead-0015] **secret-location** (medium/low) — `{"key": "AIza…[REDACTED]…uv"}` — app.4f2a.js__6cb6251497.js:None → Verify the secret is live and map its blast radius to a takeover (session/JWT forgery, cloud access, DB creds). Validating a cloud key against the provider = Operator Gate. (hunt-cloud / hunt-secrets-disclosure)
### hunt-xss
- [lead-0001] **xss-sink** (high/high) — `el.innerHTML = location.hash` — app.4f2a.js__6cb6251497.js:31 → In a browser, drive attacker-controlled input into this sink and capture execution (dialog or DOM marker). A reflection is not proof. (hunt-xss)
- [lead-0002] **postmessage-listener** (medium/high) — `window.addEventListener("message", function(e) { document.getElementById("out").innerHTML ` — app.4f2a.js__6cb6251497.js:32 → From an attacker origin, postMessage into this listener and reach the named sink with a browser PoC (execution captured). (hunt-xss)
- [lead-0013] **vulnerable-library** (medium/medium) — `jquery@1.7.1 (< 1.9.0b1)` — vendor.min.js__9d94d8982f.js:None → Confirm jquery 1.7.1 is loaded and the vulnerable path is reachable, then map the CVE to an effect. Selector interpreted as HTML; Versions of jQuery prior to 1.9.0 are vulnerable to Cross-Site Scripting (XSS). The load method fails to recognize and strip script tags containing whitespace in the closing tag (e.g. </script >), allowing enclosed script logic to execute and enabling attackers to run arbitrary JavaScript in a victim's browser.; 3rd party CORS request may execute
### hunt-auth-bypass
- [lead-0009] **auth-endpoint** (medium/medium) — `POST /api/v1/auth/login` — app.4f2a.js__6cb6251497.js:None → Attack the mechanism itself: token forgery, reset race/leak, OAuth redirect_uri/state, MFA bypass. Large-scale OTP/reset brute = Operator Gate. (hunt-auth-bypass)
- [lead-0010] **auth-endpoint** (medium/medium) — `POST /api/v1/auth/reset-password` — app.4f2a.js__6cb6251497.js:None → Attack the mechanism itself: token forgery, reset race/leak, OAuth redirect_uri/state, MFA bypass. Large-scale OTP/reset brute = Operator Gate. (hunt-auth-bypass)
### hunt-idor
- [lead-0008] **idor-candidate** (medium/medium) — `GET EXPR/users/EXPR/orders/123` — app.4f2a.js__6cb6251497.js:None → Two accounts A/B: request this object with account B using A's identifier (and the reverse), with a negative control. A cross-account read/write is the proof — a single account proves nothing. (hunt-idor)
- [lead-0012] **idor-candidate** (medium/medium) — `GET /api/v0/legacy/export` — app.4f2a.js__6cb6251497.js:None → Two accounts A/B: request this object with account B using A's identifier (and the reverse), with a negative control. A cross-account read/write is the proof — a single account proves nothing. (hunt-idor)
### hunt-api
- [lead-0003] **bfla-candidate** (medium/high) — `POST /api/admin/users/promote` — app.4f2a.js__6cb6251497.js:None → Invoke this privileged function as a low-privilege role; the action executing (vs 403 for the control account) proves BFLA. (hunt-api)
### hunt-graphql
- [lead-0011] **graphql-candidate** (medium/medium) — `POST /graphql` — app.4f2a.js__6cb6251497.js:None → Fingerprint the engine, attempt introspection + bypasses, then test per-resolver authz (node(id:)) and batching/aliasing. If introspection is open (Operator Gate), visualize the schema with GraphQL Voyager. (hunt-graphql)

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

_1 non-fetchable/dynamic kept in endpoints.json_

## Sinks (audit — ✅ = lead)
| Lead | Class | Kind | Party | Real-taint | Count | Sample |
| --- | --- | --- | --- | --- | --- | --- |
| ✅ | html | innerHTML | first | True | 1 | el.innerHTML = location.hash |
|  | html | innerHTML | first | False | 1 | document.getElementById("out").innerHTML = e.dat |

## Secrets (MASKED)
| Detector | Kind | Severity | Evidence (masked) | File |
| --- | --- | --- | --- | --- |
| jsluice | AWSAccessKey | low | {"key": "AKIA…[REDACTED]…LE"} | app.4f2a.js__6cb6251497.js |
| jsluice | gcpKey | low | {"key": "AIza…[REDACTED]…uv"} | app.4f2a.js__6cb6251497.js |
| jsluice | stripeSecretKey | high | {"match": "sk_l…[REDACTED]…GH", "pattern": "stripeSecretKey"} | app.4f2a.js__6cb6251497.js |
| jsluice | stripeTestKey | low | {"match": "sk_t…[REDACTED]…wx", "pattern": "stripeTestKey"} | widget.js__6738f2f709.js |
| jsluice | githubKey | low | {"key": "ghp_…[REDACTED]…AB"} | vendor.min.js__9d94d8982f.js |
| gitleaks | stripe-access-token | high | {"match": "sk_t…[REDACTED]…x\"", "secret": "sk_t…[REDACTED]…wx"} | widget.js__6738f2f709.js |
| gitleaks | gcp-api-key | high | {"match": "AIza…[REDACTED]…v\"", "secret": "AIza…[REDACTED]…uv"} | app.4f2a.js__6cb6251497.js |
| gitleaks | stripe-access-token | high | {"match": "sk_l…[REDACTED]…H\"", "secret": "sk_l…[REDACTED]…GH"} | app.4f2a.js__6cb6251497.js |

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

## Langkah berikutnya
- hunt-xss untuk lead-0001 (xss-sink @ app.4f2a.js__6cb6251497.js:31).
- hunt-xss untuk lead-0002 (postmessage-listener @ app.4f2a.js__6cb6251497.js:32).
- hunt-api untuk lead-0003 (bfla-candidate @ app.4f2a.js__6cb6251497.js:None).
- hunt-secrets-disclosure untuk lead-0004 (secret-location @ app.4f2a.js__6cb6251497.js:None).
- hunt-secrets-disclosure untuk lead-0005 (secret-location @ widget.js__6738f2f709.js:4).
- hunt-cloud untuk lead-0006 (secret-location @ app.4f2a.js__6cb6251497.js:30).
- Leads = kandidat, bukan temuan. Bukti = efek lintas-batas yang teramati via skill hunt-*.

## Enrichment
- Beautify: 3 file via `jsbeautifier-module` (lead line numbers refer to beautified JS).
- Sourcemaps: recovered 1 source files (inline=1, external=1, fetched=0).
- Tools: js_beautify, linkfinder, trufflehog, gitleaks, retire, sourcemapper, unwebpack_sourcemap | absent: secretfinder
